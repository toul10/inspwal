const path = require("path");
const express = require("express");
const fetch = require("node-fetch");
const { readConfig } = require("./config");
const { getObjectAndTransaction, rpcUrlFor } = require("./sui");
const {
  textDecoder,
  detectSeal,
  isBinary,
  estimateEntropy,
  estimateCompressionRatio,
  detectBinaryFormat,
  summarizeBytes,
  summarizeText,
  tryDecompressToText,
} = require("./analyze");

function getAggregatorBase(config, net) {
  const network = (net || "testnet").toString().toLowerCase();
  if (network === "mainnet") {
    if (!config.walrus.mainnet) {
      const err = new Error("Mainnet aggregator not configured");
      err.status = 500;
      throw err;
    }
    return { base: config.walrus.mainnet, network: "mainnet" };
  }
  if (!config.walrus.testnet) {
    const err = new Error("Testnet aggregator not configured");
    err.status = 500;
    throw err;
  }
  return { base: config.walrus.testnet, network: "testnet" };
}

// interpret Walrus error body to classify availability
function interpretWalrusError(status, snippet) {
  let availability = "unknown";
  let note = "Walrus returned an error";

  if (status === 404 && snippet && snippet.includes("BLOB_NOT_FOUND")) {
    availability = "absent";
    note = "Blob not found on this Walrus network";
  } else if (
    status === 500 &&
    snippet &&
    snippet.includes("could not retrieve blob or shared blob from object id")
  ) {
    availability = "unknown";
    note =
      "Walrus could not map this object id to a blob. It may belong to a different net or an older reset.";
  }

  return { availability, note };
}

function headersToObject(headers) {
  const out = {};
  headers.forEach((value, key) => {
    out[key.toLowerCase()] = value;
  });
  return out;
}

// Builds the inspector. `lookup` maps a Walrus blob id to its Sui object: the
// local index for server.js, the Blockberry API for server-Blockberry.js.
// Everything else is the same for both servers.
function createApp({ config, lookup }) {
  const app = express();

  // serve static front end from ./public
  app.use(express.static(path.join(__dirname, "..", "public")));

  // basic health
  app.get("/health", (req, res) => {
    res.json({
      ok: true,
      lookup: lookup.name,
      testnetAggregator: config.walrus.testnet,
      mainnetAggregator: config.walrus.mainnet,
    });
  });

  // the Sui object of a Walrus blob id, with a transaction to show with it
  app.get("/sui-from-blob", async (req, res) => {
    const blobId = (req.query.id || "").trim();
    const net = (req.query.net || "mainnet").toLowerCase();

    if (!blobId) {
      return res.status(400).json({
        ok: false,
        error: "Missing query parameter id with Walrus blob id",
      });
    }

    let found;
    try {
      found = await lookup.findBlob(blobId, net);
    } catch (err) {
      console.error("[sui-from-blob] lookup failed:", err.message || err);
      return res.status(err.status || 500).json({
        ok: false,
        network: net,
        blobId,
        error: err.message || String(err),
      });
    }

    try {
      const { suiObject, suiTransaction } = await getObjectAndTransaction(
        rpcUrlFor(config, found.network),
        found.objectId,
        found.txDigest
      );
      return res.json({
        ok: true,
        network: found.network,
        blobId,
        objectId: found.objectId,
        ...found.details,
        suiObject,
        suiTransaction,
      });
    } catch (err) {
      console.error("[sui-from-blob] error", err);
      return res.status(err.status || 500).json({
        ok: false,
        error: err.message || String(err),
      });
    }
  });

  // stream raw blob bytes through our server for image video audio
  app.get("/raw", async (req, res) => {
    const rawId = req.query.id;
    const netParam = typeof req.query.net === "string" ? req.query.net : "testnet";

    if (!rawId || typeof rawId !== "string" || !rawId.trim()) {
      return res.status(400).send("Missing id query parameter");
    }

    let agg;
    try {
      agg = getAggregatorBase(config, netParam);
    } catch (err) {
      const status = err.status || 500;
      return res.status(status).send(err.message || "Aggregator not configured");
    }

    const { base: aggregatorBase } = agg;
    const blobId = rawId.trim();
    const url = `${aggregatorBase}/v1/blobs/${encodeURIComponent(blobId)}`;
    console.log("[INFO] Streaming from Walrus:", url);

    try {
      const walrusResp = await fetch(url);

      if (!walrusResp.ok) {
        const txt = await walrusResp.text().catch(() => "");
        console.error("[ERROR] Walrus streaming error", walrusResp.status, txt);
        return res
          .status(walrusResp.status)
          .send(`Walrus error ${walrusResp.status}`);
      }

      const contentType = walrusResp.headers.get("content-type");
      if (contentType) {
        res.setHeader("content-type", contentType);
      }

      const contentLength = walrusResp.headers.get("content-length");
      if (contentLength) {
        res.setHeader("content-length", contentLength);
      }

      walrusResp.body.pipe(res);
    } catch (err) {
      console.error("[ERROR] Raw streaming failure:", err);
      res.status(500).send("Failed to stream blob from Walrus");
    }
  });

  // inspect by Walrus blob id
  app.get("/inspect", async (req, res) => {
    const rawId = req.query.id;

    if (!rawId || typeof rawId !== "string" || !rawId.trim()) {
      return res.status(400).json({ error: "Missing id query parameter" });
    }

    const netParam = typeof req.query.net === "string" ? req.query.net : "testnet";

    let agg;
    try {
      agg = getAggregatorBase(config, netParam);
    } catch (err) {
      console.error("[ERROR] Aggregator selection failed:", err.message);
      const status = err.status || 500;
      return res.status(status).json({
        blobId: rawId.trim(),
        network: netParam,
        availability: "unknown",
        existsOnWalrus: null,
        hasSeal: false,
        preview: null,
        previewType: null,
        mediaUrl: null,
        mimeType: null,
        sizeBytes: null,
        encryptionGuess: null,
        error: err.message,
      });
    }

    const { base: aggregatorBase, network } = agg;
    const blobId = rawId.trim();
    const baseResponse = { blobId, network };

    try {
      const url = `${aggregatorBase}/v1/blobs/${encodeURIComponent(blobId)}`;
      console.log("[INFO] Fetching from Walrus:", url);

      const walrusResp = await fetch(url);

      if (!walrusResp.ok) {
        const errText = await walrusResp.text().catch(() => "");
        const snippet = errText.slice(0, 200);
        console.error("[ERROR] Walrus replied", walrusResp.status, snippet);

        const { availability, note } = interpretWalrusError(
          walrusResp.status,
          snippet
        );

        return res.status(walrusResp.status).json({
          ...baseResponse,
          availability,
          existsOnWalrus: availability === "present" ? true : false,
          hasSeal: false,
          preview: null,
          previewType: null,
          mediaUrl: null,
          mimeType: null,
          sizeBytes: null,
          walrusStatus: walrusResp.status,
          walrusUrl: url,
          walrusSnippet: snippet || null,
          encryptionGuess: null,
          note,
          error: "Walrus fetch failed",
        });
      }

      const mimeTypeHeader =
        walrusResp.headers.get("content-type") || "application/octet-stream";
      const mimeType = mimeTypeHeader;
      const buf = await walrusResp.arrayBuffer();
      const bytes = new Uint8Array(buf);
      const sizeBytes = bytes.length;
      const walrusHeaders = headersToObject(walrusResp.headers);
      const { hashes, byteSample } = summarizeBytes(bytes);
      let textSummary = null;

      const { hasSeal, sealMeta } = detectSeal(bytes);

      const lowerMime = mimeType.toLowerCase();
      let format = detectBinaryFormat(bytes);
      if (!format) {
        const mimePart = lowerMime.split(";")[0].split("/")[1] || null;
        if (mimePart && mimePart !== "octet-stream") {
          format = mimePart;
        }
      }

      let classification = "unknown";
      let likelyEncrypted = false;
      let reason = null;
      let entropyBitsPerByte = null;
      const compressionRatio = estimateCompressionRatio(bytes);

      let previewType = null;
      let mediaUrl = null;
      let preview = null;
      let note = null;

      const isImage =
        lowerMime.startsWith("image/") ||
        format === "png" ||
        format === "jpeg" ||
        format === "gif" ||
        format === "webp";

      const isVideo =
        lowerMime.startsWith("video/") || format === "mp4";

      const isAudio =
        lowerMime.startsWith("audio/") ||
        format === "mp3" ||
        format === "ogg";

      const textLikeMime =
        lowerMime.startsWith("text/") ||
        lowerMime.includes("json") ||
        lowerMime.includes("xml") ||
        lowerMime.includes("csv") ||
        lowerMime.includes("yaml") ||
        lowerMime.includes("toml");

      if (isImage) {
        classification = "media-image";
        likelyEncrypted = false;
        reason = "Image content based on mime or magic header";
        previewType = "image";
        mediaUrl = `/raw?net=${encodeURIComponent(
          network
        )}&id=${encodeURIComponent(blobId)}`;
        note = "Image content rendered from Walrus";
      } else if (isVideo) {
        classification = "media-video";
        likelyEncrypted = false;
        reason = "Video content based on mime or magic header";
        previewType = "video";
        mediaUrl = `/raw?net=${encodeURIComponent(
          network
        )}&id=${encodeURIComponent(blobId)}`;
        note = "Video content rendered from Walrus";
      } else if (isAudio) {
        classification = "media-audio";
        likelyEncrypted = false;
        reason = "Audio content based on mime or magic header";
        previewType = "audio";
        mediaUrl = `/raw?net=${encodeURIComponent(
          network
        )}&id=${encodeURIComponent(blobId)}`;
        note = "Audio content rendered from Walrus";
      } else {
        const looksBinary = isBinary(bytes);

        if (!looksBinary) {
          const fullText = textDecoder.decode(bytes);

          const requestedMax = Number(req.query.maxLen || 500);
          const maxLen =
            Number.isFinite(requestedMax) &&
            requestedMax > 0 &&
            requestedMax <= 4000
              ? requestedMax
              : 500;

          preview =
            fullText.length > maxLen
              ? fullText.slice(0, maxLen) + "…"
              : fullText;
          textSummary = summarizeText(bytes, maxLen);
          const isJson = textSummary && textSummary.isJson;
          classification = isJson
            ? "text-json"
            : textLikeMime
            ? "text-structured"
            : "text";
          likelyEncrypted = false;
          reason = isJson
            ? "Looks like JSON content"
            : textLikeMime
            ? "Text content based on mime type"
            : "Bytes look like plain text";
          previewType = "text";
        } else {
          if (
            format === "zip" ||
            format === "gzip" ||
            format === "pdf" ||
            format === "sqlite" ||
            format === "serialization-archive"
          ) {
            classification =
              format === "serialization-archive" ? "binary-archive" : "binary-known";
            likelyEncrypted = false;
            if (format === "serialization-archive") {
              reason =
                "Binary archive with a serialization::archive header, probably structured data rather than raw media";
              if (compressionRatio !== null && compressionRatio > 0.95) {
                reason =
                  "Binary archive with a serialization::archive header, highly compressed structured data";
              }
            } else {
              reason = `Known format: ${format}`;
            }
          } else {
            classification = "binary";
            entropyBitsPerByte = estimateEntropy(bytes);

            if (entropyBitsPerByte >= 7.5) {
              likelyEncrypted = true;
              reason =
                "Binary data with very high entropy, likely encrypted or strongly compressed";
            } else {
              likelyEncrypted = false;
              reason =
                "Binary data with moderate entropy, probably structured data or light compression";
            }

            if (compressionRatio !== null) {
              if (entropyBitsPerByte >= 7.5 && compressionRatio > 0.9) {
                likelyEncrypted = true;
                reason =
                  "High entropy data that does not compress much, very likely encrypted";
              } else if (entropyBitsPerByte >= 7.3 && compressionRatio < 0.8) {
                likelyEncrypted = false;
                reason =
                  "High entropy data that still compresses, probably strongly compressed content rather than pure encryption";
              }
            }

            const decompressed = tryDecompressToText(bytes, 800);
            if (decompressed) {
              const { algo, summary } = decompressed;
              textSummary = summary;
              preview = summary.preview;
              previewType = "text";

              if (summary.isJson) {
                classification = "binary-compressed-json";
                reason = `Binary content that looks like ${algo} compressed JSON`;
              } else {
                classification = "binary-compressed-text";
                reason = `Binary content that looks like ${algo} compressed text`;
              }

              likelyEncrypted = false;
              note = `Decompressed successfully using ${algo} for preview`;
            }
          }

          if (!preview && !previewType) {
            preview = null;
            previewType = null;
            mediaUrl = null;

            if (!note) {
              if (classification === "binary-archive") {
                note =
                  "Binary archive with a serialization::archive header, preview disabled";
              } else if (likelyEncrypted) {
                note =
                  "Binary blob that looks encrypted or strongly compressed, preview disabled";
              } else {
                note = "Binary content, preview disabled";
              }
            }
          }
        }
      }

      const encryptionGuess = {
        classification,
        likelyEncrypted,
        reason,
        entropyBitsPerByte,
        compressionRatio,
      };

      const walrusUrl = `${aggregatorBase}/v1/blobs/${encodeURIComponent(
        blobId
      )}`;

      return res.json({
        ...baseResponse,
        availability: "present",
        existsOnWalrus: true,
        hasSeal,
        sealMeta,
        preview,
        previewType,
        mediaUrl,
        mimeType,
        sizeBytes,
        hashes,
        byteSample,
        walrusHeaders,
        format,
        textSummary,
        walrusUrl,
        encryptionGuess,
        note,
      });
    } catch (err) {
      console.error("[ERROR] Unexpected inspector failure:", err);
      const status = err.status || 500;
      return res.status(status).json({
        ...baseResponse,
        availability: "unknown",
        existsOnWalrus: null,
        hasSeal: false,
        sealMeta: null,
        preview: null,
        previewType: null,
        mediaUrl: null,
        mimeType: null,
        sizeBytes: null,
        encryptionGuess: null,
        error: err.message || "Internal error",
      });
    }
  });

  // inspect by Sui blob object id
  app.get("/inspect-object", async (req, res) => {
    const objectId = req.query.objectId;

    if (!objectId || typeof objectId !== "string" || !objectId.trim()) {
      return res.status(400).json({ error: "Missing objectId query parameter" });
    }

    const netParam = typeof req.query.net === "string" ? req.query.net : "testnet";

    let agg;
    try {
      agg = getAggregatorBase(config, netParam);
    } catch (err) {
      console.error("[ERROR] Aggregator selection failed:", err.message);
      const status = err.status || 500;
      return res.status(status).json({
        objectId: objectId.trim(),
        network: netParam,
        availability: "unknown",
        existsOnWalrus: null,
        preview: null,
        previewType: null,
        mediaUrl: null,
        mimeType: null,
        sizeBytes: null,
        encryptionGuess: null,
        error: err.message,
      });
    }

    const { base: aggregatorBase, network } = agg;
    const id = objectId.trim();
    const baseResponse = { objectId: id, network };

    try {
      const url = `${aggregatorBase}/v1/blobs/by-object-id/${encodeURIComponent(
        id
      )}`;
      console.log("[INFO] Fetching from Walrus by object id:", url);

      const walrusResp = await fetch(url);

      if (!walrusResp.ok) {
        const errText = await walrusResp.text().catch(() => "");
        const snippet = errText.slice(0, 200);
        console.error("[ERROR] Walrus replied", walrusResp.status, snippet);

        const { availability, note } = interpretWalrusError(
          walrusResp.status,
          snippet
        );

        return res.status(walrusResp.status).json({
          ...baseResponse,
          availability,
          existsOnWalrus: availability === "present" ? true : false,
          preview: null,
          previewType: null,
          mediaUrl: null,
          mimeType: null,
          sizeBytes: null,
          walrusStatus: walrusResp.status,
          walrusUrl: url,
          walrusSnippet: snippet || null,
          encryptionGuess: null,
          note,
          error: "Walrus fetch failed",
        });
      }

      const mimeTypeHeader =
        walrusResp.headers.get("content-type") || "application/octet-stream";
      const mimeType = mimeTypeHeader;
      const buf = await walrusResp.arrayBuffer();
      const bytes = new Uint8Array(buf);
      const sizeBytes = bytes.length;
      const walrusHeaders = headersToObject(walrusResp.headers);
      const { hashes, byteSample } = summarizeBytes(bytes);
      let textSummary = null;

      const { hasSeal, sealMeta } = detectSeal(bytes);

      const lowerMime = mimeType.toLowerCase();
      let format = detectBinaryFormat(bytes);
      if (!format) {
        const mimePart = lowerMime.split(";")[0].split("/")[1] || null;
        if (mimePart && mimePart !== "octet-stream") {
          format = mimePart;
        }
      }

      let classification = "unknown";
      let likelyEncrypted = false;
      let reason = null;
      let entropyBitsPerByte = null;
      const compressionRatio = estimateCompressionRatio(bytes);

      let previewType = null;
      let mediaUrl = null;
      let preview = null;
      let note = null;

      const isImage =
        lowerMime.startsWith("image/") ||
        format === "png" ||
        format === "jpeg" ||
        format === "gif" ||
        format === "webp";

      const isVideo =
        lowerMime.startsWith("video/") || format === "mp4";

      const isAudio =
        lowerMime.startsWith("audio/") ||
        format === "mp3" ||
        format === "ogg";

      const textLikeMime =
        lowerMime.startsWith("text/") ||
        lowerMime.includes("json") ||
        lowerMime.includes("xml") ||
        lowerMime.includes("csv") ||
        lowerMime.includes("yaml") ||
        lowerMime.includes("toml");

      if (isImage) {
        classification = "media-image";
        likelyEncrypted = false;
        reason = "Image content based on mime or magic header";
        previewType = "image";
        mediaUrl = `/raw?net=${encodeURIComponent(
          network
        )}&id=${encodeURIComponent(id)}`;
        note = "Image content rendered from Walrus";
      } else if (isVideo) {
        classification = "media-video";
        likelyEncrypted = false;
        reason = "Video content based on mime or magic header";
        previewType = "video";
        mediaUrl = `/raw?net=${encodeURIComponent(
          network
        )}&id=${encodeURIComponent(id)}`;
        note = "Video content rendered from Walrus";
      } else if (isAudio) {
        classification = "media-audio";
        likelyEncrypted = false;
        reason = "Audio content based on mime or magic header";
        previewType = "audio";
        mediaUrl = `/raw?net=${encodeURIComponent(
          network
        )}&id=${encodeURIComponent(id)}`;
        note = "Audio content rendered from Walrus";
      } else {
        const looksBinary = isBinary(bytes);

        if (!looksBinary) {
          const fullText = textDecoder.decode(bytes);
          const maxLen = 500;

          preview =
            fullText.length > maxLen
              ? fullText.slice(0, maxLen) + "…"
              : fullText;
          textSummary = summarizeText(bytes, maxLen);
          const isJson = textSummary && textSummary.isJson;
          classification = isJson
            ? "text-json"
            : textLikeMime
            ? "text-structured"
            : "text";
          likelyEncrypted = false;
          reason = isJson
            ? "Looks like JSON content"
            : textLikeMime
            ? "Text content based on mime type"
            : "Bytes look like plain text";
          previewType = "text";
        } else {
          if (
            format === "zip" ||
            format === "gzip" ||
            format === "pdf" ||
            format === "sqlite" ||
            format === "serialization-archive"
          ) {
            classification =
              format === "serialization-archive" ? "binary-archive" : "binary-known";
            likelyEncrypted = false;
            if (format === "serialization-archive") {
              reason =
                "Binary archive with a serialization::archive header, probably structured data rather than raw media";
              if (compressionRatio !== null && compressionRatio > 0.95) {
                reason =
                  "Binary archive with a serialization::archive header, highly compressed structured data";
              }
            } else {
              reason = `Known format: ${format}`;
            }
          } else {
            classification = "binary";
            entropyBitsPerByte = estimateEntropy(bytes);

            if (entropyBitsPerByte >= 7.5) {
              likelyEncrypted = true;
              reason =
                "Binary data with very high entropy, likely encrypted or strongly compressed";
            } else {
              likelyEncrypted = false;
              reason =
                "Binary data with moderate entropy, probably structured data or light compression";
            }

            if (compressionRatio !== null) {
              if (entropyBitsPerByte >= 7.5 && compressionRatio > 0.9) {
                likelyEncrypted = true;
                reason =
                  "High entropy data that does not compress much, very likely encrypted";
              } else if (entropyBitsPerByte >= 7.3 && compressionRatio < 0.8) {
                likelyEncrypted = false;
                reason =
                  "High entropy data that still compresses, probably strongly compressed content rather than pure encryption";
              }
            }

            const decompressed = tryDecompressToText(bytes, 800);
            if (decompressed) {
              const { algo, summary } = decompressed;
              textSummary = summary;
              preview = summary.preview;
              previewType = "text";

              if (summary.isJson) {
                classification = "binary-compressed-json";
                reason = `Binary content that looks like ${algo} compressed JSON`;
              } else {
                classification = "binary-compressed-text";
                reason = `Binary content that looks like ${algo} compressed text`;
              }

              likelyEncrypted = false;
              note = `Decompressed successfully using ${algo} for preview`;
            }
          }

          if (!preview && !previewType) {
            preview = null;
            previewType = null;
            mediaUrl = null;

            if (!note) {
              if (classification === "binary-archive") {
                note =
                  "Binary archive with a serialization::archive header, preview disabled";
              } else if (likelyEncrypted) {
                note =
                  "Binary blob that looks encrypted or strongly compressed, preview disabled";
              } else {
                note = "Binary content, preview disabled";
              }
            }
          }
        }
      }

      const encryptionGuess = {
        classification,
        likelyEncrypted,
        reason,
        entropyBitsPerByte,
        compressionRatio,
      };

      return res.json({
        ...baseResponse,
        availability: "present",
        existsOnWalrus: true,
        preview,
        previewType,
        mediaUrl,
        mimeType,
        sizeBytes,
        hashes,
        byteSample,
        walrusHeaders,
        format,
        textSummary,
        walrusUrl: url,
        encryptionGuess,
        hasSeal,
        sealMeta,
        note,
      });
    } catch (err) {
      console.error("[ERROR] Unexpected object inspector failure:", err);
      const status = err.status || 500;
      return res.status(status).json({
        ...baseResponse,
        availability: "unknown",
        existsOnWalrus: null,
        preview: null,
        previewType: null,
        mediaUrl: null,
        mimeType: null,
        sizeBytes: null,
        encryptionGuess: null,
        error: err.message || "Internal error",
      });
    }
  });

  return app;
}

function logAggregators(config) {
  if (!config.walrus.testnet && !config.walrus.mainnet) {
    console.warn("[WARN] No Walrus aggregators configured (testnet or mainnet)");
  } else {
    if (config.walrus.testnet) {
      console.log("[INFO] Testnet aggregator:", config.walrus.testnet);
    }
    if (config.walrus.mainnet) {
      console.log("[INFO] Mainnet aggregator:", config.walrus.mainnet);
    }
  }
}

// Starts the inspector with the given way of finding a blob's Sui object.
function start(makeLookup, config = readConfig()) {
  logAggregators(config);
  const lookup = makeLookup(config);
  const app = createApp({ config, lookup });
  return app.listen(config.port, () => {
    console.log(
      `Inspector listening on port ${config.port} (Sui object lookup: ${lookup.name})`
    );
  });
}

module.exports = { createApp, start, getAggregatorBase };
