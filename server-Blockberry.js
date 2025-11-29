const express = require("express");
const fetch = require("node-fetch");
const { TextDecoder } = require("util");
const crypto = require("crypto");
const zlib = require("zlib");
const { EncryptedObject } = require("@mysten/seal");
const { blobBase64ToDecimal } = require("./utils/blobId");
const { lookupByBlobDecimal } = require("./indexer/store");
require("dotenv").config();

const app = express();
const port = process.env.PORT || 3001;
const helperPort = process.env.PORT2 || 3002;
const helperBase =
  process.env.SUI_HELPER_URL || `http://localhost:${helperPort}`;
// Blockberry config
const BLOCKBERRY_KEY = process.env.BLOCKBERRY_API_KEY || "";
const BLOCKBERRY_WALRUS_MAINNET_BASE =
  process.env.BLOCKBERRY_WALRUS_MAINNET_BASE ||
  process.env.BLOCKBERRY_WALRUS_BASE ||
  "https://api.blockberry.one/walrus-mainnet/v1";
const BLOCKBERRY_WALRUS_TESTNET_BASE =
  process.env.BLOCKBERRY_WALRUS_TESTNET_BASE ||
  "https://api.blockberry.one/walrus-testnet/v1";
// Sui RPC config
const SUI_MAINNET_RPC_URL =
  process.env.SUI_MAINNET_RPC_URL ||
  process.env.SUI_RPC_MAINNET ||
  "https://fullnode.mainnet.sui.io:443";
const SUI_TESTNET_RPC_URL =
  process.env.SUI_TESTNET_RPC_URL ||
  process.env.SUI_RPC_TESTNET ||
  "https://fullnode.testnet.sui.io:443";

// read aggregators from env
const rawTestnet =
  process.env.WALRUS_TESTNET_URL || process.env.WALRUS_BASE_URL || "";
const rawMainnet = process.env.WALRUS_MAINNET_URL || "";

const WALRUS_TESTNET_URL = rawTestnet ? rawTestnet.replace(/\/$/, "") : null;
const WALRUS_MAINNET_URL = rawMainnet ? rawMainnet.replace(/\/$/, "") : null;

if (!WALRUS_TESTNET_URL && !WALRUS_MAINNET_URL) {
  console.warn("[WARN] No Walrus aggregators configured (testnet or mainnet)");
} else {
  if (WALRUS_TESTNET_URL) {
    console.log("[INFO] Testnet aggregator:", WALRUS_TESTNET_URL);
  }
  if (WALRUS_MAINNET_URL) {
    console.log("[INFO] Mainnet aggregator:", WALRUS_MAINNET_URL);
  }
}

function getAggregatorBase(net) {
  const network = (net || "testnet").toString().toLowerCase();
  if (network === "mainnet") {
    if (!WALRUS_MAINNET_URL) {
      const err = new Error("Mainnet aggregator not configured");
      err.status = 500;
      throw err;
    }
    return { base: WALRUS_MAINNET_URL, network: "mainnet" };
  }
  if (!WALRUS_TESTNET_URL) {
    const err = new Error("Testnet aggregator not configured");
    err.status = 500;
    throw err;
  }
  return { base: WALRUS_TESTNET_URL, network: "testnet" };
}

const textDecoder = new TextDecoder("utf-8", { fatal: false });

// generic hook, for now no special knowledge about Seal
function isSealConfirmed(network, blobId) {
  return false;
}

// quick text vs binary detector
function isBinary(bytes) {
  if (!bytes || bytes.length === 0) return false;

  let nonText = 0;
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];

    if (b === 0) {
      return true;
    }
    if (b < 9 || (b > 13 && b < 32) || b > 126) {
      nonText++;
    }
  }

  const ratio = nonText / bytes.length;
  return ratio > 0.3;
}

function estimateEntropy(bytes, maxSamples = 16384) {
  const n = Math.min(bytes.length, maxSamples);
  if (n === 0) return 0;

  const counts = new Array(256).fill(0);
  for (let i = 0; i < n; i++) {
    counts[bytes[i]]++;
  }

  let entropy = 0;
  for (let i = 0; i < 256; i++) {
    const c = counts[i];
    if (!c) continue;
    const p = c / n;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function estimateCompressionRatio(bytes, maxSamples = 65536) {
  try {
    if (!bytes || !bytes.length) return null;
    const sample = bytes.slice(0, Math.min(bytes.length, maxSamples));
    const compressed = zlib.deflateSync(sample);
    if (!compressed.length || sample.length === 0) return null;
    return compressed.length / sample.length;
  } catch (e) {
    console.warn(
      "[WARN] compression ratio check failed:",
      e.message || String(e)
    );
    return null;
  }
}

function startsWithBytes(bytes, pattern, offset = 0) {
  if (!bytes || bytes.length < pattern.length + offset) return false;
  for (let i = 0; i < pattern.length; i++) {
    if (bytes[offset + i] !== pattern[i]) return false;
  }
  return true;
}

// detect some common binary formats by magic header
function detectBinaryFormat(bytes) {
  if (!bytes || bytes.length < 4) return null;

  // png
  if (
    startsWithBytes(bytes, [
      0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
    ])
  ) {
    return "png";
  }

  // jpeg
  if (startsWithBytes(bytes, [0xff, 0xd8, 0xff])) {
    return "jpeg";
  }

  // gif
  if (startsWithBytes(bytes, [0x47, 0x49, 0x46, 0x38])) {
    return "gif";
  }

  // webp
  if (
    startsWithBytes(bytes, [0x52, 0x49, 0x46, 0x46]) &&
    startsWithBytes(bytes, [0x57, 0x45, 0x42, 0x50], 8)
  ) {
    return "webp";
  }

  // pdf
  if (startsWithBytes(bytes, [0x25, 0x50, 0x44, 0x46])) {
    return "pdf";
  }

  // zip
  if (startsWithBytes(bytes, [0x50, 0x4b, 0x03, 0x04])) {
    return "zip";
  }

  // gzip
  if (startsWithBytes(bytes, [0x1f, 0x8b])) {
    return "gzip";
  }

  // sqlite
  if (
    startsWithBytes(
      bytes,
      [
        0x53, 0x51, 0x4c, 0x69, 0x74, 0x65, 0x20, 0x66,
        0x6f, 0x72, 0x6d, 0x61, 0x74, 0x20, 0x33, 0x00,
      ]
    )
  ) {
    return "sqlite";
  }

  // mp4
  if (bytes.length > 12 && startsWithBytes(bytes, [0x66, 0x74, 0x79, 0x70], 4)) {
    return "mp4";
  }

  // mp3
  if (
    startsWithBytes(bytes, [0x49, 0x44, 0x33]) ||
    startsWithBytes(bytes, [0xff, 0xfb])
  ) {
    return "mp3";
  }

  // ogg
  if (startsWithBytes(bytes, [0x4f, 0x67, 0x67, 0x53])) {
    return "ogg";
  }

  // generic serialized archive header
  try {
    const asciiHeader = Buffer.from(bytes.slice(0, 64)).toString("ascii");
    if (asciiHeader.includes("serialization::archive")) {
      return "serialization-archive";
    }
  } catch (_) {
    // ignore
  }

  return null;
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

function summarizeBytes(bytes) {
  const buf = Buffer.from(bytes);
  const sample = buf.subarray(0, Math.min(buf.length, 64));

  return {
    hashes: {
      sha256: crypto.createHash("sha256").update(buf).digest("hex"),
      sha512: crypto.createHash("sha512").update(buf).digest("hex"),
      blake2b512: crypto.createHash("blake2b512").update(buf).digest("hex"),
      sha1: crypto.createHash("sha1").update(buf).digest("hex"),
      md5: crypto.createHash("md5").update(buf).digest("hex"),
    },
    byteSample: {
      hex: sample.toString("hex"),
      base64: sample.toString("base64"),
      length: sample.length,
    },
  };
}

function summarizeText(bytes, maxLen = 800) {
  const buf = Buffer.from(bytes);
  const text = textDecoder.decode(buf);

  const printable = Array.from(text).filter((ch) => {
    const code = ch.charCodeAt(0);
    return code >= 32 && code <= 126;
  }).length;
  const printableRatio =
    text.length === 0 ? 1 : Number((printable / text.length).toFixed(3));

  let isJson = false;
  let jsonKeys = null;
  try {
    const parsed = JSON.parse(text);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      isJson = true;
      jsonKeys = Object.keys(parsed).slice(0, 10);
    } else if (Array.isArray(parsed)) {
      isJson = true;
    }
  } catch (_) {
    // not json, ignore
  }

  const preview =
    text.length > maxLen ? `${text.slice(0, maxLen)}…` : text;

  return {
    preview,
    printableRatio,
    isJson,
    jsonKeys,
    length: text.length,
    lines: text.split(/\r?\n/).length,
  };
}

// try to decompress with a few common algorithms and see if we get readable text
function tryDecompressToText(bytes, maxLen = 2000) {
  const buf = Buffer.from(bytes);

  const attempts = [
    { name: "gzip", fn: zlib.gunzipSync },
    { name: "deflate", fn: zlib.inflateSync },
    { name: "brotli", fn: zlib.brotliDecompressSync },
  ];

  for (const attempt of attempts) {
    try {
      const out = attempt.fn(buf);
      // if result still looks binary, ignore this attempt
      if (isBinary(out)) continue;

      const summary = summarizeText(out, maxLen);
      return { algo: attempt.name, summary };
    } catch (e) {
      // not this compression format, ignore
    }
  }

  return null;
}

// measure how compressible the blob is
function estimateCompressionRatio(bytes) {
  try {
    const buf = Buffer.from(bytes);
    const compressed = zlib.deflateSync(buf);
    if (!compressed.length || !buf.length) return null;
    return compressed.length / buf.length;
  } catch (e) {
    return null;
  }
}

async function getSuiDetailsFromBlobId(blobIdBase64, net = "mainnet") {
  const blobIdDecimal = blobBase64ToDecimal(blobIdBase64);
  const row = lookupByBlobDecimal(blobIdDecimal);
  if (!row) {
    const err = new Error("Blob id not found in local Walrus index");
    err.status = 404;
    throw err;
  }

  const suiRpc =
    net === "testnet" ? SUI_TESTNET_RPC_URL : SUI_MAINNET_RPC_URL;

  const objectId = row.object_id;
  const txDigest = row.tx_digest;

  const [objectResult, txResult] = await Promise.all([
    callSuiRpc(suiRpc, "sui_getObject", [
      objectId,
      {
        showType: true,
        showOwner: true,
        showPreviousTransaction: true,
        showContent: true,
        showDisplay: false,
        showStorageRebate: true,
      },
    ]),
    txDigest
      ? callSuiRpc(suiRpc, "sui_getTransactionBlock", [
          txDigest,
          {
            showInput: true,
            showEffects: true,
            showEvents: true,
            showObjectChanges: true,
            showBalanceChanges: true,
          },
        ])
      : null,
  ]);

  return {
    ok: true,
    network: net,
    blobId: blobIdBase64,
    objectId,
    summary: {
      registeredEpoch: row.start_epoch,
      certifiedEpoch: row.end_epoch,
      deletable: row.deletable,
      txDigest,
    },
    suiObject: objectResult,
    suiTransaction: txResult,
  };
}

async function callSuiRpc(url, method, params) {
  const body = {
    jsonrpc: "2.0",
    id: Date.now(),
    method,
    params,
  };

  const res = await fetch(url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify(body),
  });

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(
      `Sui RPC error status ${res.status} ${res.statusText} body ${text}`
    );
  }

  const json = await res.json();
  if (json.error) {
    throw new Error(
      `Sui RPC returned error ${json.error.code}: ${json.error.message}`
    );
  }

  return json.result;
}

async function getBlobFromBlockberry(blobId, net = "mainnet") {
  if (!BLOCKBERRY_KEY) {
    throw new Error(
      "Missing BLOCKBERRY_API_KEY env value for Blockberry access"
    );
  }

  const base =
    net === "testnet"
      ? BLOCKBERRY_WALRUS_TESTNET_BASE
      : BLOCKBERRY_WALRUS_MAINNET_BASE;
  const url = `${base}/blobs/${encodeURIComponent(blobId)}`;

  const res = await fetch(url, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${BLOCKBERRY_KEY}`,
      "x-api-key": BLOCKBERRY_KEY,
      accept: "application/json",
    },
  });

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    const err = new Error(
      `Blockberry error status ${res.status} ${res.statusText} body ${text}`
    );
    err.status = res.status;
    err.body = text;
    err.urlTried = url;
    throw err;
  }

  const json = await res.json();
  const data = json.data || json;

  const objectId =
    data.objectId ||
    data.suiObjectId ||
    (Array.isArray(data.items) &&
      data.items[0] &&
      data.items[0].objectId) ||
    null;

  if (!objectId) {
    throw new Error(
      "Could not find objectId in Blockberry blob response, check payload format"
    );
  }

  return { blob: data, objectId };
}

// serve static front end from ./public
app.use(express.static("public"));

// basic health
app.get("/health", (req, res) => {
  res.json({
    ok: true,
    testnetAggregator: WALRUS_TESTNET_URL,
    mainnetAggregator: WALRUS_MAINNET_URL,
    suiHelper: helperBase,
  });
});

app.get("/sui-from-blob", async (req, res) => {
  const blobId = (req.query.id || "").trim();
  const net = (req.query.net || "mainnet").toLowerCase();

  if (!blobId) {
    return res.status(400).json({
      ok: false,
      error: "Missing query parameter id with Walrus blob id",
    });
  }

  try {
    let blobInfo = null;
    let objectId = null;
    let usedNet = net;
    let lastErr = null;

    try {
      blobInfo = await getBlobFromBlockberry(blobId, net);
      objectId = blobInfo.objectId;
    } catch (err) {
      lastErr = err;
      console.warn(
        `[WARN] Blockberry lookup failed on ${net}, retrying other net if possible:`,
        err.message || err
      );
      const altNet = net === "mainnet" ? "testnet" : "mainnet";
      try {
        const alt = await getBlobFromBlockberry(blobId, altNet);
        blobInfo = alt;
        objectId = alt.objectId;
        usedNet = altNet;
      } catch (err2) {
        lastErr = err2;
        blobInfo = null;
      }
    }

    if (!blobInfo || !objectId) {
      return res.status(404).json({
        ok: false,
        network: net,
        blobId,
        error:
          (lastErr && lastErr.message) ||
          "Could not fetch blob/object from Blockberry",
      });
    }

    const { blob } = blobInfo;

    let suiRpc;
    if (usedNet === "mainnet") {
      suiRpc = SUI_MAINNET_RPC_URL;
    } else if (usedNet === "testnet") {
      suiRpc = SUI_TESTNET_RPC_URL;
    } else {
      suiRpc = SUI_MAINNET_RPC_URL;
    }

    const objectResult = await callSuiRpc(suiRpc, "sui_getObject", [
      objectId,
      {
        showType: true,
        showOwner: true,
        showPreviousTransaction: true,
        showContent: true,
        showDisplay: false,
        showStorageRebate: true,
      },
    ]);

    const objectData = objectResult.data || null;
    const previousTxDigest =
      objectData && objectData.previousTransaction
        ? objectData.previousTransaction
        : null;

    let txResult = null;

    if (previousTxDigest) {
      txResult = await callSuiRpc(suiRpc, "sui_getTransactionBlock", [
        previousTxDigest,
        {
          showInput: true,
          showEffects: true,
          showEvents: true,
          showObjectChanges: true,
          showBalanceChanges: true,
        },
      ]);
    }

    res.json({
      ok: true,
      network: usedNet,
      blobId,
      objectId,
      sources: {
        blockberry: blob,
      },
      suiObject: objectResult,
      suiTransaction: txResult,
    });
  } catch (err) {
    console.error("[sui-from-blob] error", err);
    const status = err.status || 500;
    res.status(status).json({
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
    agg = getAggregatorBase(netParam);
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
    agg = getAggregatorBase(netParam);
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
    const sealConfirmed = isSealConfirmed(network, blobId);
    if (sealConfirmed) {
      const url = `${aggregatorBase}/v1/blobs/${encodeURIComponent(blobId)}`;
      const mediaUrl = `/raw?net=${encodeURIComponent(network)}&id=${encodeURIComponent(
        blobId
      )}`;
      return res.json({
        ...baseResponse,
        availability: "present",
        existsOnWalrus: true,
        hasSeal: true,
        preview: null,
        previewType: null,
        mediaUrl,
        mimeType: null,
        sizeBytes: null,
        walrusUrl: url,
        encryptionGuess: null,
        note: "Content marked as protected by the app, preview disabled",
      });
    }

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

    let hasSeal = false;
    let sealMeta = null;
    try {
      const encObj = EncryptedObject.parse(new Uint8Array(bytes));
      hasSeal = true;
      sealMeta = {
        idHex: Buffer.from(encObj.id).toString("hex"),
        threshold: encObj.threshold,
        services: Array.isArray(encObj.services)
          ? encObj.services.map(([objectId, weight]) => ({
              objectId,
              weight,
            }))
          : [],
      };
    } catch (e) {
      hasSeal = false;
      sealMeta = null;
    }

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
      hasSeal,
      sealMeta,
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
    agg = getAggregatorBase(netParam);
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

app.listen(port, () => {
  console.log(`Inspector listening on port ${port}`);
});
