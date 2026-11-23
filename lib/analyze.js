// Byte-level analysis of a blob: Seal detection, file format, entropy,
// compression and text previews. No network access.
const crypto = require("crypto");
const zlib = require("zlib");
const { TextDecoder } = require("util");
const { EncryptedObject } = require("@mysten/seal");

const textDecoder = new TextDecoder("utf-8", { fatal: false });

// A blob counts as Seal-encrypted only when it is exactly one serialized
// EncryptedObject: version 0, a valid threshold and no trailing bytes.
// Parsing alone is not enough, because BCS can read arbitrary bytes as a header.
function detectSeal(bytes) {
  try {
    const encObj = EncryptedObject.parse(new Uint8Array(bytes));
    const services = Array.isArray(encObj.services) ? encObj.services : [];
    const consumed = EncryptedObject.serialize(encObj).toBytes().length;
    if (
      encObj.version !== 0 ||
      services.length === 0 ||
      encObj.threshold < 1 ||
      encObj.threshold > services.length ||
      consumed !== bytes.length
    ) {
      return { hasSeal: false, sealMeta: null };
    }
    return {
      hasSeal: true,
      sealMeta: {
        idHex:
          typeof encObj.id === "string"
            ? encObj.id
            : Buffer.from(encObj.id).toString("hex"),
        threshold: encObj.threshold,
        services: services.map(([objectId, weight]) => ({ objectId, weight })),
      },
    };
  } catch (e) {
    return { hasSeal: false, sealMeta: null };
  }
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

module.exports = {
  textDecoder,
  detectSeal,
  isBinary,
  estimateEntropy,
  estimateCompressionRatio,
  detectBinaryFormat,
  summarizeBytes,
  summarizeText,
  tryDecompressToText,
};
