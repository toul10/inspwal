const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const zlib = require("node:zlib");
const { EncryptedObject } = require("@mysten/seal");
const {
  detectSeal,
  detectBinaryFormat,
  isBinary,
  estimateEntropy,
  estimateCompressionRatio,
  tryDecompressToText,
} = require("../lib/analyze");

// Bytes that look random but are the same on every run.
function noise(length) {
  const parts = [];
  for (let i = 0; parts.length * 32 < length; i++) {
    parts.push(crypto.createHash("sha256").update(`inspwal-${i}`).digest());
  }
  return Buffer.concat(parts).subarray(0, length);
}

const address = (digit) => "0x" + digit.repeat(64);

function sealObject({ version = 0, threshold = 2 } = {}) {
  return EncryptedObject.serialize({
    version,
    packageId: address("1"),
    id: "deadbeef",
    services: [
      [address("2"), 1],
      [address("3"), 1],
    ],
    threshold,
    encryptedShares: {
      BonehFranklinBLS12381: {
        nonce: Array(96).fill(7),
        encryptedShares: [Array(32).fill(1), Array(32).fill(2)],
        encryptedRandomness: Array(32).fill(3),
      },
    },
    ciphertext: { Aes256Gcm: { blob: Array(300).fill(9), aad: null } },
  }).toBytes();
}

test("detectSeal reads the metadata of a serialized Seal object", () => {
  assert.deepEqual(detectSeal(sealObject()), {
    hasSeal: true,
    sealMeta: {
      idHex: "deadbeef",
      threshold: 2,
      services: [
        { objectId: address("2"), weight: 1 },
        { objectId: address("3"), weight: 1 },
      ],
    },
  });
});

test("detectSeal rejects bytes that are not exactly one valid Seal object", () => {
  const notSeal = { hasSeal: false, sealMeta: null };
  const trailing = Buffer.concat([sealObject(), Buffer.from([1, 2, 3])]);
  assert.deepEqual(detectSeal(trailing), notSeal);
  assert.deepEqual(detectSeal(sealObject({ version: 1 })), notSeal);
  assert.deepEqual(detectSeal(sealObject({ threshold: 3 })), notSeal);
  assert.deepEqual(detectSeal(noise(4096)), notSeal);
  assert.deepEqual(detectSeal(new Uint8Array(0)), notSeal);
});

test("detectBinaryFormat recognises common file headers", () => {
  const withHeader = (...parts) =>
    Buffer.concat([...parts.map((part) => Buffer.from(part)), noise(64)]);
  const cases = {
    png: withHeader([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    jpeg: withHeader([0xff, 0xd8, 0xff, 0xe0]),
    gif: withHeader("GIF89a"),
    webp: withHeader("RIFF", [0, 0, 0, 0], "WEBPVP8 "),
    mp4: withHeader([0, 0, 0, 0x18], "ftypmp42"),
    mp3: withHeader("ID3"),
    ogg: withHeader("OggS"),
    zip: withHeader([0x50, 0x4b, 0x03, 0x04]),
    gzip: zlib.gzipSync("walrus"),
    pdf: withHeader("%PDF-1.7\n"),
    sqlite: withHeader("SQLite format 3\0"),
    "serialization-archive": withHeader(
      [0x16, 0, 0, 0, 0, 0, 0, 0],
      "serialization::archive"
    ),
  };
  for (const [format, bytes] of Object.entries(cases)) {
    assert.equal(detectBinaryFormat(bytes), format, format);
  }
  assert.equal(detectBinaryFormat(Buffer.from("plain words, no header")), null);
  assert.equal(detectBinaryFormat(Buffer.from([1, 2])), null);
});

test("isBinary tells ASCII text from binary data", () => {
  assert.equal(isBinary(Buffer.from("hello walrus\n")), false);
  assert.equal(isBinary(noise(512)), true);
  assert.equal(isBinary(new Uint8Array(0)), false);
});

test("entropy and compression ratio separate zeros from random data", () => {
  assert.ok(estimateEntropy(Buffer.alloc(65536)) < 0.01);
  assert.ok(estimateEntropy(noise(65536)) > 7.9);
  assert.ok(estimateCompressionRatio(Buffer.alloc(65536)) < 0.01);
  assert.ok(estimateCompressionRatio(noise(65536)) > 0.99);
  assert.equal(estimateCompressionRatio(new Uint8Array(0)), null);
});

test("tryDecompressToText finds gzip, deflate and brotli text", () => {
  const json = JSON.stringify({ hello: "walrus" });
  const algorithms = [
    ["gzip", zlib.gzipSync],
    ["deflate", zlib.deflateSync],
    ["brotli", zlib.brotliCompressSync],
  ];
  for (const [algo, compress] of algorithms) {
    const result = tryDecompressToText(compress(json));
    assert.equal(result.algo, algo);
    assert.equal(result.summary.isJson, true);
  }
  assert.equal(tryDecompressToText(noise(1024)), null);
});
