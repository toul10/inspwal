function blobBase64ToDecimal(blobIdBase64) {
  const padLen = (4 - (blobIdBase64.length % 4)) % 4;
  const padded = blobIdBase64 + "=".repeat(padLen);

  const bytesLE = Buffer.from(padded, "base64url");
  if (bytesLE.length !== 32) {
    throw new Error("Expected 32 byte blob id, got " + bytesLE.length);
  }

  let n = 0n;
  for (let i = bytesLE.length - 1; i >= 0; i--) {
    n = (n << 8n) + BigInt(bytesLE[i]);
  }

  return n.toString(10);
}

module.exports = { blobBase64ToDecimal };
