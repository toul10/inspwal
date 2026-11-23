const { blobBase64ToDecimal } = require("../../utils/blobId");
const { lookupByBlobDecimal } = require("../../indexer/store");

// Finds a blob's Sui object in indexer/blob_index.json, the snapshot of
// BlobCertified events that `npm run index` builds. No API key needed.
// `findRow` can be replaced, for example by a test.
function localIndexLookup({ findRow = lookupByBlobDecimal } = {}) {
  return {
    name: "local index",
    async findBlob(blobId, network) {
      const row = findRow(blobBase64ToDecimal(blobId));
      if (!row) {
        const err = new Error("Blob id not found in local Walrus index");
        err.status = 404;
        throw err;
      }

      return {
        network,
        objectId: row.object_id,
        txDigest: row.tx_digest,
        details: {
          // start_epoch and end_epoch come from the BlobCertified event: the
          // epoch the blob was certified in, and its storage end at that time.
          summary: {
            certifiedEpoch: row.start_epoch,
            endEpoch: row.end_epoch,
            deletable: row.deletable,
            txDigest: row.tx_digest,
          },
        },
      };
    },
  };
}

module.exports = { localIndexLookup };
