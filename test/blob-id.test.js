const test = require("node:test");
const assert = require("node:assert/strict");
const { blobBase64ToDecimal } = require("../utils/blobId");
const { lookupByBlobDecimal } = require("../indexer/store");

// The first row of indexer/blob_index.json.
const BLOB_ID = "J0dXjua1JfGE2ahreGuKogDjRWwMeCZoe6rf1_DcbWU";
const BLOB_ID_DECIMAL =
  "45877708914288396699732353003371136192074038796906586215641510660375232071463";
const OBJECT_ID =
  "0x6084689b21f0611a074b2c66f01351ed143c306175a389424aad30898906e38f";

test("blobBase64ToDecimal turns a Walrus blob id into the index's decimal id", () => {
  assert.equal(blobBase64ToDecimal(BLOB_ID), BLOB_ID_DECIMAL);
});

test("blobBase64ToDecimal rejects an id that is not 32 bytes", () => {
  assert.throws(() => blobBase64ToDecimal("short"), /Expected 32 byte blob id/);
});

test("the local index finds the Sui object of a blob in the snapshot", () => {
  assert.equal(lookupByBlobDecimal(BLOB_ID_DECIMAL).object_id, OBJECT_ID);
  assert.equal(lookupByBlobDecimal("1"), null);
});
