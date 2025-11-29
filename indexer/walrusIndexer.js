const fetch = require("node-fetch");
const { blobBase64ToDecimal } = require("../utils/blobId");

const SUI_RPC =
  process.env.SUI_RPC ||
  process.env.SUI_MAINNET_RPC_URL ||
  "https://fullnode.mainnet.sui.io";

const BLOB_CERT_EVENT =
  "0xfdc88f7d7cf30afab2f82e8380d11ee8f70efb90e863d1de8616fae1bb09ea77::events::BlobCertified";

async function queryEvents(cursor) {
  const body = {
    jsonrpc: "2.0",
    id: 1,
    method: "suix_queryEvents",
    params: [{ MoveEventType: BLOB_CERT_EVENT }, cursor || null, 100, true],
  };

  const resp = await fetch(SUI_RPC, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const json = await resp.json();
  if (json.error) {
    throw new Error("RPC error " + JSON.stringify(json.error));
  }
  return json.result;
}

async function runIndexOnce(saveRow) {
  let cursor = null;
  while (true) {
    const res = await queryEvents(cursor);
    const events = res.data || [];

    for (const ev of events) {
      const pj = ev.parsedJson || {};
      const blobIdDecimal = pj.blob_id;
      const objectId = pj.object_id;
      const startEpoch = pj.epoch;
      const endEpoch = pj.end_epoch;
      const deletable = pj.deletable;
      const txDigest = ev.id && ev.id.txDigest;

      await saveRow({
        blob_id_decimal: blobIdDecimal,
        object_id: objectId,
        start_epoch: startEpoch,
        end_epoch: endEpoch,
        deletable,
        tx_digest: txDigest,
      });
    }

    if (!res.hasNextPage) break;
    cursor = res.nextCursor;
  }
}

module.exports = { runIndexOnce, queryEvents };
