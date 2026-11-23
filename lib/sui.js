const fetch = require("node-fetch");

// What the inspector asks a Sui fullnode for.
const OBJECT_OPTIONS = {
  showType: true,
  showOwner: true,
  showPreviousTransaction: true,
  showContent: true,
  showDisplay: false,
  showStorageRebate: true,
};

const TRANSACTION_OPTIONS = {
  showInput: true,
  showEffects: true,
  showEvents: true,
  showObjectChanges: true,
  showBalanceChanges: true,
};

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

function rpcUrlFor(config, network) {
  return network === "testnet" ? config.suiRpc.testnet : config.suiRpc.mainnet;
}

// Fetches a blob's Sui object and one transaction to show with it: the
// certifying transaction when the lookup knows it, otherwise the object's
// latest transaction.
async function getObjectAndTransaction(rpcUrl, objectId, txDigest) {
  if (txDigest) {
    const [suiObject, suiTransaction] = await Promise.all([
      callSuiRpc(rpcUrl, "sui_getObject", [objectId, OBJECT_OPTIONS]),
      callSuiRpc(rpcUrl, "sui_getTransactionBlock", [
        txDigest,
        TRANSACTION_OPTIONS,
      ]),
    ]);
    return { suiObject, suiTransaction };
  }

  const suiObject = await callSuiRpc(rpcUrl, "sui_getObject", [
    objectId,
    OBJECT_OPTIONS,
  ]);
  const previousTx =
    suiObject && suiObject.data ? suiObject.data.previousTransaction : null;
  const suiTransaction = previousTx
    ? await callSuiRpc(rpcUrl, "sui_getTransactionBlock", [
        previousTx,
        TRANSACTION_OPTIONS,
      ])
    : null;
  return { suiObject, suiTransaction };
}

module.exports = { callSuiRpc, rpcUrlFor, getObjectAndTransaction };
