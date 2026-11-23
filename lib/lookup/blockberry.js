const fetch = require("node-fetch");

async function getBlob(blockberry, blobId, net = "mainnet") {
  if (!blockberry.apiKey) {
    throw new Error(
      "Missing BLOCKBERRY_API_KEY env value for Blockberry access"
    );
  }

  const base =
    net === "testnet"
      ? blockberry.testnet
      : blockberry.mainnet;
  const url = `${base}/blobs/${encodeURIComponent(blobId)}`;

  const res = await fetch(url, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${blockberry.apiKey}`,
      "x-api-key": blockberry.apiKey,
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

function found(network, objectId, blob) {
  return {
    network,
    objectId,
    txDigest: null,
    details: { sources: { blockberry: blob } },
  };
}

// Finds a blob's Sui object through the Blockberry API at request time. Needs
// BLOCKBERRY_API_KEY. When the blob is not found on the requested network,
// the other network is tried.
function blockberryLookup(config) {
  return {
    name: "Blockberry API",
    async findBlob(blobId, network) {
      try {
        const { blob, objectId } = await getBlob(config.blockberry, blobId, network);
        return found(network, objectId, blob);
      } catch (err) {
        console.warn(
          `[WARN] Blockberry lookup failed on ${network}, retrying other net if possible:`,
          err.message || err
        );
      }

      const otherNetwork = network === "mainnet" ? "testnet" : "mainnet";
      try {
        const { blob, objectId } = await getBlob(
          config.blockberry,
          blobId,
          otherNetwork
        );
        return found(otherNetwork, objectId, blob);
      } catch (err) {
        const notFound = new Error(
          err.message || "Could not fetch blob/object from Blockberry"
        );
        notFound.status = 404;
        throw notFound;
      }
    },
  };
}

module.exports = { blockberryLookup };
