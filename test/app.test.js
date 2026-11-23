const { test, before, after, mock } = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const { EncryptedObject } = require("@mysten/seal");
const { createApp } = require("../lib/app");
const { readConfig } = require("../lib/config");
const { localIndexLookup } = require("../lib/lookup/local-index");
const { blockberryLookup } = require("../lib/lookup/blockberry");
const { blobBase64ToDecimal } = require("../utils/blobId");

// One local server stands in for the Walrus aggregator, the Sui fullnodes and
// Blockberry, so the tests need no network and no keys.
const address = (digit) => "0x" + digit.repeat(64);
const PNG = Buffer.concat([
  Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
  Buffer.alloc(200, 1),
]);
const JSON_BLOB = Buffer.from(JSON.stringify({ hello: "walrus" }));
const SEAL = Buffer.from(
  EncryptedObject.serialize({
    version: 0,
    packageId: address("1"),
    id: "cafe",
    services: [[address("2"), 1]],
    threshold: 1,
    encryptedShares: {
      BonehFranklinBLS12381: {
        nonce: Array(96).fill(7),
        encryptedShares: [Array(32).fill(1)],
        encryptedRandomness: Array(32).fill(3),
      },
    },
    ciphertext: { Aes256Gcm: { blob: Array(64).fill(9), aad: null } },
  }).toBytes()
);
const BLOBS = {
  png: ["image/png", PNG],
  json: ["application/json", JSON_BLOB],
  seal: ["application/octet-stream", SEAL],
};
const OBJECTS = { "0xpng": "png" };
const BLOCKBERRY = {
  "only-on-testnet": { "bb-testnet": { objectId: "0xfrom-blockberry" } },
};

// Two blobs in a fake local index.
const INDEXED = Buffer.alloc(32, 7).toString("base64url");
const BROKEN = Buffer.alloc(32, 9).toString("base64url");
const INDEX_ROWS = {
  [blobBase64ToDecimal(INDEXED)]: {
    object_id: "0xindexed",
    tx_digest: "certifying-tx",
    start_epoch: 18,
    end_epoch: 55,
    deletable: true,
  },
  [blobBase64ToDecimal(BROKEN)]: {
    object_id: "0xbroken",
    tx_digest: "some-tx",
    start_epoch: 1,
    end_epoch: 2,
    deletable: false,
  },
};

const upstreamCalls = [];

function upstream(req, res) {
  let body = "";
  req.on("data", (chunk) => (body += chunk));
  req.on("end", () => {
    const url = new URL(req.url, "http://upstream");
    upstreamCalls.push({ path: url.pathname, headers: req.headers });
    const [service, ...rest] = url.pathname
      .split("/")
      .filter(Boolean)
      .map(decodeURIComponent);
    if (service === "walrus") return walrus(rest, res);
    if (service.startsWith("sui-")) return sui(JSON.parse(body), res, service);
    if (service.startsWith("bb-")) return blockberry(rest, res, service);
    res.writeHead(500).end("unexpected upstream path");
  });
}

function walrus(rest, res) {
  // /v1/blobs/<id> or /v1/blobs/by-object-id/<object id>
  const key = rest[2] === "by-object-id" ? OBJECTS[rest[3]] : rest[2];
  const blob = BLOBS[key];
  if (!blob) {
    return res.writeHead(404, { "content-type": "text/plain" }).end("BLOB_NOT_FOUND");
  }
  const [type, bytes] = blob;
  res.writeHead(200, { "content-type": type, "content-length": bytes.length }).end(bytes);
}

function sui({ id, method, params }, res, service) {
  const reply = (payload) =>
    res
      .writeHead(200, { "content-type": "application/json" })
      .end(JSON.stringify({ jsonrpc: "2.0", id, ...payload }));
  const [first] = params;
  if (method === "sui_getObject") {
    if (first === "0xbroken") return reply({ error: { code: -32000, message: "boom" } });
    return reply({
      result: {
        data: { objectId: first, previousTransaction: `latest-tx-of-${first}`, served: service },
      },
    });
  }
  if (method === "sui_getTransactionBlock") {
    return reply({ result: { digest: first, served: service } });
  }
  reply({ error: { code: -32601, message: "Method not found" } });
}

function blockberry(rest, res, service) {
  // /blobs/<blob id>
  const found = (BLOCKBERRY[rest[1]] || {})[service];
  if (!found) return res.writeHead(404, { "content-type": "text/plain" }).end("not found");
  res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ data: found }));
}

const servers = [];
const inspectors = {};

async function listen(handler) {
  const server = http.createServer(handler);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { server, url: `http://127.0.0.1:${server.address().port}` };
}

async function close(server) {
  server.closeAllConnections();
  await new Promise((resolve) => server.close(resolve));
}

async function get(inspector, path) {
  const res = await fetch(inspectors[inspector] + path);
  const type = res.headers.get("content-type") || "";
  const body = type.includes("json")
    ? await res.json()
    : Buffer.from(await res.arrayBuffer());
  return { status: res.status, type, body };
}

before(async () => {
  for (const level of ["log", "warn", "error"]) mock.method(console, level, () => {});

  const up = await listen(upstream);
  servers.push(up.server);
  const config = readConfig({
    WALRUS_MAINNET_URL: `${up.url}/walrus`,
    WALRUS_TESTNET_URL: `${up.url}/walrus`,
    SUI_RPC_MAINNET: `${up.url}/sui-mainnet`,
    SUI_RPC_TESTNET: `${up.url}/sui-testnet`,
    BLOCKBERRY_API_KEY: "test-key",
    BLOCKBERRY_WALRUS_MAINNET_BASE: `${up.url}/bb-mainnet`,
    BLOCKBERRY_WALRUS_TESTNET_BASE: `${up.url}/bb-testnet`,
  });

  // An aggregator address with nothing listening on it.
  const gone = await listen(() => {});
  await close(gone.server);

  const local = localIndexLookup({ findRow: (decimal) => INDEX_ROWS[decimal] || null });
  const apps = {
    local: createApp({ config, lookup: local }),
    blockberry: createApp({ config, lookup: blockberryLookup(config) }),
    unreachable: createApp({
      config: { ...config, walrus: { mainnet: gone.url, testnet: gone.url } },
      lookup: local,
    }),
  };
  for (const [name, app] of Object.entries(apps)) {
    const inspector = await listen(app);
    servers.push(inspector.server);
    inspectors[name] = inspector.url;
  }
});

after(async () => {
  for (const server of servers) await close(server);
  mock.restoreAll();
});

test("/health says which lookup the server uses", async () => {
  const { status, body } = await get("local", "/health");
  assert.equal(status, 200);
  assert.equal(body.ok, true);
  assert.equal(body.lookup, "local index");
  assert.equal((await get("blockberry", "/health")).body.lookup, "Blockberry API");
});

test("/inspect needs a blob id", async () => {
  const { status, body } = await get("local", "/inspect");
  assert.equal(status, 400);
  assert.equal(body.error, "Missing id query parameter");
});

test("/inspect classifies an image and links it through /raw", async () => {
  const { status, body } = await get("local", "/inspect?id=png&net=mainnet");
  assert.equal(status, 200);
  assert.equal(body.format, "png");
  assert.equal(body.encryptionGuess.classification, "media-image");
  assert.equal(body.mediaUrl, "/raw?net=mainnet&id=png");
  assert.equal(body.sizeBytes, PNG.length);
});

test("/inspect previews JSON as text", async () => {
  const { body } = await get("local", "/inspect?id=json&net=mainnet");
  assert.equal(body.encryptionGuess.classification, "text-json");
  assert.equal(body.preview, JSON_BLOB.toString());
});

test("/inspect reports a Seal-encrypted blob", async () => {
  const { body } = await get("local", "/inspect?id=seal&net=mainnet");
  assert.equal(body.hasSeal, true);
  assert.equal(body.sealMeta.threshold, 1);
});

test("/inspect marks a blob Walrus does not know as absent", async () => {
  const { status, body } = await get("local", "/inspect?id=missing&net=mainnet");
  assert.equal(status, 404);
  assert.equal(body.availability, "absent");
  assert.equal(body.existsOnWalrus, false);
});

test("/inspect answers with JSON when the aggregator cannot be reached", async () => {
  const { status, type, body } = await get("unreachable", "/inspect?id=png&net=mainnet");
  assert.equal(status, 500);
  assert.match(type, /application\/json/);
  assert.equal(body.availability, "unknown");
  assert.equal(body.hasSeal, false);
  assert.equal(body.sealMeta, null);
  assert.match(body.error, /ECONNREFUSED/);
});

test("/inspect-object fetches the blob by its Sui object id", async () => {
  const { status, body } = await get("local", "/inspect-object?objectId=0xpng&net=mainnet");
  assert.equal(status, 200);
  assert.equal(body.objectId, "0xpng");
  assert.equal(body.format, "png");
  assert.ok(upstreamCalls.some((c) => c.path === "/walrus/v1/blobs/by-object-id/0xpng"));
});

test("/raw passes the blob bytes and content type through", async () => {
  const { status, type, body } = await get("local", "/raw?id=png&net=mainnet");
  assert.equal(status, 200);
  assert.equal(type, "image/png");
  assert.deepEqual(body, PNG);
});

test("/sui-from-blob with the local index returns the object, its certifying transaction and the index epochs", async () => {
  const { status, body } = await get("local", `/sui-from-blob?id=${INDEXED}&net=mainnet`);
  assert.equal(status, 200);
  assert.equal(body.objectId, "0xindexed");
  assert.deepEqual(body.summary, {
    certifiedEpoch: 18,
    endEpoch: 55,
    deletable: true,
    txDigest: "certifying-tx",
  });
  assert.equal(body.suiObject.data.objectId, "0xindexed");
  assert.equal(body.suiTransaction.digest, "certifying-tx");
  assert.equal(body.suiTransaction.served, "sui-mainnet");
});

test("/sui-from-blob answers 404 for a blob that is not in the index", async () => {
  const other = Buffer.alloc(32, 8).toString("base64url");
  const { status, body } = await get("local", `/sui-from-blob?id=${other}&net=mainnet`);
  assert.equal(status, 404);
  assert.deepEqual(body, {
    ok: false,
    network: "mainnet",
    blobId: other,
    error: "Blob id not found in local Walrus index",
  });
});

test("/sui-from-blob passes a Sui RPC error on", async () => {
  const { status, body } = await get("local", `/sui-from-blob?id=${BROKEN}&net=mainnet`);
  assert.equal(status, 500);
  assert.equal(body.ok, false);
  assert.match(body.error, /Sui RPC returned error -32000: boom/);
});

test("/sui-from-blob with Blockberry tries the other network and shows the object's latest transaction", async () => {
  const { status, body } = await get("blockberry", "/sui-from-blob?id=only-on-testnet&net=mainnet");
  assert.equal(status, 200);
  assert.equal(body.network, "testnet");
  assert.equal(body.objectId, "0xfrom-blockberry");
  assert.deepEqual(body.sources, { blockberry: { objectId: "0xfrom-blockberry" } });
  assert.equal(body.suiObject.data.served, "sui-testnet");
  assert.equal(body.suiTransaction.digest, "latest-tx-of-0xfrom-blockberry");
  const call = upstreamCalls.find((c) => c.path === "/bb-testnet/blobs/only-on-testnet");
  assert.equal(call.headers["x-api-key"], "test-key");
});

test("the Blockberry lookup needs an API key", async () => {
  const lookup = blockberryLookup(readConfig({}));
  await assert.rejects(
    lookup.findBlob("any", "mainnet"),
    (err) => err.status === 404 && /BLOCKBERRY_API_KEY/.test(err.message)
  );
});
