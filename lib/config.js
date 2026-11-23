// Settings shared by both servers, read from the environment. The entry
// points load .env before calling readConfig().

function withoutTrailingSlash(url) {
  return url ? url.replace(/\/$/, "") : null;
}

function readConfig(env = process.env) {
  return {
    port: env.PORT || 3001,
    walrus: {
      mainnet: withoutTrailingSlash(env.WALRUS_MAINNET_URL || ""),
      testnet: withoutTrailingSlash(
        env.WALRUS_TESTNET_URL || env.WALRUS_BASE_URL || ""
      ),
    },
    suiRpc: {
      mainnet:
        env.SUI_MAINNET_RPC_URL ||
        env.SUI_RPC_MAINNET ||
        "https://fullnode.mainnet.sui.io:443",
      testnet:
        env.SUI_TESTNET_RPC_URL ||
        env.SUI_RPC_TESTNET ||
        "https://fullnode.testnet.sui.io:443",
    },
    blockberry: {
      apiKey: env.BLOCKBERRY_API_KEY || "",
      mainnet:
        env.BLOCKBERRY_WALRUS_MAINNET_BASE ||
        env.BLOCKBERRY_WALRUS_BASE ||
        "https://api.blockberry.one/walrus-mainnet/v1",
      testnet:
        env.BLOCKBERRY_WALRUS_TESTNET_BASE ||
        "https://api.blockberry.one/walrus-testnet/v1",
    },
  };
}

module.exports = { readConfig };
