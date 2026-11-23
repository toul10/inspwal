// The inspector, finding a blob's Sui object through the Blockberry API.
// Needs BLOCKBERRY_API_KEY in .env.
require("dotenv").config();

const { start } = require("./lib/app");
const { blockberryLookup } = require("./lib/lookup/blockberry");

start((config) => blockberryLookup(config));
