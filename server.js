// The inspector, finding a blob's Sui object in the local index
// (indexer/blob_index.json). No API key needed.
require("dotenv").config();

const { start } = require("./lib/app");
const { localIndexLookup } = require("./lib/lookup/local-index");

start(() => localIndexLookup());
