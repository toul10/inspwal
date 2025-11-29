# inspwal
Inspector for Walrus blobs ID that shows reachability, hashes, basic content guesses, Seal encryption status and related Sui object and transaction data.

Walrus Blob Inspector for Sui

inspwal is a tiny web app that lets you paste a Walrus blob id or Sui object id and see

1) Whether the blob exists on Walrus and on which network  
2) Basic content classification and hashes  
3) A short preview when the content is not protected with Seal  
4) Seal detection using the official Seal SDK  
5) The related Sui `blob::Blob` object and the certifying transaction

The front end is a single static page. The back end is a small Express server that talks to Walrus aggregators and to Sui fullnodes plus a helper service that resolves blob id to Sui object id.




Back end and Blockberry integration



There are two Node back ends in this repo. Both take a Walrus blob id as input.

server-Blockberry.js (main server)

This is the main inspector server used in production. It:

serves the front end from public

queries Walrus aggregators

calls Blockberry for extra Walrus and Sui data when needed

You need a Blockberry API key for this server.

Create an account and get an API key from
https://api.blockberry.one/

Create a .env file in the project root (or update your existing one) and add:

BLOCKBERRY_API_KEY="your key"

PORT=3001
PORT2=3002

BLOCKBERRY_WALRUS_MAINNET_BASE=https://api.blockberry.one/walrus-mainnet/v1
BLOCKBERRY_WALRUS_TESTNET_BASE=https://api.blockberry.one/walrus-testnet/v1


WALRUS_BASE_URL=http://127.0.0.1:9001
WALRUS_TESTNET_URL=https://aggregator.walrus-testnet.walrus.space
WALRUS_MAINNET_URL=https://aggregator.walrus-mainnet.walrus.space
SUI_RPC_TESTNET=https://fullnode.testnet.sui.io:443
SUI_RPC_MAINNET=https://fullnode.mainnet.sui.io:443



Start the server:

node server-Blockberry.js



The inspector will then be available on the configured PORT value, default 3001.




server.js and the local indexer

The second server uses a local index file instead of calling Blockberry at request time.

The indexer script lives at:

indexer/run.js

It calls Blockberry once, downloads blob information and writes:

indexer/blob_index.json

This file contains mappings from blob_id_decimal to object_id, for example:

{
  "12345678901234567890": "0xabc123...",
  "98765432109876543210": "0xdef456..."
}


To build or refresh the index:

node indexer/run.js


After blob_index.json exists, you can run the lightweight server:

node server.js


Trus reachability, content fingerprints and classification, Seal status and the related Sui object and transaction data.   
