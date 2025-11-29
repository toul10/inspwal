# inspwal
Inspector for Walrus blobs and Sui objects that shows reachability, hashes, basic content guesses, Seal encryption status and related Sui object and transaction data.

Walrus Blob Inspector for Sui

inspwal is a tiny web app that lets you paste a Walrus blob id or Sui object id and see

1) Whether the blob exists on Walrus and on which network  
2) Basic content classification and hashes  
3) A short preview when the content is not protected with Seal  
4) Seal detection using the official Seal SDK  
5) The related Sui `blob::Blob` object and the certifying transaction

The front end is a single static page. The back end is a small Express server that talks to Walrus aggregators and to Sui fullnodes plus a helper service that resolves blob id to Sui object id.

## Features

1) Walrus reachability check  
   The server queries the configured Walrus aggregator and returns status, mime type, size, headers and a link to the original Walrus URL.

2) Content fingerprint  
   The inspector computes SHA256, SHA512, BLAKE2b512, SHA1 and MD5 hashes along with a short sample of the first bytes.

3) Content classification  
   The server tries to recognise common formats using magic bytes and mime type.  
   It separates media content, known binary formats, generic binary content and text.  
   For text it builds a short preview and a summary that includes printable ratio, number of lines and a quick JSON check.

4) Seal detection  
   The server uses `EncryptedObject.parse` from `@mysten/seal-sdk` to recognise Seal ciphertexts.  
   If parsing succeeds, the response includes `hasSeal` and a small `sealMeta` object with id, threshold and services.  
   When Seal is detected the front end never renders a preview even if the bytes look like media or text.  
   The UI shows a clear badge that the blob is protected by Seal.

5) Sui integration  
   The helper service takes a Walrus blob id, resolves it to the Sui `blob::Blob` object and then calls Sui JSON RPC to fetch  
   the object and the creation transaction.  
   The UI shows owner, type, storage rebate, gas usage, event count and object changes along with raw JSON.  
   Extra Walrus specific fields from the object content are also shown, such as encoding type, registered and storage epochs and blob type.
