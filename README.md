# @15ms/signing

A toolkit for 15ms services to create or verify message signing.

# Install

```bash
npm i @15ms/signing --save
```

# Usage

## create or verify message signing

```ts
import {
  createSignature,
  verifySignature
} from '@15ms/signing';

const signature: string = await createSignature({
  algorithm: '15ms-v1-hmac-sha256',
  accessToken: 'AccessToken', // getAccessTokenByCredential(YourCredential)
  resourceURI: 'ResourceURI', // such as /account/detail
  contentHash: 'ContentHash' // hex(md5(YourRequestBody))
});

const matched: boolean = await verifySignature({
  signature: 'YourSignature',
  algorithm: '15ms-v1-hmac-sha256',
  accessToken: 'AccessToken', // getAccessTokenByCredential(YourCredential)
  resourceURI: 'ResourceURI', // such as /account/detail
  contentHash: 'ContentHash' // hex(md5(YourRequestBody))
});
```

## build or parse authorization header

```ts
import {
  buildAuthorization,
  parseAuthorization,
  IAuthorization
} from '@15ms/signing';

const authorization: string = buildAuthorization({
  algorithm: '15ms-v1-hmac-sha256',
  credential: 'Credential', // AccountID or AccountID/SessionID
  resourceURI: 'ResourceURI', // such as /account/detail
  contentHash: 'ContentHash', // hex(md5(YourRequestBody))
  signature: 'Signature' // YourSignature
});

const {
  algorithm,
  credential,
  resourceURI,
  contentHash,
  signature
}: IAuthorization = parseAuthorization(authorization);
```
