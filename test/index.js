import assert from 'assert';

import signing from '../build/index.js';

describe('@15ms/signing', function () {
  this.timeout(75 * 1000);

  const accessTokens = {
    'test-a': 'test-a-secret',
    'test-b': 'test-b-secret'
  };

  it('create and verify signature', async () => {
    const signature = await signing.createSignature({
      algorithm: '15ms-v1-hmac-sha256',
      credential: 'test-a',
      accessToken: accessTokens['test-a'],
      resourceURI: '/',
      contentHash: ''
    });
    const matchedA = await signing.verifySignature({
      algorithm: '15ms-v1-hmac-sha256',
      credential: 'test-a',
      accessToken: accessTokens['test-a'],
      resourceURI: '/',
      contentHash: '',
      signature
    });
    const matchedB = await signing.verifySignature({
      algorithm: '15ms-v1-hmac-sha256',
      credential: 'test-b',
      accessToken: accessTokens['test-b'],
      resourceURI: '/',
      contentHash: '',
      signature
    });
    await new Promise(resolve => setTimeout(resolve, 60 * 1000));
    const matchedAAfter60s = await signing.verifySignature({
      algorithm: '15ms-v1-hmac-sha256',
      credential: 'test-a',
      accessToken: accessTokens['test-a'],
      resourceURI: '/',
      contentHash: '',
      signature
    });
    assert.deepEqual(matchedA, true);
    assert.deepEqual(matchedAAfter60s, true);
    assert.deepEqual(matchedB, false);
  });

  it('build and parse authorization', () => {
    const authorization = signing.buildAuthorization({
      algorithm: '15ms-v1-hmac-sha256',
      credential: 'Credential',
      resourceURI: '/',
      contentHash: 'abc',
      signature: 'Signature'
    });
    const {
      algorithm,
      credential,
      resourceURI,
      contentHash,
      signature
    } = signing.parseAuthorization(authorization);
    assert.deepEqual(algorithm, '15ms-v1-hmac-sha256');
    assert.deepEqual(credential, 'Credential');
    assert.deepEqual(resourceURI, '/');
    assert.deepEqual(contentHash, 'abc');
    assert.deepEqual(signature, 'Signature');
  });
});