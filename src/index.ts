import {
  createSignature as createSignatureV1,
  verifySignature as verifySignatureV1
} from './15ms-v1-hmac-sha256/index.js';
import { EErrorId } from './error.js';
import { IAuthorization, ISignature } from './types.js';

async function createSignature({
  algorithm,
  credential,
  accessToken,
  resourceURI,
  contentHash
}: ISignature): Promise<string> {
  if (algorithm === '15ms-v1-hmac-sha256') {
    return createSignatureV1({
      credential,
      accessToken,
      resourceURI,
      contentHash
    });
  }
  throw new Error(EErrorId.AlgorithmNotSupported);
}

async function verifySignature({
  signature,
  algorithm,
  credential,
  accessToken,
  resourceURI,
  contentHash
}: ISignature & { signature: string; }): Promise<boolean> {
  if (algorithm === '15ms-v1-hmac-sha256') {
    return verifySignatureV1({
      signature,
      credential,
      accessToken,
      resourceURI,
      contentHash
    });
  }
  throw new Error(EErrorId.AlgorithmNotSupported);
}

function buildAuthorization({
  algorithm,
  credential,
  resourceURI,
  contentHash,
  signature
}: IAuthorization): string {
  const components = [
    `credential=${credential}`,
    `resource-uri=${resourceURI}`,
    contentHash && `content-hash=${contentHash}`,
    signature && `signature=${signature}`
  ].filter(Boolean);
  return `${algorithm} ${components.join(',')}`;
}

function parseAuthorization(authorization: string): IAuthorization {
  const [algorithm, othertext] = authorization.split(' ');
  const components = othertext.split(',').map(component => component.trim()).filter(Boolean);
  const parsedResult: IAuthorization = {
    algorithm,
    credential: '',
    resourceURI: '',
    contentHash: undefined,
    signature: ''
  };
  const componentKeyMap: { [key in string]: keyof Omit<IAuthorization, 'algorithm'>; } = {
    'credential': 'credential',
    'resource-uri': 'resourceURI',
    'content-hash': 'contentHash',
    'signature': 'signature'
  };
  components.forEach(component => {
    const [key, value] = component.split('=');
    parsedResult[componentKeyMap[key]] = value;
  });
  return parsedResult;
}

export default {
  createSignature,
  verifySignature,
  buildAuthorization,
  parseAuthorization
};
 