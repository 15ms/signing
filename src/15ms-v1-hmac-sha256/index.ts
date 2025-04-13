import { EErrorId } from '../error.js';
import { ISignature } from '../types.js';

function arrayBufferToHex(buffer: ArrayBuffer): string {
  const uint8s = new Uint8Array(buffer);
  const hexes = [];
  for (let i = 0; i < uint8s.length; i += 1) {
    const hex = uint8s[i].toString(16).padStart(2, '0');
    hexes.push(hex);
  }
  return hexes.join('');
}

async function signByWebCrypto(key: string, message: string): Promise<string> {
  const subtleCrypto = globalThis.crypto?.subtle;
  if (!subtleCrypto) {
    throw new Error(EErrorId.RuntimeNotSupported);
  }
  const encoder = new TextEncoder();
  const keyData = encoder.encode(key);
  const messageData = encoder.encode(message);
  const cryptoKey = await subtleCrypto.importKey('raw', keyData, { name: 'HMAC', hash: { name: 'SHA-256' } }, false, ['sign']);
  const signature = await subtleCrypto.sign('HMAC', cryptoKey, messageData);
  const signatureInHex = arrayBufferToHex(signature);
  return signatureInHex;
}

async function createSignature({
  credential,
  accessToken,
  resourceURI,
  contentHash
}: Omit<ISignature, 'algorithm'>): Promise<string> {
  const currentTime = Math.floor(Date.now() / 1000 / 60);
  const messageText = [
    credential,
    currentTime,
    resourceURI,
    contentHash
  ].filter(Boolean).join('|');
  return signByWebCrypto(accessToken, messageText);
}

async function verifySignature({
  signature,
  credential,
  accessToken,
  resourceURI,
  contentHash
}: Omit<ISignature, 'algorithm'> & { signature: string; }): Promise<boolean> {
  const timeSlice0 = Math.floor(Date.now() / 1000 / 60);
  const timeSlices = [timeSlice0, timeSlice0 - 1];
  for (const timeSlice of timeSlices) {
    const messageText = [
      credential,
      timeSlice,
      resourceURI,
      contentHash
    ].filter(Boolean).join('|');
    const expectedValue = await signByWebCrypto(accessToken, messageText);
    if (signature === expectedValue) {
      return true;
    }
  }
  return false;
}

export {
  createSignature,
  verifySignature
};
