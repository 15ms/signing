type TSignatureAlgorithm = '15ms-v1-hmac-sha256' | string;

interface ISignature {
  algorithm: TSignatureAlgorithm;
  credential: string;
  accessToken: string;
  resourceURI: string;
  contentHash: string;
}

interface IAuthorization {
  algorithm: TSignatureAlgorithm;
  credential: string;
  resourceURI: string;
  contentHash?: string;
  signature: string;
}

export type {
  TSignatureAlgorithm,
  ISignature,
  IAuthorization
};
