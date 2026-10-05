declare module 'multiformats/bases/base58' {
  export const base58btc: {
    encode: (bytes: Uint8Array) => string;
    decode: (str: string) => Uint8Array;
    name: string;
    prefix: string;
  };
}
