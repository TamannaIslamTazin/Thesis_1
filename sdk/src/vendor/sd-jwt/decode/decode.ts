/**
 * VENDORED from @sd-jwt/decode@0.19.0 — src/decode.ts
 *
 * Apache-2.0. Copyright the sd-jwt-js authors. See ../LICENSE and ../NOTICE.
 * Upstream: https://github.com/openwallet-foundation/sd-jwt-js
 *
 * MODIFICATION NOTICE (Apache-2.0 §4(b)): CHANGED by BDHealthTrust — see divergences D3 (RFC 9807 §7.3: unmatched
 *   disclosures are rejected) and D6 (import paths) in ../NOTICE.
 */
import type { HasherAndAlgSync, HasherSync } from '../types';
import {
  type Hasher,
  type HasherAndAlg,
  SD_DIGEST,
  SD_LIST_KEY,
  SD_SEPARATOR,
} from '../types';
// BDHT DIVERGENCE D3: `SdJwtDisclosureError` added to this import.
import {
  base64urlDecode,
  Disclosure,
  SdJwtDisclosureError,
  SDJWTException,
} from '../utils';

export const decodeJwt = <
  H extends Record<string, unknown>,
  T extends Record<string, unknown>,
>(
  jwt: string,
): { header: H; payload: T; signature: string } => {
  const { 0: header, 1: payload, 2: signature, length } = jwt.split('.');
  if (length !== 3) {
    throw new SDJWTException('Invalid JWT as input');
  }

  return {
    header: JSON.parse(base64urlDecode(header)),
    payload: JSON.parse(base64urlDecode(payload)),
    signature: signature,
  };
};

// Split the sdjwt into 3 parts: jwt, disclosures and keybinding jwt. each part is base64url encoded
// It's separated by the ~ character
//
// If there is no keybinding jwt, the third part will be undefined
// If there are no disclosures, the second part will be an empty array
export const splitSdJwt = (
  sdjwt: string,
): { jwt: string; disclosures: string[]; kbJwt?: string } => {
  const [encodedJwt, ...encodedDisclosures] = sdjwt.split(SD_SEPARATOR);
  if (encodedDisclosures.length === 0) {
    // if input is just jwt, then return here.
    // This is for compatibility with jwt
    return {
      jwt: encodedJwt,
      disclosures: [],
    };
  }

  const encodedKeyBindingJwt = encodedDisclosures.pop();
  return {
    jwt: encodedJwt,
    disclosures: encodedDisclosures,
    kbJwt: encodedKeyBindingJwt || undefined,
  };
};

// Decode the sdjwt into the jwt, disclosures and keybinding jwt
// jwt, disclosures and keybinding jwt are also decoded
export const decodeSdJwt = async (
  sdjwt: string,
  hasher: Hasher,
): Promise<DecodedSDJwt> => {
  const [encodedJwt, ...encodedDisclosures] = sdjwt.split(SD_SEPARATOR);
  const jwt = decodeJwt(encodedJwt);

  if (encodedDisclosures.length === 0) {
    // if input is just jwt, then return here.
    // This is for compatibility with jwt
    return {
      jwt,
      disclosures: [],
    };
  }

  const encodedKeyBindingJwt = encodedDisclosures.pop();
  const kbJwt = encodedKeyBindingJwt
    ? decodeJwt(encodedKeyBindingJwt)
    : undefined;

  const { _sd_alg } = getSDAlgAndPayload(jwt.payload);

  const disclosures = await Promise.all(
    encodedDisclosures.map((ed) =>
      Disclosure.fromEncode(ed, { alg: _sd_alg, hasher }),
    ),
  );

  return {
    jwt,
    disclosures,
    kbJwt,
  };
};

export const decodeSdJwtSync = (
  sdjwt: string,
  hasher: HasherSync,
): DecodedSDJwt => {
  const [encodedJwt, ...encodedDisclosures] = sdjwt.split(SD_SEPARATOR);
  const jwt = decodeJwt(encodedJwt);

  if (encodedDisclosures.length === 0) {
    // if input is just jwt, then return here.
    // This is for compatibility with jwt
    return {
      jwt,
      disclosures: [],
    };
  }

  const encodedKeyBindingJwt = encodedDisclosures.pop();
  const kbJwt = encodedKeyBindingJwt
    ? decodeJwt(encodedKeyBindingJwt)
    : undefined;

  const { _sd_alg } = getSDAlgAndPayload(jwt.payload);

  const disclosures = encodedDisclosures.map((ed) =>
    Disclosure.fromEncodeSync(ed, { alg: _sd_alg, hasher }),
  );

  return {
    jwt,
    disclosures,
    kbJwt,
  };
};

// Get the claims from jwt and disclosures
// The digested values are matched with the disclosures and the claims are extracted
export const getClaims = async <T>(
  rawPayload: Record<string, unknown>,
  disclosures: Array<Disclosure>,
  hasher: Hasher,
): Promise<T> => {
  const { unpackedObj } = await unpack(rawPayload, disclosures, hasher);
  return unpackedObj as T;
};

export const getClaimsSync = <T>(
  rawPayload: Record<string, unknown>,
  disclosures: Array<Disclosure>,
  hasher: HasherSync,
): T => {
  const { unpackedObj } = unpackSync(rawPayload, disclosures, hasher);
  return unpackedObj as T;
};

const unpackArray = (
  arr: Array<unknown>,
  map: Record<string, Disclosure>,
  prefix = '',
): { unpackedObj: unknown; disclosureKeymap: Record<string, string> } => {
  const keys: Record<string, string> = {};
  const unpackedArray: unknown[] = [];
  arr.forEach((item, idx) => {
    if (typeof item === 'object' && item !== null) {
      const hash = (item as Record<string, string>)[SD_LIST_KEY];
      if (hash) {
        const disclosed = map[hash];
        if (disclosed) {
          const presentKey = prefix ? `${prefix}.${idx}` : `${idx}`;
          keys[presentKey] = hash;

          const { unpackedObj, disclosureKeymap: disclosureKeys } =
            unpackObjInternal(disclosed.value, map, presentKey);
          unpackedArray.push(unpackedObj);
          Object.assign(keys, disclosureKeys);
        }
      } else {
        const newKey = prefix ? `${prefix}.${idx}` : `${idx}`;
        const { unpackedObj, disclosureKeymap: disclosureKeys } =
          unpackObjInternal(item, map, newKey);
        unpackedArray.push(unpackedObj);
        Object.assign(keys, disclosureKeys);
      }
    } else {
      unpackedArray.push(item);
    }
  });
  return { unpackedObj: unpackedArray, disclosureKeymap: keys };
};

export const unpackObj = (obj: unknown, map: Record<string, Disclosure>) => {
  const copiedObj = JSON.parse(JSON.stringify(obj));
  return unpackObjInternal(copiedObj, map);
};

const unpackObjInternal = (
  obj: unknown,
  map: Record<string, Disclosure>,
  prefix = '',
): { unpackedObj: unknown; disclosureKeymap: Record<string, string> } => {
  const keys: Record<string, string> = {};
  if (typeof obj === 'object' && obj !== null) {
    if (Array.isArray(obj)) {
      return unpackArray(obj, map, prefix);
    }

    for (const key in obj) {
      if (
        key !== SD_DIGEST &&
        key !== SD_LIST_KEY &&
        typeof (obj as Record<string, unknown>)[key] === 'object'
      ) {
        const newKey = prefix ? `${prefix}.${key}` : key;
        const { unpackedObj, disclosureKeymap: disclosureKeys } =
          unpackObjInternal((obj as Record<string, unknown>)[key], map, newKey);
        (obj as Record<string, unknown>)[key] = unpackedObj;
        Object.assign(keys, disclosureKeys);
      }
    }

    const { _sd, ...payload } = obj as Record<string, unknown> & {
      _sd?: Array<string>;
    };
    const claims: Record<string, unknown> = {};
    if (_sd) {
      for (const hash of _sd) {
        const disclosed = map[hash];
        if (disclosed?.key) {
          const presentKey = prefix
            ? `${prefix}.${disclosed.key}`
            : disclosed.key;
          keys[presentKey] = hash;

          const { unpackedObj, disclosureKeymap: disclosureKeys } =
            unpackObjInternal(disclosed.value, map, presentKey);
          claims[disclosed.key] = unpackedObj;
          Object.assign(keys, disclosureKeys);
        }
      }
    }

    const unpackedObj = Object.assign(payload, claims);
    return { unpackedObj, disclosureKeymap: keys };
  }
  return { unpackedObj: obj, disclosureKeymap: keys };
};

// Creates a mapping of the digests of the disclosures to the actual disclosures
export const createHashMapping = async (
  disclosures: Array<Disclosure>,
  hash: HasherAndAlg,
) => {
  const map: Record<string, Disclosure> = {};
  for (let i = 0; i < disclosures.length; i++) {
    const disclosure = disclosures[i];
    const digest = await disclosure.digest(hash);
    map[digest] = disclosure;
  }
  return map;
};

export const createHashMappingSync = (
  disclosures: Array<Disclosure>,
  hash: HasherAndAlgSync,
) => {
  const map: Record<string, Disclosure> = {};
  for (let i = 0; i < disclosures.length; i++) {
    const disclosure = disclosures[i];
    const digest = disclosure.digestSync(hash);
    map[digest] = disclosure;
  }
  return map;
};

// Extract _sd_alg. If it is not present, it is assumed to be sha-256
export const getSDAlgAndPayload = (SdJwtPayload: Record<string, unknown>) => {
  const { _sd_alg, ...payload } = SdJwtPayload;
  if (typeof _sd_alg !== 'string') {
    // This is for compatibility
    return { _sd_alg: 'sha-256', payload };
  }
  return { _sd_alg, payload };
};

// ── BDHT DIVERGENCE D3 ──────────────────────────────────────────────────────
// RFC 9807 §7.3: a Verifier MUST reject a presentation carrying any Disclosure
// it cannot match to a digest in the signed payload. Upstream cannot do that,
// structurally: `unpackObj` is PAYLOAD-DRIVEN — it walks the payload's `_sd`
// arrays and `{"...": digest}` entries and looks each digest up in the map
// built from the wire. Nothing ever iterates the map to find entries that were
// never visited, so there is no code path on which an unmatched disclosure
// could raise anything. It is simply never reached, and verification succeeds.
//
// WHAT THAT COSTS. No claim can be FORGED — the digest is what makes forgery
// impossible, and a modified disclosure stops hashing to a committed digest.
// The problem is that tampering becomes UNDETECTABLE: flip one byte of a
// disclosure and the claim vanishes from the resolved claims while the artifact
// still verifies. A verifier cannot distinguish that from the holder having
// chosen to withhold the claim. "No allergy recorded", "no restriction on this
// licence", "no prior authorisation required" — verifier logic that reads an
// absent claim as a benign default is then reading an attacker-controlled
// value. The attacker cannot choose what a claim says, only which claims the
// verifier never sees, and the verifier's own defaulting supplies the rest.
// Measured against Credo 0.6.3 on this project's ledger; see
// CREDO-SECURITY-REPORT.md finding 3.
//
// THE CHECK. `unpackObj` already returns `disclosureKeymap`, whose VALUES are
// exactly the digests resolution consumed. Anything in the map and not in that
// set was carried on the wire and committed to by nobody. This is reachability-
// driven rather than commitment-driven, which is marginally stricter than
// collecting every `_sd` member from the payload: a disclosure whose digest is
// committed only inside a container disclosure that is itself unmatched is
// refused here. That is the correct reading of §7.3 — a commitment the verifier
// cannot reach is a commitment it has not seen.
//
// Decoys are unaffected: a decoy is a digest in `_sd` with no disclosure behind
// it, so it never enters the map.
//
// Unconditional, deliberately. There is no legitimate artifact this rejects. A
// holder narrowing a presentation removes disclosures — digests without
// disclosures, which resolution skips — and never the other way round.
// ────────────────────────────────────────────────────────────────────────────
const assertEveryDisclosureWasMatched = (
  map: Record<string, Disclosure>,
  disclosureKeymap: Record<string, string>,
): void => {
  const consumed = new Set(Object.values(disclosureKeymap));
  const unmatched = Object.keys(map).filter((digest) => !consumed.has(digest));
  if (unmatched.length > 0) {
    throw new SdJwtDisclosureError(
      `SD-JWT carries ${unmatched.length} disclosure(s) the issuer never committed to — it has been tampered with or disclosures have been injected (RFC 9807 §7.3)`,
      { unmatchedDigests: unmatched },
    );
  }
};
// ── END BDHT DIVERGENCE D3 ──────────────────────────────────────────────────

// Match the digests of the disclosures with the claims and extract the claims
// unpack function use unpackObjInternal and unpackArray to recursively unpack the claims
// Since getSDAlgAndPayload create new object So we don't need to clone it again
export const unpack = async (
  SdJwtPayload: Record<string, unknown>,
  disclosures: Array<Disclosure>,
  hasher: Hasher,
) => {
  const { _sd_alg, payload } = getSDAlgAndPayload(SdJwtPayload);
  const hash = { hasher, alg: _sd_alg };
  const map = await createHashMapping(disclosures, hash);

  // BDHT DIVERGENCE D3: upstream is `return unpackObj(payload, map);`
  const result = unpackObj(payload, map);
  assertEveryDisclosureWasMatched(map, result.disclosureKeymap);
  return result;
};

export const unpackSync = (
  SdJwtPayload: Record<string, unknown>,
  disclosures: Array<Disclosure>,
  hasher: HasherSync,
) => {
  const { _sd_alg, payload } = getSDAlgAndPayload(SdJwtPayload);
  const hash = { hasher, alg: _sd_alg };
  const map = createHashMappingSync(disclosures, hash);

  // BDHT DIVERGENCE D3: upstream is `return unpackObj(payload, map);`
  const result = unpackObj(payload, map);
  assertEveryDisclosureWasMatched(map, result.disclosureKeymap);
  return result;
};

// This is the type of the object that is returned by the decodeSdJwt function
// It is a combination of the decoded jwt, the disclosures and the keybinding jwt
export type DecodedSDJwt = {
  jwt: {
    header: Record<string, unknown>;
    payload: Record<string, unknown>; // raw payload of sd-jwt
    signature: string;
  };
  disclosures: Array<Disclosure>;
  kbJwt?: {
    header: Record<string, unknown>;
    payload: Record<string, unknown>;
    signature: string;
  };
};
