/**
 * VENDORED from @sd-jwt/core@0.19.0 — src/sdjwt.ts
 *
 * Apache-2.0. Copyright the sd-jwt-js authors. See ../LICENSE and ../NOTICE.
 * Upstream: https://github.com/openwallet-foundation/sd-jwt-js
 *
 * MODIFICATION NOTICE (Apache-2.0 §4(b)): CHANGED by BDHealthTrust — see divergences D2 (an unsatisfiable disclosure
 *   frame now throws instead of leaking) and D6 (import paths) in ../NOTICE.
 */
import { createHashMapping, getSDAlgAndPayload, unpack } from '../decode';
import { transformPresentationFrame } from '../present';
import {
  type DisclosureFrame,
  type Hasher,
  type HasherAndAlg,
  type kbHeader,
  type kbPayload,
  type PresentationFrame,
  type SaltGenerator,
  SD_DECOY,
  SD_DIGEST,
  SD_LIST_KEY,
  SD_SEPARATOR,
  type SDJWTCompact,
} from '../types';
// BDHT DIVERGENCE D2: `SdJwtFrameError` added to this import.
import { Disclosure, SDJWTException, SdJwtFrameError } from '../utils';
import { createDecoy } from './decoy';
import { Jwt } from './jwt';
import { KBJwt } from './kbjwt';

export type SDJwtData<
  Header extends Record<string, unknown>,
  Payload extends Record<string, unknown>,
  KBHeader extends kbHeader = kbHeader,
  KBPayload extends kbPayload = kbPayload,
> = {
  jwt?: Jwt<Header, Payload>;
  disclosures?: Array<Disclosure>;
  kbJwt?: KBJwt<KBHeader, KBPayload>;
};

export class SDJwt<
  Header extends Record<string, unknown> = Record<string, unknown>,
  Payload extends Record<string, unknown> = Record<string, unknown>,
  KBHeader extends kbHeader = kbHeader,
  KBPayload extends kbPayload = kbPayload,
> {
  public jwt?: Jwt<Header, Payload>;
  public disclosures?: Array<Disclosure>;
  public kbJwt?: KBJwt<KBHeader, KBPayload>;

  constructor(data?: SDJwtData<Header, Payload, KBHeader, KBPayload>) {
    this.jwt = data?.jwt;
    this.disclosures = data?.disclosures;
    this.kbJwt = data?.kbJwt;
  }

  public static async decodeSDJwt<
    Header extends Record<string, unknown> = Record<string, unknown>,
    Payload extends Record<string, unknown> = Record<string, unknown>,
    KBHeader extends kbHeader = kbHeader,
    KBPayload extends kbPayload = kbPayload,
  >(
    sdjwt: SDJWTCompact,
    hasher: Hasher,
  ): Promise<{
    jwt: Jwt<Header, Payload>;
    disclosures: Array<Disclosure>;
    kbJwt?: KBJwt<KBHeader, KBPayload>;
  }> {
    const [encodedJwt, ...encodedDisclosures] = sdjwt.split(SD_SEPARATOR);
    const jwt = Jwt.fromEncode<Header, Payload>(encodedJwt);

    if (!jwt.payload) {
      throw new Error('Payload is undefined on the JWT. Invalid state reached');
    }

    if (encodedDisclosures.length === 0) {
      return {
        jwt,
        disclosures: [],
      };
    }

    const encodedKeyBindingJwt = encodedDisclosures.pop();
    const kbJwt = encodedKeyBindingJwt
      ? KBJwt.fromKBEncode<KBHeader, KBPayload>(encodedKeyBindingJwt)
      : undefined;

    const { _sd_alg } = getSDAlgAndPayload(jwt.payload);

    const disclosures = await Promise.all(
      (encodedDisclosures as Array<string>).map((ed) =>
        Disclosure.fromEncode(ed, { alg: _sd_alg, hasher }),
      ),
    );

    return {
      jwt,
      disclosures,
      kbJwt,
    };
  }

  public static async extractJwt<
    Header extends Record<string, unknown> = Record<string, unknown>,
    Payload extends Record<string, unknown> = Record<string, unknown>,
  >(encodedSdJwt: SDJWTCompact): Promise<Jwt<Header, Payload>> {
    const [encodedJwt, ..._encodedDisclosures] =
      encodedSdJwt.split(SD_SEPARATOR);

    return Jwt.fromEncode(encodedJwt);
  }

  public static async fromEncode<
    Header extends Record<string, unknown> = Record<string, unknown>,
    Payload extends Record<string, unknown> = Record<string, unknown>,
    KBHeader extends kbHeader = kbHeader,
    KBPayload extends kbPayload = kbPayload,
  >(
    encodedSdJwt: SDJWTCompact,
    hasher: Hasher,
  ): Promise<SDJwt<Header, Payload>> {
    const { jwt, disclosures, kbJwt } = await SDJwt.decodeSDJwt<
      Header,
      Payload,
      KBHeader,
      KBPayload
    >(encodedSdJwt, hasher);

    return new SDJwt<Header, Payload, KBHeader, KBPayload>({
      jwt,
      disclosures,
      kbJwt,
    });
  }

  public async present<T extends Record<string, unknown>>(
    presentFrame: PresentationFrame<T> | undefined,
    hasher: Hasher,
  ): Promise<SDJWTCompact> {
    const disclosures = await this.getPresentDisclosures(presentFrame, hasher);
    const presentSDJwt = new SDJwt({
      jwt: this.jwt,
      disclosures,
      kbJwt: this.kbJwt,
    });
    return presentSDJwt.encodeSDJwt();
  }

  public async getPresentDisclosures<T extends Record<string, unknown>>(
    presentFrame: PresentationFrame<T> | undefined,
    hasher: Hasher,
  ): Promise<Disclosure<unknown>[]> {
    if (!this.jwt?.payload || !this.disclosures) {
      throw new SDJWTException('Invalid sd-jwt: jwt or disclosures is missing');
    }
    const { _sd_alg: alg } = getSDAlgAndPayload(this.jwt.payload);
    const hash = { alg, hasher };
    const hashmap = await createHashMapping(this.disclosures, hash);
    const { disclosureKeymap } = await unpack(
      this.jwt.payload,
      this.disclosures,
      hasher,
    );

    const keys = presentFrame
      ? transformPresentationFrame(presentFrame)
      : await this.presentableKeys(hasher);
    const disclosures = keys
      .map((k) => hashmap[disclosureKeymap[k]])
      .filter((d) => d !== undefined);
    return disclosures;
  }

  public encodeSDJwt(): SDJWTCompact {
    const data: string[] = [];

    if (!this.jwt) {
      throw new SDJWTException('Invalid sd-jwt: jwt is missing');
    }

    const encodedJwt = this.jwt.encodeJwt();
    data.push(encodedJwt);

    if (this.disclosures && this.disclosures.length > 0) {
      const encodeddisclosures = this.disclosures
        .map((dc) => dc.encode())
        .join(SD_SEPARATOR);
      data.push(encodeddisclosures);
    }

    data.push(this.kbJwt ? this.kbJwt.encodeJwt() : '');
    return data.join(SD_SEPARATOR);
  }

  public async keys(hasher: Hasher): Promise<string[]> {
    return listKeys(await this.getClaims(hasher)).sort();
  }

  public async presentableKeys(hasher: Hasher): Promise<string[]> {
    if (!this.jwt?.payload || !this.disclosures) {
      throw new SDJWTException('Invalid sd-jwt: jwt or disclosures is missing');
    }
    const { disclosureKeymap } = await unpack(
      this.jwt?.payload,
      this.disclosures,
      hasher,
    );
    return Object.keys(disclosureKeymap).sort();
  }

  public async getClaims<T>(hasher: Hasher): Promise<T> {
    if (!this.jwt?.payload || !this.disclosures) {
      throw new SDJWTException('Invalid sd-jwt: jwt or disclosures is missing');
    }
    const { unpackedObj } = await unpack(
      this.jwt.payload,
      this.disclosures,
      hasher,
    );
    return unpackedObj as T;
  }
}

export const listKeys = (obj: Record<string, unknown>, prefix = '') => {
  const keys: string[] = [];
  for (const key in obj) {
    if (obj[key] === undefined) continue;
    const newKey = prefix ? `${prefix}.${key}` : key;
    keys.push(newKey);

    if (obj[key] && typeof obj[key] === 'object' && obj[key] !== null) {
      keys.push(...listKeys(obj[key] as Record<string, unknown>, newKey));
    }
  }
  return keys;
};

// ── BDHT DIVERGENCE D2 ──────────────────────────────────────────────────────
// A disclosure frame directive that cannot be satisfied against the payload
// being signed is now a REFUSAL TO ISSUE, not a silent no-op.
//
// THE BUG THIS CLOSES. Upstream `pack()` decides which array elements to redact
// with `sd.includes(i)`, where `i` is the numeric loop counter. A frame written
// with string indices — `{ medications: { _sd: ['0','1','2'] } }` — matches
// nothing. Nothing throws. Nothing warns. The `else` branch runs for every
// element and THE WHOLE ARRAY GOES INTO THE ISSUER-SIGNED PAYLOAD IN CLEARTEXT.
// Measured, twice, in this repository:
//   - packages/backend/tests/fast/disclosureFrameLeak.test.ts
//   - CREDO-SECURITY-REPORT.md finding 4
// A patient who asked to reveal one of three medications reveals all three, and
// the two issuer payloads are structurally identical, so nothing downstream can
// tell the leaking one from the safe one.
//
// WHY THE TYPE FIX (D4) IS NOT ENOUGH ON ITS OWN. Credo's published
// `IDisclosureFrame` types `_sd` as `string[]`, so a developer obeying their
// vendor's type, with the compiler agreeing, produces the leaking form and has
// to cast to produce the working one. The type points the wrong way; a type is
// therefore the one signal that cannot be relied on here. Only a runtime
// assertion catches it, and it has to run BEFORE the payload is signed.
//
// WHY IT ALSO REJECTS UNKNOWN OBJECT KEYS. `{ _sd: ['medication'] }` against a
// payload whose field is `medications` is the same class of failure — a
// directive that matches nothing while the real field stays in cleartext — and
// from inside `pack()` a typo is indistinguishable from a deliberately absent
// optional claim. We take the strict reading: build frames from the payload you
// are actually signing. `buildDisclosureFrame` in `@ssi-healthcare/shared` does
// exactly that, so this costs us nothing and costs a careless integrator an
// error instead of a data leak. This is the one divergence that could reject
// input upstream accepts; it is recorded as such in ../NOTICE.
//
// FAILS CLOSED. Every branch either proves the directive is satisfiable or
// throws. "There was nothing to check" is not a passing outcome.
// ────────────────────────────────────────────────────────────────────────────
const assertFrameIsSatisfiable = (
  claims: unknown,
  sd: Array<string | number>,
): void => {
  if (sd.length === 0) return;

  if (Array.isArray(claims)) {
    for (const index of sd) {
      if (typeof index !== 'number' || !Number.isInteger(index)) {
        throw new SdJwtFrameError(
          'Disclosure frame targets an array element by a non-numeric index, which the frame walker cannot match. Array indices must be numbers, not strings — the whole array would otherwise be issued in cleartext.',
          { index, arrayLength: claims.length },
        );
      }
      if (index < 0 || index >= claims.length) {
        throw new SdJwtFrameError(
          'Disclosure frame targets an array element that does not exist, so the directive would be silently ignored.',
          { index, arrayLength: claims.length },
        );
      }
    }
    return;
  }

  if (typeof claims === 'object' && claims !== null) {
    for (const key of sd) {
      if (
        typeof key !== 'string' ||
        !Object.prototype.hasOwnProperty.call(claims, key)
      ) {
        throw new SdJwtFrameError(
          'Disclosure frame names a claim the payload does not have, so the directive would be silently ignored and the payload issued as-is.',
          { key, available: Object.keys(claims as Record<string, unknown>) },
        );
      }
    }
    return;
  }

  throw new SdJwtFrameError(
    'Disclosure frame names claims to redact, but the value it applies to is neither an object nor an array.',
    { sd, receivedType: claims === null ? 'null' : typeof claims },
  );
};
// ── END BDHT DIVERGENCE D2 ──────────────────────────────────────────────────

export const pack = async <T extends Record<string, unknown>>(
  claims: T,
  disclosureFrame: DisclosureFrame<T> | undefined,
  hash: HasherAndAlg,
  saltGenerator: SaltGenerator,
): Promise<{
  packedClaims: Record<string, unknown> | Array<Record<string, unknown>>;
  disclosures: Array<Disclosure>;
}> => {
  if (!disclosureFrame) {
    return {
      packedClaims: claims,
      disclosures: [],
    };
  }

  const sd = disclosureFrame[SD_DIGEST] ?? [];
  const decoyCount = disclosureFrame[SD_DECOY] ?? 0;

  // BDHT DIVERGENCE D2: refuse a frame that cannot take effect. See the block
  // comment on `assertFrameIsSatisfiable` below for why this is the load-bearing
  // fix and the type change in ../types/type.ts is not.
  assertFrameIsSatisfiable(claims, sd as Array<string | number>);

  if (Array.isArray(claims)) {
    const packedClaims: Array<Record<typeof SD_LIST_KEY, string>> = [];
    const disclosures: Array<Disclosure> = [];
    const recursivePackedClaims: Record<number, unknown> = {};

    for (const key in disclosureFrame) {
      if (key !== SD_DIGEST) {
        const idx = Number.parseInt(key, 10);
        const packed = await pack(
          claims[idx],
          disclosureFrame[idx],
          hash,
          saltGenerator,
        );
        recursivePackedClaims[idx] = packed.packedClaims;
        disclosures.push(...packed.disclosures);
      }
    }

    for (let i = 0; i < claims.length; i++) {
      const claim = recursivePackedClaims[i]
        ? recursivePackedClaims[i]
        : claims[i];
      /** This part is set discloure for array items.
       *  The example of disclosureFrame of an Array is
       *
       *  const claims = {
       *    array: ['a', 'b', 'c']
       *  }
       *
       *  diclosureFrame: DisclosureFrame<typeof claims> = {
       *    array: {
       *      _sd: [0, 2]
       *    }
       *  }
       *
       *  It means that we want to disclose the first and the third item of the array
       *
       *  So If the index `i` is in the disclosure list(sd), then we create a disclosure for the claim
       */
      // @ts-expect-error
      if (sd.includes(i)) {
        const salt = await saltGenerator(16);
        const disclosure = new Disclosure([salt, claim]);
        const digest = await disclosure.digest(hash);
        packedClaims.push({ [SD_LIST_KEY]: digest });
        disclosures.push(disclosure);
      } else {
        packedClaims.push(claim);
      }
    }
    for (let j = 0; j < decoyCount; j++) {
      const decoyDigest = await createDecoy(hash, saltGenerator);
      packedClaims.push({ [SD_LIST_KEY]: decoyDigest });
    }
    return { packedClaims, disclosures };
  }

  const packedClaims: Record<string, unknown> = {};
  const disclosures: Array<Disclosure> = [];
  const recursivePackedClaims: Record<string, unknown> = {};

  for (const key in disclosureFrame) {
    if (key !== SD_DIGEST) {
      const packed = await pack(
        // @ts-expect-error
        claims[key],
        disclosureFrame[key],
        hash,
        saltGenerator,
      );
      recursivePackedClaims[key] = packed.packedClaims;
      disclosures.push(...packed.disclosures);
    }
  }

  const _sd: string[] = [];

  for (const key in claims) {
    const claim = recursivePackedClaims[key]
      ? recursivePackedClaims[key]
      : claims[key];
    if (sd.includes(key)) {
      const salt = await saltGenerator(16);
      const disclosure = new Disclosure([salt, key, claim]);
      const digest = await disclosure.digest(hash);

      _sd.push(digest);
      disclosures.push(disclosure);
    } else {
      packedClaims[key] = claim;
    }
  }

  for (let j = 0; j < decoyCount; j++) {
    const decoyDigest = await createDecoy(hash, saltGenerator);
    _sd.push(decoyDigest);
  }

  if (_sd.length > 0) {
    packedClaims[SD_DIGEST] = _sd.sort();
  }
  return { packedClaims, disclosures };
};
