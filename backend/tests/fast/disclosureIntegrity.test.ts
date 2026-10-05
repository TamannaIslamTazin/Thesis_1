/**
 * `assertDisclosuresResolve` — the pure kernel of NEGATIVE CONTROL #3.
 *
 * WHAT THE HOLE IS. A tampered disclosure does not forge a claim: its digest
 * stops matching, `getClaimsSync` drops it, and the claim simply disappears.
 * Nothing reports that. Credo 0.6 returns `isValid: true` for a presentation
 * carrying a disclosure that resolves to nothing — measured — so a verifier
 * that asked for `hivStatus` gets a "valid" presentation with `hivStatus`
 * silently missing, and the attacker chooses which claims vanish. RFC 9807 §7.3
 * requires a verifier to reject exactly this, so the check is conformance
 * rather than a house rule.
 *
 * WHY THIS HALF IS FAST AND THE OTHER HALF IS NOT. `assertDisclosuresResolve`
 * takes a compact SD-JWT string and returns errors. It needs no agent, no DID
 * resolution and no network — only a hasher. So the DETECTION logic is fully
 * testable here, and it is the part most likely to be broken by a well-meaning
 * refactor (the `_sd_alg` honouring and the container-nesting walk both look
 * like dead weight until you know why they are there).
 *
 * What is NOT establishable here is the other half of the control: that
 * unmodified Credo ACCEPTS the tampered presentation, and that our boundary
 * rejects it while every other check stays green. That attribution needs real
 * signatures over real DIDs and lives in `tests/live/negativeControls.live.test.ts`.
 */
import { describe, it, expect } from 'vitest';
import { assertDisclosuresResolve } from '../../src/services/sdJwtVc.js';
import {
  createSdJwtInstance,
  decodedDisclosures,
  replaceDisclosure,
  injectDisclosure,
  keepOnlyDisclosures,
  splitCompact,
  joinCompact,
  SD_JWT_SEPARATOR,
} from './helpers/sdJwtFixture.js';

const HOLDER = 'did:cheqd:bdhealthtestnet:00000000-0000-4000-8000-000000000001';

const SUBJECT = {
  id: HOLDER,
  hivStatus: 'negative',
  bloodType: 'O+',
  prescriber: { name: 'Dr Karim', licence: 'BMDC-4471' },
  medications: ['Metformin 500mg', 'Sertraline 50mg'],
};

/** An honest SD-JWT over SUBJECT, containers and array elements included. */
async function honestSdJwt(): Promise<string> {
  const sdJwt = await createSdJwtInstance();
  return sdJwt.issue(
    { credentialSubject: { ...SUBJECT } },
    {
      credentialSubject: {
        _sd: ['hivStatus', 'bloodType', 'prescriber', 'medications'],
        prescriber: { _sd: ['name', 'licence'] },
        medications: { _sd: [0, 1] },
      },
    },
  );
}

/** Index of the disclosure for a named object member. */
function indexOfMember(compact: string, name: string): number {
  return decodedDisclosures(compact).findIndex((d) => d.length === 3 && d[1] === name);
}

describe('assertDisclosuresResolve — honest artifacts are not caught', () => {
  it('accepts a full, untampered SD-JWT', async () => {
    // A false positive here rejects every genuine presentation, so this is as
    // load-bearing as the rejections below.
    expect(assertDisclosuresResolve(await honestSdJwt())).toEqual([]);
  });

  it('accepts a NESTED container whose member digests are not in the payload', async () => {
    // The subtle case the walk exists for. `prescriber.name`'s digest lives
    // inside the `prescriber` disclosure's own value, not in the payload's
    // `_sd`. A checker that only walked the payload would declare every nested
    // disclosure unmatched and reject every honest credential that has one.
    const compact = await honestSdJwt();
    expect(decodedDisclosures(compact).some((d) => d[1] === 'name')).toBe(true);
    expect(assertDisclosuresResolve(compact)).toEqual([]);
  });

  it('accepts ARRAY ELEMENT digests, which use the reserved "..." key', async () => {
    const compact = await honestSdJwt();
    const elements = decodedDisclosures(compact).filter((d) => d.length === 2);
    expect(elements).toHaveLength(2);
    expect(assertDisclosuresResolve(compact)).toEqual([]);
  });

  it('accepts a credential with no disclosures at all', async () => {
    const sdJwt = await createSdJwtInstance();
    const compact = await sdJwt.issue({ credentialSubject: { id: HOLDER } }, {});
    expect(assertDisclosuresResolve(compact)).toEqual([]);
  });

  it('accepts a STRICT SUBSET — withholding disclosures is the holder\'s right', async () => {
    // Selective disclosure works by DROPPING disclosures. The check must object
    // to disclosures that do not match a digest, never to digests that have no
    // disclosure — otherwise it would forbid selective disclosure itself.
    //
    // The subset keeps only a TOP-LEVEL leaf, whose digest sits in the payload's
    // own `_sd` and is therefore still reachable once everything else is gone.
    const compact = await honestSdJwt();
    const subset = keepOnlyDisclosures(compact, [indexOfMember(compact, 'hivStatus')]);

    expect(assertDisclosuresResolve(subset)).toEqual([]);
  });

  it('REJECTS a nested disclosure whose ANCESTOR container was withheld', async () => {
    // Discovered while writing the subset case above, and kept because it is a
    // real property rather than a quirk. `prescriber.name`'s digest lives inside
    // the `prescriber` disclosure's VALUE, not in the payload. Disclose the
    // member without its container and the digest is genuinely unreachable, so
    // the verifier cannot tie the claim to anything the issuer signed.
    //
    // Rejecting is correct: a descendant without its ancestor is a malformed
    // presentation, and "malformed" must not resolve to "claim silently
    // absent" — that is the whole failure mode this check exists to stop.
    const compact = await honestSdJwt();
    const orphaned = keepOnlyDisclosures(compact, [indexOfMember(compact, 'name')]);

    expect(assertDisclosuresResolve(orphaned).length).toBeGreaterThan(0);
  });
});

describe('assertDisclosuresResolve — tampering is caught', () => {
  it('REJECTS a disclosure whose value was altered', async () => {
    // The claim-deletion attack: flip `hivStatus` to a value of the attacker's
    // choosing. The digest stops matching, Credo drops the claim and reports
    // success. We must not.
    const compact = await honestSdJwt();
    const index = indexOfMember(compact, 'hivStatus');
    const original = decodedDisclosures(compact)[index]!;

    const tampered = replaceDisclosure(compact, index, [original[0], 'hivStatus', 'positive']);
    const errors = assertDisclosuresResolve(tampered);

    expect(errors.length).toBeGreaterThan(0);
    expect(errors.join(' ')).toMatch(/never committed to|tampered with or injected/i);
  });

  it('REJECTS a disclosure whose SALT was altered, value untouched', async () => {
    // Same digest failure by a different route. Proves the check hashes the
    // encoded form rather than comparing claim values.
    const compact = await honestSdJwt();
    const index = indexOfMember(compact, 'bloodType');
    const original = decodedDisclosures(compact)[index]!;

    const tampered = replaceDisclosure(compact, index, ['AAAAAAAAAAAAAAAA', 'bloodType', original[2]]);
    expect(assertDisclosuresResolve(tampered).length).toBeGreaterThan(0);
  });

  it('REJECTS an INJECTED disclosure the issuer never committed to', async () => {
    const compact = await honestSdJwt();
    const injected = injectDisclosure(compact, ['ZZZZZZZZZZZZZZZZ', 'clearance', 'top-secret']);

    const errors = assertDisclosuresResolve(injected);
    expect(errors.length).toBeGreaterThan(0);
  });

  it('REJECTS a disclosure that is not decodable at all', async () => {
    // In a DISCLOSURE position, not the trailing one — the trailing slot is the
    // key-binding position and is refused for a different, separately-tested
    // reason. Appending after the final `~` is the only way to test the
    // disclosure path, so the key-binding slot is re-emptied afterwards.
    const compact = await honestSdJwt();
    const parts = splitCompact(compact);
    const mangled = joinCompact({
      ...parts,
      disclosures: [...parts.disclosures, '!!!not-base64url-json!!!'],
    });
    const errors = assertDisclosuresResolve(mangled);

    expect(errors.length).toBeGreaterThan(0);
  });

  it('reports ONE error per tampered disclosure', async () => {
    // Attribution: a verifier operator needs to know how much of the
    // presentation was touched, not merely that something was.
    const compact = await honestSdJwt();
    const disclosures = decodedDisclosures(compact);

    let tampered = compact;
    const hiv = indexOfMember(compact, 'hivStatus');
    const blood = indexOfMember(compact, 'bloodType');
    tampered = replaceDisclosure(tampered, hiv, [disclosures[hiv]![0], 'hivStatus', 'positive']);
    tampered = replaceDisclosure(tampered, blood, [disclosures[blood]![0], 'bloodType', 'AB-']);

    expect(assertDisclosuresResolve(tampered)).toHaveLength(2);
  });

  it('FAILS CLOSED when the payload cannot be read but disclosures are present', async () => {
    // If the payload is unreadable there are no committed digests to match
    // against. "Nothing to check" must not read as "nothing wrong".
    const compact = await honestSdJwt();
    const broken = joinCompact({
      ...splitCompact(compact),
      jwt: 'eyJhbGciOiJFZERTQSJ9.@@@not-json@@@.sig',
    });

    expect(assertDisclosuresResolve(broken).length).toBeGreaterThan(0);
  });
});

describe('assertDisclosuresResolve — _sd_alg is honoured, not assumed', () => {
  it('does not hardcode sha-256', async () => {
    // A credential issued under sha-512 would otherwise have every disclosure
    // declared unmatched and be rejected wholesale — a denial of service on
    // honest credentials dressed up as a security check.
    const compact = await honestSdJwt();
    const [jwt, ...disclosures] = compact.split(SD_JWT_SEPARATOR);
    const [header, payloadSegment, signature] = jwt!.split('.');

    const payload = JSON.parse(Buffer.from(payloadSegment!, 'base64url').toString('utf8'));
    expect(payload._sd_alg).toBe('sha-256');

    // Relabel the payload as sha-512 without rehashing anything. Every digest
    // must now fail to match — which is the proof the label was actually read.
    payload._sd_alg = 'sha-512';
    const relabelled = [
      [header, Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url'), signature].join('.'),
      ...disclosures,
    ].join(SD_JWT_SEPARATOR);

    const errors = assertDisclosuresResolve(relabelled);
    expect(errors.length).toBe(disclosures.filter(Boolean).length);
  });
});
