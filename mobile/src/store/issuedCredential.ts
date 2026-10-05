/**
 * Build a WalletCredential envelope from a credential the wallet received
 * directly from an issuer over OID4VCI.
 *
 * WHY THIS EXISTS. The accept path assumed an ISSUER BACKEND persisted the
 * credential and the wallet only had to re-fetch its list. That held while the
 * issuer WAS the national backend; it is false for a hospital issuer, which
 * signs the credential, returns it, and keeps nothing on our behalf. Without
 * this step the credential is received, reported as "success", and discarded —
 * issued correctly and never stored.
 *
 * The envelope mirrors what `GET /credentials` returns, because the local
 * encrypted database and every reader of it (transformCredential, the Cards
 * screen) take that shape. Fields the issuer does not supply are derived here;
 * none of them is a trust decision — the issuer's signature travels untouched
 * in `credentialJwt` and is what any verifier checks.
 */
import { base64UrlToBytes } from '@ssi-healthcare/shared';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';
import type { WalletCredential } from '@ssi-healthcare/sdk';

/** Mirrors the server's type -> category mapping for the OID4VCI types. */
const CATEGORY_BY_TYPE: Record<string, WalletCredential['category']> = {
  PatientProfileCredential: 'IDENTITY',
  VitalSignsCredential: 'GENERAL',
  PrescriptionCredential: 'PRESCRIPTIONS',
  AppointmentDiagnosisCredential: 'GENERAL',
  ImmunizationCredential: 'VACCINATIONS',
  DischargeSummaryCredential: 'GENERAL',
  LabResultCredential: 'LAB_RESULTS',
};

function decodeJwtPayload(jwt: string): Record<string, unknown> {
  const parts = jwt.split('.');
  if (parts.length < 2) {
    throw new Error('The issuer returned a credential that is not a JWT');
  }
  return JSON.parse(new TextDecoder().decode(base64UrlToBytes(parts[1]))) as Record<string, unknown>;
}

/** "PrescriptionCredential" -> "Prescription". */
function readableName(type: string): string {
  const withoutSuffix = type.replace(/Credential$/, '');
  const spaced = withoutSuffix.replace(/([a-z])([A-Z])/g, '$1 $2').trim();
  return spaced.length > 0 ? spaced : type;
}

export function walletCredentialFromIssued(jwt: string, fallbackHolderDid = ''): WalletCredential {
  const payload = decodeJwtPayload(jwt);
  const vc = (payload.vc ?? payload) as Record<string, unknown>;

  const types = Array.isArray(vc.type) ? (vc.type as string[]) : ['VerifiableCredential'];
  const specificType = types[types.length - 1] ?? 'VerifiableCredential';

  const issuer = vc.issuer;
  const issuerDid =
    typeof issuer === 'string'
      ? issuer
      : String((issuer as { id?: string } | undefined)?.id ?? payload.iss ?? '');

  // The holder is the credential's own subject — the issuer bound it there, so
  // it is the authoritative answer and needs no profile lookup.
  const subject = vc.credentialSubject as { id?: string } | undefined;
  const holderDid =
    typeof subject?.id === 'string' && subject.id.length > 0 ? subject.id : fallbackHolderDid;

  const digest = bytesToHex(sha256(new TextEncoder().encode(jwt)));
  const now = new Date().toISOString();
  const validFrom = String(vc.validFrom ?? vc.issuanceDate ?? now);

  return {
    // The issuer's own id when it supplied one; otherwise a hash-derived id, so
    // the row is stable across a re-import of the same credential.
    id: typeof vc.id === 'string' && vc.id.length > 0 ? vc.id : `issued-${digest.slice(0, 24)}`,
    holderDid,
    issuerDid,
    type: types,
    category: CATEGORY_BY_TYPE[specificType] ?? 'GENERAL',
    name: readableName(specificType),
    credentialHash: digest,
    status: 'ACTIVE',
    issuedAt: validFrom,
    createdAt: now,
    updatedAt: now,
    useCount: 0,
    credential: vc as unknown as WalletCredential['credential'],
    credentialJwt: jwt,
    credentialFormat: 'vc+jwt',
  };
}
