/**
 * R5 Phase B — the patient's Recovery Controller Key, its guardian custody, and
 * its optional PRF envelope.
 *
 * Nothing here knows what a DID is. The chain-facing half lives in
 * `packages/backend/src/services/deviceRecoveryKey.ts`, and the split is the
 * point: this code must run on a device with no ledger client, and keeping the
 * seam here is what makes "the key never leaves the device" a checkable claim
 * rather than an asserted one.
 */

export * from './base64Url.js';
export * from './multibase.js';
export * from './keyEnvelope.js';
export * from './recoveryKey.js';
export * from './guardianShares.js';
// Exported because a caller driving `slip39` itself on React Native needs the
// same runtime scope `guardianShares.ts` uses; the crypto shim beside it is NOT
// exported, because it is a Metro resolution target rather than an API.
export * from './slip39Runtime.js';
export * from './guardianCeremony.js';
export * from './prfEnvelope.js';
export * from './passphraseEnvelope.js';
