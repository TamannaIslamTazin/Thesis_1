/**
 * `@ssi-healthcare/sdk/ledger` — reading the chain, portably.
 *
 * DID resolution, DID-document vocabulary, and the chain's own validation rules,
 * expressed so they run anywhere: a handset, a browser, an integrator's server.
 *
 * THE LINE THIS MODULE DRAWS. Reads live here; WRITES do not. Transaction
 * building, signing and deployment stay in the backend, which is where the keys
 * and the custody rules are. A wallet needs to check what a DID document says;
 * it has no business publishing one.
 *
 * Chain access, when it arrives, goes over `fetch` rather than Credo's
 * `CheqdLedgerService`. That is not a style preference — @credo-ts/* is a Node
 * stack and the dependency-direction guard rejects it here, which is the whole
 * point of the guard. Anything needing Credo belongs in the backend or behind a
 * port this module declares and the backend implements.
 */
export {
  DID_V1_CONTEXT,
  ED25519_2020_CONTEXT,
  ED25519_VERIFICATION_KEY_2020,
  ED25519_MULTICODEC_PREFIX,
  ED25519_RAW_KEY_LENGTH,
  isCheqdDid,
  didPartOf,
  fragmentOf,
  uniqueSorted,
  controllersOrSubject,
  signerDidsForCreate,
  signerDidsForUpdate,
  verificationMethodDelta,
  verificationMethodChanged,
} from './didDocument';
export type {
  VerificationMethodSlot,
  CheqdDidDocumentShape,
  SignerSetInputDocument,
  VerificationMethodDelta,
} from './didDocument';

// base58btc/multibase, replacing Credo's MultiBaseEncoder -- which supports
// base58btc and nothing else, so this is a complete replacement rather than a
// subset. See ./multibase for the one deliberate divergence.
export {
  BASE58BTC_ALPHABET,
  BASE58BTC_MULTIBASE_PREFIX,
  base58btcDecode,
  base58btcEncode,
  multibaseDecode,
  multibaseEncode,
  toHex,
} from './multibase';
export type { MultibaseName, DecodedMultibase } from './multibase';

export {
  ed25519PublicKeyFromMultibase,
  ed25519PublicKeyToMultibase,
  assertEd25519Multibase,
} from './ed25519Key';

// The shape refusals. A handset about to rotate its own key needs to predict
// what the chain will demand BEFORE it broadcasts, and an integrator needs the
// same answer without standing up our backend.
export {
  assertIsCheqdDid,
  assertRotationIsSurvivable,
  assertInstitutionalShape,
  assertPatientRecoverableShape,
  assertRecoveryControllerShape,
  SHAPE_ASSERTION_DELIBERATELY_OMITTED,
  classifyPatientDid,
} from './didShapes';
export type { PatientShapeExpectation, PatientDidRecoverability } from './didShapes';
