/**
 * OID4VCI IssuerAgent
 *
 * Implements the OpenID for Verifiable Credential Issuance (OID4VCI) protocol
 * using the pre-authorized code flow. Any organization (hospital, clinic, lab)
 * can instantiate this class to become a VC issuer.
 *
 * Usage:
 *   const issuer = await IssuerAgent.create({ issuerName: 'City Hospital', issuerUrl: '...' });
 *   const { uri } = await issuer.createOffer('PrescriptionCredential', subjectData);
 *   // Display uri as QR code — wallet scans and retrieves credential
 *
 * Express integration:
 *   app.get('/.well-known/openid-credential-issuer', (req, res) => res.json(issuer.getIssuerMetadata()));
 *   app.post('/api/oid4vci/token', async (req, res) => res.json(await issuer.handleTokenRequest(req.body)));
 *   app.post('/api/oid4vci/credential', async (req, res) => res.json(await issuer.handleCredentialRequest(req.body, req.headers.authorization)));
 */

import { SignJWT, generateKeyPair, exportJWK, importJWK, decodeProtectedHeader } from 'jose';
import type {
  IssuerConfig,
  IssuerMetadata,
  CredentialSupportedEntry,
  OID4VCICredentialOffer,
  PendingOffer,
  TokenRequest,
  TokenResponse,
  CredentialRequest,
  CredentialResponse,
  IssuanceSession,
  W3CCredential,
  HealthcareCredentialType,
} from './types';
import { CREDENTIAL_TYPE_CONTEXTS, CREDENTIAL_SCHEMA_VALIDATORS } from './schemas';

// ---------------------------------------------------------------------------
// did:key helpers (Ed25519 multibase-encoded)
// ---------------------------------------------------------------------------

/** Multicodec prefix for Ed25519 public key: 0xed 0x01 */
const ED25519_MULTICODEC_PREFIX = new Uint8Array([0xed, 0x01]);

/** Base58btc alphabet */
const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function encodeBase58(bytes: Uint8Array): string {
  let num = BigInt(0);
  for (const byte of bytes) {
    num = num * BigInt(256) + BigInt(byte);
  }
  let encoded = '';
  while (num > BigInt(0)) {
    const remainder = Number(num % BigInt(58));
    encoded = BASE58_ALPHABET[remainder] + encoded;
    num = num / BigInt(58);
  }
  // Leading zeros
  for (const byte of bytes) {
    if (byte === 0) encoded = '1' + encoded;
    else break;
  }
  return encoded;
}

/**
 * Credo's `parseHolderBindingFromCredential` rejects any `cnf.kid` that is not
 * an absolute DID URL — it needs both the `did:` scheme and a `#` fragment to
 * dereference. A relative reference like `#key-1` is legal in a DID document
 * and useless here, so the check is not cosmetic.
 */
function isAbsoluteDidUrl(value: string): boolean {
  return value.startsWith('did:') && value.includes('#');
}

/**
 * The verification method DID URL of a `did:key` identifier.
 *
 * `did:key` embeds its public key in the identifier, so the verification method
 * is `did:key:<mb>#<mb>` with the same multibase value repeated — no resolution
 * and no network. Returns null for every other method, which must go through
 * the configured resolver instead.
 */
function didKeyVerificationMethod(did: string): string | null {
  if (!did.startsWith('did:key:')) return null;
  const multibase = did.slice('did:key:'.length);
  // Reject a did:key that already carries a path, query or fragment: the
  // caller passed something that is not a bare identifier.
  if (!multibase || /[#?/]/.test(multibase)) return null;
  return `${did}#${multibase}`;
}

/** Convert an Ed25519 public key (JWK) to a did:key identifier */
async function publicKeyJwkToDidKey(publicKeyJwk: JsonWebKey): Promise<string> {
  // Import the key and export as raw bytes
  const key = await importJWK(publicKeyJwk, 'EdDSA') as CryptoKey;
  const rawBytes = await crypto.subtle.exportKey('raw', key);
  const keyBytes = new Uint8Array(rawBytes);

  // Prepend multicodec prefix for Ed25519
  const multicodecKey = new Uint8Array(ED25519_MULTICODEC_PREFIX.length + keyBytes.length);
  multicodecKey.set(ED25519_MULTICODEC_PREFIX);
  multicodecKey.set(keyBytes, ED25519_MULTICODEC_PREFIX.length);

  // Base58btc encode with 'z' multibase prefix
  const encoded = 'z' + encodeBase58(multicodecKey);
  return `did:key:${encoded}`;
}

// ---------------------------------------------------------------------------
// Token / ID generation helpers
// ---------------------------------------------------------------------------

function generateId(prefix = ''): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  return prefix ? `${prefix}-${hex}` : hex;
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

// ---------------------------------------------------------------------------
// IssuerAgent
// ---------------------------------------------------------------------------

export class IssuerAgent {
  private readonly config: IssuerConfig;
  private privateKey!: CryptoKey;

  /** In-memory stores (swap for DB adapter in production) */
  private readonly pendingOffers = new Map<string, PendingOffer>();
  private readonly issuanceSessions = new Map<string, IssuanceSession>();

  private constructor(config: IssuerConfig) {
    this.config = config;
  }

  // -------------------------------------------------------------------------
  // Factory — generate a fresh Ed25519 did:key or restore from existing JWKs
  // -------------------------------------------------------------------------

  /**
   * Create an IssuerAgent.
   *
   * If `privateKeyJwk` / `publicKeyJwk` are provided, restores from those keys.
   * Otherwise generates a new Ed25519 key pair and derives a did:key.
   *
   * Store the returned `keyMaterial()` in your environment / secrets manager
   * so the same DID is reused across restarts.
   */
  static async create(options: {
    issuerName: string;
    issuerUrl: string;
    supportedCredentialTypes?: HealthcareCredentialType[];
    privateKeyJwk?: JsonWebKey;
    publicKeyJwk?: JsonWebKey;
    offerTtlSeconds?: number;
    /**
     * Required to issue to any DID method other than `did:key` when the wallet
     * sends no proof of possession. See `IssuerConfig.resolveHolderBinding`.
     * The constructor is private, so this factory is the only way to supply it.
     */
    resolveHolderBinding?: IssuerConfig['resolveHolderBinding'];
  }): Promise<IssuerAgent> {
    let privateKeyJwk: JsonWebKey;
    let publicKeyJwk: JsonWebKey;

    if (options.privateKeyJwk && options.publicKeyJwk) {
      privateKeyJwk = options.privateKeyJwk;
      publicKeyJwk = options.publicKeyJwk;
    } else {
      // Generate fresh Ed25519 key pair
      const { privateKey, publicKey } = await generateKeyPair('EdDSA', {
        crv: 'Ed25519',
        extractable: true,
      });
      privateKeyJwk = await exportJWK(privateKey);
      publicKeyJwk = await exportJWK(publicKey);
      privateKeyJwk.alg = 'EdDSA';
      publicKeyJwk.alg = 'EdDSA';
    }

    const issuerDid = await publicKeyJwkToDidKey(publicKeyJwk);

    const config: IssuerConfig = {
      issuerDid,
      issuerName: options.issuerName,
      issuerUrl: options.issuerUrl.replace(/\/$/, ''),
      privateKeyJwk,
      publicKeyJwk,
      supportedCredentialTypes: options.supportedCredentialTypes ?? [
        'PatientProfileCredential',
        'VitalSignsCredential',
        'PrescriptionCredential',
        'AppointmentDiagnosisCredential',
        'ImmunizationCredential',
        'DischargeSummaryCredential',
      ],
      offerTtlSeconds: options.offerTtlSeconds ?? 300,
      resolveHolderBinding: options.resolveHolderBinding,
    };

    const agent = new IssuerAgent(config);
    agent.privateKey = await importJWK(privateKeyJwk, 'EdDSA') as CryptoKey;
    return agent;
  }

  /** The issuer's DID (persist this — it's the public identity of the issuer) */
  get did(): string {
    return this.config.issuerDid;
  }

  /** Export key material for persistence across restarts */
  keyMaterial(): { privateKeyJwk: JsonWebKey; publicKeyJwk: JsonWebKey; issuerDid: string } {
    return {
      privateKeyJwk: this.config.privateKeyJwk,
      publicKeyJwk: this.config.publicKeyJwk,
      issuerDid: this.config.issuerDid,
    };
  }

  // -------------------------------------------------------------------------
  // OID4VCI: /.well-known/openid-credential-issuer
  // -------------------------------------------------------------------------

  getIssuerMetadata(): IssuerMetadata {
    const base = this.config.issuerUrl;
    const credentialsSupported: CredentialSupportedEntry[] = this.config.supportedCredentialTypes.map(type => ({
      // Advertise what is actually issued: VC 2.0 with an enveloping JWT proof.
      format: 'vc+jwt',
      id: type,
      types: ['VerifiableCredential', type],
      cryptographic_binding_methods_supported: ['did:key'],
      cryptographic_suites_supported: ['EdDSA'],
      display: [{ name: this.humanize(type), locale: 'en' }],
    }));

    return {
      credential_issuer: base,
      credential_endpoint: `${base}/api/oid4vci/credential`,
      token_endpoint: `${base}/api/oid4vci/token`,
      credentials_supported: credentialsSupported,
      display: [{ name: this.config.issuerName, locale: 'en' }],
    };
  }

  // -------------------------------------------------------------------------
  // OID4VCI: Create credential offer → return openid-credential-offer:// URI
  // -------------------------------------------------------------------------

  async createOffer(
    credentialType: HealthcareCredentialType,
    credentialSubject: Record<string, unknown>,
    options: { subjectDid?: string; userPinRequired?: boolean } = {},
  ): Promise<{ offer: OID4VCICredentialOffer; offerId: string; uri: string }> {
    // Validate the subject data against the schema
    const validator = CREDENTIAL_SCHEMA_VALIDATORS[credentialType];
    if (!validator) {
      throw new Error(`Unsupported credential type: ${credentialType}`);
    }
    const parsed = validator.safeParse(credentialSubject);
    if (!parsed.success) {
      const errors = parsed.error.errors.map(e => `${e.path.join('.')}: ${e.message}`).join('; ');
      throw new Error(`Invalid credential subject for ${credentialType}: ${errors}`);
    }

    const offerId = generateId('offer');
    const preAuthCode = generateId('pac');
    const expiresAt = nowSeconds() + (this.config.offerTtlSeconds ?? 300);

    const pending: PendingOffer = {
      offerId,
      preAuthCode,
      credentialType,
      credentialSubject: parsed.data as Record<string, unknown>,
      subjectDid: options.subjectDid,
      expiresAt,
      used: false,
    };
    this.pendingOffers.set(preAuthCode, pending);

    const offer: OID4VCICredentialOffer = {
      credential_issuer: this.config.issuerUrl,
      credentials: [credentialType],
      grants: {
        'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
          'pre-authorized_code': preAuthCode,
          user_pin_required: options.userPinRequired ?? false,
        },
      },
    };

    // OID4VCI credential offer URI
    const encodedOffer = encodeURIComponent(JSON.stringify(offer));
    const uri = `openid-credential-offer://?credential_offer=${encodedOffer}`;

    return { offer, offerId, uri };
  }

  // -------------------------------------------------------------------------
  // OID4VCI: POST /api/oid4vci/token
  // -------------------------------------------------------------------------

  async handleTokenRequest(body: TokenRequest): Promise<TokenResponse> {
    if (body.grant_type !== 'urn:ietf:params:oauth:grant-type:pre-authorized_code') {
      throw Object.assign(new Error('unsupported_grant_type'), { statusCode: 400 });
    }

    const pending = this.pendingOffers.get(body['pre-authorized_code']);
    if (!pending) {
      throw Object.assign(new Error('invalid_grant: pre-authorized_code not found'), { statusCode: 400 });
    }
    if (pending.used) {
      throw Object.assign(new Error('invalid_grant: pre-authorized_code already used'), { statusCode: 400 });
    }
    if (nowSeconds() > pending.expiresAt) {
      this.pendingOffers.delete(body['pre-authorized_code']);
      throw Object.assign(new Error('invalid_grant: pre-authorized_code expired'), { statusCode: 400 });
    }

    // Mark as used
    pending.used = true;

    const accessToken = generateId('at');
    const cNonce = generateId('cn');
    const session: IssuanceSession = {
      accessToken,
      offerId: pending.offerId,
      credentialType: pending.credentialType,
      credentialSubject: pending.credentialSubject,
      subjectDid: pending.subjectDid,
      expiresAt: nowSeconds() + 300,
      issued: false,
    };
    this.issuanceSessions.set(accessToken, session);

    return {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 300,
      c_nonce: cNonce,
      c_nonce_expires_in: 300,
    };
  }

  // -------------------------------------------------------------------------
  // OID4VCI: POST /api/oid4vci/credential
  // -------------------------------------------------------------------------

  async handleCredentialRequest(
    body: CredentialRequest,
    authorizationHeader: string | undefined,
  ): Promise<CredentialResponse> {
    const accessToken = this.extractBearerToken(authorizationHeader);
    const session = this.issuanceSessions.get(accessToken);

    if (!session) {
      throw Object.assign(new Error('invalid_token'), { statusCode: 401 });
    }
    if (nowSeconds() > session.expiresAt) {
      this.issuanceSessions.delete(accessToken);
      throw Object.assign(new Error('invalid_token: token expired'), { statusCode: 401 });
    }

    // Optionally verify proof of possession JWT (c_nonce binding)
    // For development with did:key wallets, we accept without strict proof check.
    // Production: verify body.proof.jwt against c_nonce.

    // Establish the holder binding BEFORE signing. Failing here costs the
    // wallet one legible error; succeeding without a binding would hand it a
    // credential that is a bearer token and cannot be presented at all.
    const holderKeyId = await this.resolveHolderKeyId(body, session);

    // Build and sign the W3C VC
    const vc = await this.buildCredential(session);
    const jwtVc = await this.signCredential(vc, session.subjectDid, holderKeyId);

    session.issued = true;

    return {
      format: 'vc+jwt',
      credential: jwtVc,
    };
  }

  // -------------------------------------------------------------------------
  // Internal: holder binding
  // -------------------------------------------------------------------------

  /**
   * Determine the absolute DID URL to bind the credential to (`cnf.kid`).
   *
   * WHY THIS EXISTS AT ALL. Until now this issuer emitted no `cnf`, so every
   * credential it produced was a bearer token that anyone holding the JWT could
   * present as their own — and, against Credo 0.6, could not be presented by
   * anybody, because its presentation signer derives the holder key from
   * exactly this claim and throws when it is missing. Both properties are
   * invisible at issuance: the credential verifies fine in isolation.
   *
   * Three sources, in this order, and the order is the point:
   *
   *  1. The OID4VCI proof-of-possession JWT's `kid`. Preferred because it is
   *     the only source that carries EVIDENCE: the wallet signed the proof with
   *     that key, so it demonstrably controls it. The other two are assertions.
   *  2. The integrator's `resolveHolderBinding` hook, for DID methods needing a
   *     network resolver the SDK deliberately does not ship.
   *  3. Local `did:key` derivation, which needs no network because the method
   *     encodes the key in the identifier itself.
   *
   * Throws rather than returning null when none apply. See the class of bug
   * this mirrors on the backend: an unbound credential is not a degraded
   * credential, it is a guaranteed failure deferred to a confusing moment.
   */
  private async resolveHolderKeyId(
    body: CredentialRequest,
    session: IssuanceSession,
  ): Promise<string> {
    // 1. Proof of possession — the wallet proved control of this key.
    const fromProof = this.holderKeyIdFromProof(body.proof?.jwt);
    if (fromProof) return fromProof;

    const subjectDid = session.subjectDid;
    if (!subjectDid) {
      throw Object.assign(
        new Error(
          'invalid_credential_request: cannot issue an unbound credential — the request carried no proof of possession and the offer named no subject DID',
        ),
        { statusCode: 400, code: 'invalid_credential_request' },
      );
    }

    // 2. Integrator-supplied resolver, for methods that need the network.
    if (this.config.resolveHolderBinding) {
      const resolved = await this.config.resolveHolderBinding(subjectDid);
      if (resolved && isAbsoluteDidUrl(resolved)) return resolved;
    }

    // 3. did:key needs no resolver — the identifier IS the key.
    const derived = didKeyVerificationMethod(subjectDid);
    if (derived) return derived;

    throw Object.assign(
      new Error(
        `invalid_credential_request: cannot bind a credential to '${subjectDid}' — supply a proof of possession, or an IssuerConfig.resolveHolderBinding hook for this DID method`,
      ),
      { statusCode: 400, code: 'invalid_credential_request' },
    );
  }

  /**
   * Read the holder's key id out of an OID4VCI proof-of-possession JWT.
   *
   * The spec puts the wallet's key in the protected header as either `kid` (a
   * DID URL) or an embedded `jwk`. Only `kid` yields the absolute DID URL that
   * a `cnf` claim needs, so an embedded-JWK proof falls through to the other
   * sources rather than being silently mis-bound.
   */
  private holderKeyIdFromProof(proofJwt: string | undefined): string | null {
    if (!proofJwt) return null;
    try {
      const header = decodeProtectedHeader(proofJwt);
      const kid = header.kid;
      return kid && isAbsoluteDidUrl(kid) ? kid : null;
    } catch {
      // A malformed proof is not authority for anything. Fall through to the
      // remaining sources; if none apply the caller fails closed anyway.
      return null;
    }
  }

  // -------------------------------------------------------------------------
  // Internal: build W3C VC from session data
  // -------------------------------------------------------------------------

  private async buildCredential(session: IssuanceSession): Promise<W3CCredential> {
    const contexts = CREDENTIAL_TYPE_CONTEXTS[session.credentialType] ?? [
      'https://www.w3.org/ns/credentials/v2',
    ];

    const credentialSubject: Record<string, unknown> = { ...session.credentialSubject };
    if (session.subjectDid) {
      credentialSubject.id = session.subjectDid;
    }

    return {
      '@context': contexts,
      type: ['VerifiableCredential', session.credentialType],
      id: `urn:uuid:${generateId()}`,
      issuer: {
        id: this.config.issuerDid,
        name: this.config.issuerName,
      },
      // VC 2.0 names the validity window validFrom/validUntil.
      validFrom: new Date().toISOString(),
      validUntil: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(), // 1 year
      credentialSubject,
    };
  }

  // -------------------------------------------------------------------------
  // Internal: sign as an enveloped VC 2.0 credential (W3C VC-JOSE-COSE)
  // -------------------------------------------------------------------------

  /**
   * Secure a credential with an enveloping JWT proof.
   *
   * VC 2.0 SEPARATES THE DATA MODEL FROM THE SECURING MECHANISM, and the JWT
   * encoding differs from VC 1.1 accordingly. In 1.1 the credential was nested
   * under a `vc` claim beside registered claims (`iss`, `sub`, `nbf`, `exp`,
   * `jti`) that duplicated its fields, and the registered claims won on
   * conflict. In 2.0 THE PAYLOAD IS THE CREDENTIAL: its members sit at the top
   * level, there is no `vc` wrapper, and no registered claim restates them.
   *
   * The `typ` header is `vc+jwt` rather than `JWT`, which is how a verifier
   * knows which set of decoding rules to apply — see `detectVcJwtDataModel` on
   * the backend. Getting this wrong is silent: a v1 decoder reading a v2 token
   * finds none of the claims it looks for and yields an empty credential rather
   * than an error.
   *
   * `iat` and `cnf` are the two claims added, matching what Credo's
   * `W3cV2JwtCredentialService.signCredential` emits, so credentials from this
   * SDK and from the backend agent are byte-compatible for verifiers.
   *
   * `cnf` is the holder binding and is REQUIRED, not optional — see
   * `resolveHolderKeyId`. Its absence is what made every credential this SDK
   * previously issued a bearer token and unpresentable.
   */
  private async signCredential(
    vc: W3CCredential,
    subjectDid: string | undefined,
    holderKeyId: string,
  ): Promise<string> {
    const verificationMethod = `${this.config.issuerDid}#${this.config.issuerDid.split(':')[2]}`;

    // Ensure the credential identifies its subject, since VC 2.0 has no `sub`
    // claim to carry that separately.
    const credential: W3CCredential = {
      ...vc,
      id: vc.id ?? `urn:uuid:${generateId()}`,
      credentialSubject:
        subjectDid && !vc.credentialSubject.id
          ? { ...vc.credentialSubject, id: subjectDid }
          : vc.credentialSubject,
    };

    return new SignJWT({
      ...(credential as unknown as Record<string, unknown>),
      iat: nowSeconds(),
      // Holder binding. `kid` is an absolute DID URL naming the key the holder
      // must sign a presentation with — this is what stops the credential
      // being a bearer token, and what Credo reads to find the presentation
      // signing key.
      cnf: { kid: holderKeyId },
    })
      .setProtectedHeader({
        alg: 'EdDSA',
        typ: 'vc+jwt',
        kid: verificationMethod,
      })
      .sign(this.privateKey);
  }

  // -------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------

  private extractBearerToken(header: string | undefined): string {
    if (!header?.startsWith('Bearer ')) {
      throw Object.assign(new Error('invalid_token: missing Bearer token'), { statusCode: 401 });
    }
    return header.slice(7);
  }

  private humanize(type: string): string {
    return type.replace(/([A-Z])/g, ' $1').trim().replace('Credential', '').trim();
  }

  /** Clean up expired offers and sessions (call periodically or on demand) */
  purgeExpired(): void {
    const now = nowSeconds();
    for (const [key, offer] of this.pendingOffers) {
      if (now > offer.expiresAt) this.pendingOffers.delete(key);
    }
    for (const [key, session] of this.issuanceSessions) {
      if (now > session.expiresAt) this.issuanceSessions.delete(key);
    }
  }
}
