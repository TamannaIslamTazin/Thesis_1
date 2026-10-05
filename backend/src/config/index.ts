/**
 * SSI Healthcare Backend - Configuration
 *
 * Centralised configuration loaded from environment variables with
 * validation via Zod. Fails fast on startup if required vars are missing.
 */

import { z } from 'zod';
import dotenv from 'dotenv';

dotenv.config();

const configSchema = z.object({
  port: z.coerce.number().default(3001),
  nodeEnv: z.enum(['development', 'production', 'test']).default('development'),

  // Database
  databaseUrl: z.string().min(1, 'DATABASE_URL is required'),

  // Request limits (DDoS protection)
  bodyLimit: z.string().default('1mb'),

  // JWT
  jwtSecret: z.string().min(32, 'JWT_SECRET must be at least 32 characters'),

  // Web3Auth MPC
  web3authClientId: z.string().min(1, 'WEB3AUTH_CLIENT_ID is required'),
  web3authNetwork: z.string().default('sapphire_devnet'),

  // OAuth ID token audiences.
  // Each value is the OAuth client ID this server expects in the `aud` claim.
  // A provider with no client ID configured is refused at runtime rather than
  // verified without an audience check — an ID token is only meaningful when
  // it was minted FOR this application.
  googleClientId: z.string().optional(),
  appleClientId: z.string().optional(),
  microsoftClientId: z.string().optional(),
  // Microsoft issuers are tenant-scoped. The `common` endpoint returns an
  // issuer containing the concrete tenant GUID, so a specific tenant must be
  // configured for the issuer and JWKS URIs to be constructible.
  microsoftTenantId: z.string().optional(),

  // Cheqd
  //
  // `cheqdNetwork` is NOT free-form. Credo matches it against the network
  // segment of the DID being resolved (`did:cheqd:<network>:<id>`) when it
  // picks which SDK instance to use, so a value that does not appear in our
  // DIDs means every ledger operation fails with "Network not found".
  //
  // It is now `bdhealthtestnet`, OUR name, not cheqd's. Until 2026-08-14 this
  // read `testnet`, which named cheqd's PUBLIC test chain while the chain
  // actually behind it was our own `bd-health-trust-1`. Every identifier we
  // minted therefore advertised a network it did not live on, and an external
  // resolver following it would query cheqd and find nothing — which defeats
  // the whole point of issuing resolvable identifiers.
  //
  // Three things must carry the same string or DIDs become uncreatable or
  // unresolvable, and they are maintained in three different repositories:
  //   1. this value, and the DID strings built from it;
  //   2. `CheqdNetwork` in @cheqd/sdk and `NETWORK` in @credo-ts/cheqd, both
  //      held by pnpm patches in ../../patches/;
  //   3. `app_state.cheqd.did_namespace` in the chain's genesis.json, in
  //      /home/ahsan/Work/Project/BDHealthTrust/cheqd-localnet. The node enforces it and
  //      rejects mismatches outright — this is not a soft failure.
  //
  // The sibling network is `bdhealth`, our future production chain. Note that
  // it is NOT cheqd mainnet: there is deliberately no remaining code path to
  // cheqd's public networks anywhere in this system.
  //
  // Deliberately an enum and not `z.string()`. A free-form string here is
  // indistinguishable from a typo until the first DID write fails somewhere
  // deep inside Credo, and the failure mode of a wrong value is unresolvable
  // identifiers rather than a clean error. Enumerating the two legal values
  // moves that failure to process start, and gives the rest of the codebase a
  // literal union type instead of `string` — which is what lets callers pass
  // this straight into Credo's `network` option without a cast.
  cheqdNetwork: z
    .enum(['bdhealthtestnet', 'bdhealth'])
    .default('bdhealthtestnet'),

  // Points at the SOVEREIGN FORK, not at public cheqd. Deployment lives in
  // /home/ahsan/Work/Project/BDHealthTrust/cheqd-localnet (`docker compose up -d`), and
  // identity writes there are free — literal `fee: []`, not nominal dust.
  //
  // The previous default was `https://rpc.cheqd.network`, which is a genuinely
  // confusing string: in Credo's old `DefaultRPCUrl` enum, `rpc.cheqd.net` was
  // MAINNET and `rpc.cheqd.network` was TESTNET. One letter apart, and the
  // longer one is the *less* dangerous of the two. If you ever reintroduce a
  // public endpoint here, write which one it is in a comment beside it — do
  // not make the next reader infer it from the hostname.
  //
  // That enum no longer exists. The @credo-ts/cheqd patch deletes it outright
  // rather than repointing it, so omitting `rpcUrl` is now a startup error
  // instead of a silent redirect to a chain we do not control. This value is
  // consequently load bearing: nothing downstream will invent an endpoint if
  // it is missing.
  cheqdRpcUrl: z.string().url().default('http://localhost:26657'),

  // SECRET. The key that signs and pays for every DID write to our chain.
  //
  // Lives in .env only, which is gitignored (`.env*` with a `!.env.example`
  // negation). .env.example carries a placeholder and never a real value.
  //
  // WHY A FRESH KEY IS NOT OPTIONAL. Every genesis account on
  // bd-health-trust-1 was created from cheqd's upstream *test* mnemonics,
  // which are published in plaintext in their public repository. Anyone can
  // sign as `operator-0`. A DID whose creating transaction was signed by a key
  // the whole internet holds carries no authenticity claim at all, which
  // defeats the point of writing it to a ledger. This key is generated fresh
  // and has never left this machine.
  //
  // FORMAT. @cheqd/sdk's `createCosmosPayerWallet` accepts EITHER a BIP39
  // English mnemonic (dispatched to DirectSecp256k1HdWallet.fromMnemonic) OR a
  // raw secp256k1 private key in hex (DirectSecp256k1Wallet.fromKey). It picks
  // between them by testing the string against cosmjs's EnglishMnemonic
  // matcher, i.e. /^[a-z]+( [a-z]+)*$/. Note the trap that hides in there: a
  // hex key that happens to contain only the letters a-f and no digits would
  // match that regex and be misrouted to the mnemonic path. We use a 24-word
  // mnemonic, which cannot collide.
  //
  // The regex below rejects a malformed value at process start rather than at
  // the first DID write, where it would otherwise surface as an opaque throw
  // from inside cosmjs, long after the request that triggered it.
  //
  // EMPTY IS LEGAL AND MEANS "READS ONLY". Resolving DIDs needs no payer; only
  // writes do. A deployment that only verifies credentials can leave this
  // unset, and it will fail loudly on the first write attempt rather than
  // being blocked from starting. That is why this is not `.min(1)`.
  cosmosPayerSeed: z
    .string()
    .default('')
    .refine(
      (value) =>
        value === '' ||
        /^([a-z]+ ){11,23}[a-z]+$/.test(value) ||
        /^(0x)?[0-9a-fA-F]{64}$/.test(value),
      {
        message:
          'COSMOS_PAYER_SEED must be a BIP39 mnemonic (12-24 lowercase words), ' +
          'a 64-character hex private key, or empty to disable ledger writes',
      },
    ),

  // Credo Agent
  agentLabel: z.string().default('SSI-Healthcare-Backend'),
  agentWalletId: z.string().default('ssi-healthcare-wallet'),
  agentWalletKey: z.string().min(1, 'AGENT_WALLET_KEY is required'),

  // Base URLs
  issuerBaseUrl: z.string().url().default('http://localhost:3001'),
  verifierBaseUrl: z.string().url().default('http://localhost:3001'),

  /**
   * This backend's own DID, as the AUDIENCE of presentations made to it.
   *
   * No default and never taken from the request. A verifier that lets the
   * presenter name the audience has not bound the presentation to anything —
   * the holder simply names us and replays elsewhere. Absent means the
   * professional-authority guard refuses every request (503) rather than
   * verifying against an unbound audience.
   */
  verifierDid: z.string().startsWith('did:').optional(),

  /**
   * Round 5 (WALLET-CUSTODY-NOTE.md): comma-separated allowlist of locker
   * base URLs `POST /api/wallet/locker-session` may broker a DID-authenticated
   * session against. Not open to an arbitrary caller-supplied URL — the
   * response is only a bearer token, not reflected content, so the risk this
   * bounds is a caller getting this backend to authenticate to a host of
   * their choosing, not a data-exfiltration path. Defaults to the datastore
   * locker `awaken.sh` starts locally; a self-hosted locker (staged
   * decentralisation, CLAUDE.md) is added here, not hardcoded.
   */
  walletLockerAllowedUrls: z
    .string()
    .default('http://127.0.0.1:4540')
    .transform((value) => value.split(',').map((url) => url.trim()).filter(Boolean)),

  /**
   * The institutional DID that co-controls every patient enrolled here.
   *
   * Half of the 2-of-2 AND in S-1 §8.1: `[patient RCK, institutional DID]`.
   * Absent means patient enrolment refuses with 503 rather than guessing, and
   * guessing is the one option that is definitely wrong — a controller set can
   * never be repaired (S-1 §5.4), so a DID anchored to the wrong institution is
   * unrepairable from the moment it is written.
   *
   * Provisioned by `scripts/provision-institutional-did.ts`, which is the only
   * thing that emits the 1-of-N self-controlled shape #292 requires.
   */
  institutionalDid: z.string().startsWith('did:cheqd:').optional(),

  /**
   * Who holds the patient's recovery controller key.
   *
   * `device-held-guardian-split` is the R5 Phase B answer and the only value
   * permitted outside development: the RCK is generated for one enrolment, split
   * to SLIP-39 guardians, and never enters this backend's key store.
   *
   * `backend-held-phase-a` is HONESTLY CUSTODIAL — the RCK lives in the Askar
   * store, so both halves of the 2-of-2 sit in the same building. It is retained
   * ONLY so that DIDs already minted under it can still be reasoned about, and
   * {@link assertCustodyIsPermitted} refuses it whenever `NODE_ENV` is
   * `production`. The DOCUMENT shape the two write is identical, so nothing
   * minted under Phase A needs re-issuing.
   *
   * Still no default, and still spelled out rather than boolean, so a deployment
   * cannot become custodial by leaving something unset.
   */
  patientRecoveryCustody: z
    .enum(['device-held-guardian-split', 'backend-held-phase-a'])
    .optional(),

  // R5 Phase C — guardian-share backup vault (packages/backup-vault).
  //
  // All three optional together: a deployment with no vault configured is
  // legal (the institutional share is then held only by the institution, the
  // pre-Phase-C situation), and `depositInstitutionShare` degrades to logging
  // a PENDING backup job rather than crashing enrolment. What is NOT legal is
  // configuring one of the three without the other two — see the refine below.
  backupVaultUrl: z.string().url().optional(),
  backupVaultSharedSecret: z.string().min(1).optional(),
  // 32 raw bytes, base64url. The AEAD key that encrypts a share BEFORE it
  // leaves this process — the vault never sees this value or anything
  // derived from it. Never the same value as any other secret in this file.
  backupVaultKekBase64: z
    .string()
    .optional()
    .refine((value) => value === undefined || Buffer.from(value, 'base64url').length === 32, {
      message: 'BACKUP_VAULT_KEK must decode (base64url) to exactly 32 bytes',
    }),

  /**
   * Peppers for the keystore vault's handle-based lookup (AUTH-AND-KEYSTORE-API.md §4).
   *
   * `keystoreHandlePepper` HMACs the phone handle into `KeystoreEnvelope.handleHmac`.
   * `keystoreOwnerPepper` HMACs the authenticated userId into `ownerTag`, which
   * authorises replacing an existing slot. Deliberately two separate secrets: a
   * pepper that leaked (e.g. logged with the wrong scope) would only let an
   * attacker relate handles or owners **to each other**, never invert one into
   * the phone number or userId it was derived from, and would not also expose
   * the other derivation.
   *
   * Development defaults exist so `pnpm dev` keeps working without a `.env`
   * edit; both are on `KNOWN_PLACEHOLDER_SECRETS` below and
   * `assertSecretsAreNotPlaceholders` refuses to boot in production with either
   * still set.
   */
  keystoreHandlePepper: z.string().min(16).default('dev-keystore-handle-pepper-change-in-production'),
  keystoreOwnerPepper: z.string().min(16).default('dev-keystore-owner-pepper-change-in-production'),

  // Logging
  logLevel: z.string().default('debug'),

  // WebAuthn / Passkeys
  rpId: z.string().default('localhost'),
  rpName: z.string().default('SSI Healthcare'),
  rpOrigin: z.string().url().default('http://localhost:3000'),

  // CORS
  corsOrigin: z.string().default('http://localhost:3000,http://localhost:5173'),

  // Email (SMTP) - all optional; undefined means email is disabled
  smtpHost: z.string().optional(),
  smtpPort: z.coerce.number().default(587),
  smtpUser: z.string().optional(),
  smtpPass: z.string().optional(),
  smtpFrom: z.string().default('SSI Healthcare <noreply@ssi-healthcare.local>'),
  smtpSecure: z.string().transform(v => v === 'true').default('false'),
});

type AppConfig = z.infer<typeof configSchema>;

function loadConfig(): AppConfig {
  const result = configSchema.safeParse({
    port: process.env.PORT,
    nodeEnv: process.env.NODE_ENV,
    databaseUrl: process.env.DATABASE_URL,
    bodyLimit: process.env.BODY_LIMIT,
    jwtSecret: process.env.JWT_SECRET,
    web3authClientId: process.env.WEB3AUTH_CLIENT_ID,
    web3authNetwork: process.env.WEB3AUTH_NETWORK,
    googleClientId: process.env.GOOGLE_CLIENT_ID || undefined,
    appleClientId: process.env.APPLE_CLIENT_ID || undefined,
    microsoftClientId: process.env.MICROSOFT_CLIENT_ID || undefined,
    microsoftTenantId: process.env.MICROSOFT_TENANT_ID || undefined,
    cheqdNetwork: process.env.CHEQD_NETWORK,
    cheqdRpcUrl: process.env.CHEQD_RPC_URL,
    cosmosPayerSeed: process.env.COSMOS_PAYER_SEED,
    agentLabel: process.env.AGENT_LABEL,
    agentWalletId: process.env.AGENT_WALLET_ID,
    agentWalletKey: process.env.AGENT_WALLET_KEY,
    issuerBaseUrl: process.env.ISSUER_BASE_URL,
    verifierBaseUrl: process.env.VERIFIER_BASE_URL,
    verifierDid: process.env.VERIFIER_DID || undefined,
    walletLockerAllowedUrls: process.env.WALLET_LOCKER_ALLOWED_URLS || undefined,
    institutionalDid: process.env.INSTITUTIONAL_DID || undefined,
    patientRecoveryCustody: process.env.PATIENT_RECOVERY_CUSTODY || undefined,
    backupVaultUrl: process.env.BACKUP_VAULT_URL || undefined,
    backupVaultSharedSecret: process.env.BACKUP_VAULT_SHARED_SECRET || undefined,
    backupVaultKekBase64: process.env.BACKUP_VAULT_KEK || undefined,
    keystoreHandlePepper: process.env.KEYSTORE_HANDLE_PEPPER,
    keystoreOwnerPepper: process.env.KEYSTORE_OWNER_PEPPER,
    rpId: process.env.RP_ID,
    rpName: process.env.RP_NAME,
    rpOrigin: process.env.RP_ORIGIN,
    logLevel: process.env.LOG_LEVEL,
    corsOrigin: process.env.CORS_ORIGIN,
    smtpHost: process.env.SMTP_HOST || undefined,
    smtpPort: process.env.SMTP_PORT,
    smtpUser: process.env.SMTP_USER || undefined,
    smtpPass: process.env.SMTP_PASS || undefined,
    smtpFrom: process.env.SMTP_FROM,
    smtpSecure: process.env.SMTP_SECURE,
  });

  if (!result.success) {
    const formatted = result.error.format();
    console.error('Configuration validation failed:', JSON.stringify(formatted, null, 2));
    process.exit(1);
  }

  const cfg = result.data;
  if (cfg.smtpHost && (!cfg.smtpUser || !cfg.smtpPass)) {
    console.warn('[config] SMTP_HOST is set but SMTP_USER or SMTP_PASS is missing — email sending may fail');
  }
  const vaultFieldsSet = [cfg.backupVaultUrl, cfg.backupVaultSharedSecret, cfg.backupVaultKekBase64].filter(
    (v) => v !== undefined,
  ).length;
  if (vaultFieldsSet > 0 && vaultFieldsSet < 3) {
    console.error(
      '[config] BACKUP_VAULT_URL, BACKUP_VAULT_SHARED_SECRET and BACKUP_VAULT_KEK must be set ' +
        'together or not at all — a partially configured vault client is worse than none.',
    );
    process.exit(1);
  }

  assertSecretsAreNotPlaceholders(cfg);
  assertCustodyIsPermitted(cfg);
  assertKeystorePeppersAreDistinct(cfg);

  return cfg;
}

/**
 * Same reasoning as `packages/locker/src/config.ts`'s pepper/secret check: one
 * pepper pseudonymises the handle, the other the owner, and sharing a value
 * would couple two blast radii that are deliberately kept separate.
 */
function assertKeystorePeppersAreDistinct(cfg: AppConfig): void {
  if (cfg.keystoreHandlePepper === cfg.keystoreOwnerPepper) {
    console.error(
      '[config] KEYSTORE_HANDLE_PEPPER and KEYSTORE_OWNER_PEPPER must differ. One ' +
        'pseudonymises the phone handle, the other the authenticated account; sharing a ' +
        'value would let anyone who recovers one pepper invert the other derivation too.',
    );
    process.exit(1);
  }
}

/**
 * R5 Phase B: `backend-held-phase-a` is no longer reachable in production.
 *
 * The value is not deleted, because DIDs minted under it exist and an operator
 * reading a log line naming it must still find something that explains it. What
 * changes is that it can no longer be SELECTED where it would matter: the
 * process refuses to start.
 *
 * FAILS AT STARTUP, NOT AT FIRST ENROLMENT. A custodial deployment that boots
 * and then refuses each patient individually is a deployment someone quietly
 * reverts under pressure at 2am. One loud refusal at boot, before any patient
 * exists, is the smaller damage surface.
 */
function assertCustodyIsPermitted(cfg: AppConfig): void {
  if (cfg.nodeEnv === 'production' && cfg.patientRecoveryCustody === 'backend-held-phase-a') {
    console.error(
      '[config] PATIENT_RECOVERY_CUSTODY=backend-held-phase-a is refused in production.\n' +
        '  It puts the patient recovery key in this backend\'s Askar store, so both halves\n' +
        '  of the 2-of-2 controller set are held by one party and the sovereignty claim is\n' +
        '  false. R5 Phase B replaced it with device-held-guardian-split, which writes the\n' +
        '  IDENTICAL document shape — so nothing minted under Phase A needs re-issuing and\n' +
        '  there is no migration to schedule.\n\n' +
        '  Set PATIENT_RECOVERY_CUSTODY=device-held-guardian-split.',
    );
    process.exit(1);
  }
}

/**
 * Exact placeholder secrets that have been published in this repository.
 * `.env.production` was byte-identical to `.env.example`, so these strings are
 * public knowledge and must never protect a running system.
 */
const KNOWN_PLACEHOLDER_SECRETS: readonly string[] = [
  'change-this-to-a-secure-random-string-at-least-32-chars',
  'change-this-to-a-secure-key-in-production',
  'change-this-staging-jwt-secret-at-least-32-chars',
  'change-this-staging-key',
  'dev-jwt-secret-change-in-staging-min-32-chars-xxxxx',
  'dev-wallet-key-change-in-staging',
  'dev-keystore-handle-pepper-change-in-production',
  'dev-keystore-owner-pepper-change-in-production',
];

/**
 * Patterns that indicate a value was copied from a template and never replaced.
 * `JWT_SECRET` passes `z.string().min(32)` at 55 characters while still being
 * the published example value, so length alone proves nothing.
 */
const PLACEHOLDER_PATTERNS: readonly RegExp[] = [
  /change[-_]?this/i,
  /change[-_]?in[-_]?(staging|production)/i,
  /^dev[-_]/i,
  /^(changeme|secret|password|test|example|placeholder)$/i,
  /your[-_]?(secret|key)[-_]?here/i,
];

function isPlaceholderSecret(value: string): boolean {
  if (KNOWN_PLACEHOLDER_SECRETS.includes(value)) return true;
  return PLACEHOLDER_PATTERNS.some((pattern) => pattern.test(value));
}

/**
 * Refuse to start with template secrets.
 *
 * JWT_SECRET signs the OID4VCI access tokens that gate credential claims, and
 * AGENT_WALLET_KEY unlocks the agent wallet holding the issuer's signing keys.
 * A known value for either lets anyone mint tokens or impersonate the issuer.
 *
 * In production this is fatal. Outside production it is a loud warning rather
 * than a hard stop, so that local development and CI keep working with the
 * committed sample values — a check that blocks `pnpm dev` is a check someone
 * will delete. Deployment environments must set real secrets.
 */
function assertSecretsAreNotPlaceholders(cfg: AppConfig): void {
  const offenders: string[] = [];

  if (isPlaceholderSecret(cfg.jwtSecret)) offenders.push('JWT_SECRET');
  if (isPlaceholderSecret(cfg.agentWalletKey)) offenders.push('AGENT_WALLET_KEY');
  if (isPlaceholderSecret(cfg.keystoreHandlePepper)) offenders.push('KEYSTORE_HANDLE_PEPPER');
  if (isPlaceholderSecret(cfg.keystoreOwnerPepper)) offenders.push('KEYSTORE_OWNER_PEPPER');

  if (offenders.length === 0) return;

  const detail =
    `${offenders.join(' and ')} ${offenders.length === 1 ? 'is' : 'are'} still set to a ` +
    'placeholder value from the environment template. These values are committed ' +
    'to the repository and are therefore public.';

  if (cfg.nodeEnv === 'production') {
    console.error(
      `[config] FATAL: ${detail} Refusing to start. ` +
      'Generate replacements, for example: openssl rand -hex 32'
    );
    process.exit(1);
  }

  console.warn(
    `[config] WARNING: ${detail} This is tolerated because NODE_ENV=${cfg.nodeEnv}, ` +
    'but startup will fail when NODE_ENV=production.'
  );
}

export const config = loadConfig();
