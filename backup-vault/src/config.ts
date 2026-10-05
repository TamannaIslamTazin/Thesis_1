/**
 * R5 Phase C — vault configuration. Fails fast: an unset secret is refused at
 * startup, not discovered the first time a request needs it (same posture as
 * `packages/backend/src/config/index.ts`).
 */

export interface VaultConfig {
  readonly port: number;
  readonly dbPath: string;
  /** Bearer token the backend must present. Compared in constant time — see crypto.ts. */
  readonly sharedSecret: string;
  /**
   * HMAC key used ONLY to pseudonymise the subject reference written into
   * `erasure_receipts` (amendment 3). Deliberately a second secret, not the
   * backend's KEK and not the auth token — this key never protects anything
   * an attacker could decrypt, so mixing its blast radius with a secret that
   * does would be pointless coupling.
   */
  readonly pepperKey: string;
}

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value || value.trim().length === 0) {
    throw new Error(
      `${name} is not set. The vault refuses to start rather than run with an absent secret ` +
        '— an unauthenticated or unpseudonymised vault is a worse failure than a vault that ' +
        'will not boot.',
    );
  }
  return value;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): VaultConfig {
  const port = Number(env.VAULT_PORT ?? '4530');
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new Error(`VAULT_PORT must be a valid TCP port, got '${env.VAULT_PORT}'.`);
  }

  const sharedSecret = requireEnv('VAULT_SHARED_SECRET');
  const pepperKey = requireEnv('VAULT_PEPPER_KEY');
  if (sharedSecret === pepperKey) {
    throw new Error(
      'VAULT_SHARED_SECRET and VAULT_PEPPER_KEY must differ. One authenticates callers, the ' +
        'other pseudonymises erasure receipts; sharing a value couples two unrelated blast radii.',
    );
  }

  return {
    port,
    dbPath: env.VAULT_DB_PATH ?? '/data/vault.sqlite',
    sharedSecret,
    pepperKey,
  };
}
