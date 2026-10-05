/**
 * Locker configuration. Fails fast on an absent secret, same posture as the
 * Phase C vault: a locker that will not boot is a smaller problem than a
 * locker running without authentication or without a pepper.
 *
 * ===========================================================================
 * THE SELF-HOSTED PATH IS THIS FILE, AND NOTHING ELSE
 * ===========================================================================
 * #340's reason for choosing MinIO was architectural, not about storage: an
 * S3-compatible API makes "my own server in my own house" and "the ministry
 * cluster" the SAME CLIENT CODE, so the self-hosted option costs nothing
 * extra and the ministry locker never becomes the only path.
 *
 * That promise is kept here or not at all. There is exactly one code path to
 * object storage; which endpoint it talks to is four environment variables.
 * A user hosting their own locker runs THE SAME IMAGE with a different .env,
 * and the wallet points at a different URL. If a future change ever adds an
 * `if (isMinistryDeployment)` branch, the promise is broken and the thesis
 * claim about non-centralisation goes with it.
 */

import { policyForRole, type LockerPolicy } from './policy.js';

export interface LockerConfig {
  readonly port: number;
  readonly policy: LockerPolicy;
  readonly dbPath: string;

  /** S3 endpoint. A ministry cluster or a container on the user's own machine. */
  readonly s3Endpoint: string;
  readonly s3Region: string;
  readonly s3AccessKeyId: string;
  readonly s3SecretAccessKey: string;
  readonly s3Bucket: string;
  /**
   * MinIO serves buckets as a path (`host/bucket/key`) rather than as a
   * subdomain, which is what AWS defaults to. Forced on: virtual-host style
   * against MinIO fails in a way that looks like a credentials problem.
   */
  readonly s3ForcePathStyle: boolean;

  /**
   * Where DID documents are resolved from — the cheqd Cosmos REST API.
   *
   * Deliberately NOT a Credo agent. The only DID-document signature check in
   * this monorepo goes through `agent.dids.resolveDidDocument` plus Credo's
   * KMS, which means an agent, a wallet and askar. Embedding that in a
   * container a USER SELF-HOSTS would be indefensible, so the locker resolves
   * over plain HTTP and verifies with @noble/curves.
   */
  readonly didResolverUrl: string;
  readonly didResolverTimeoutMs: number;

  /**
   * Pseudonymises DIDs before they become object key prefixes or receipt
   * subjects. A raw DID in an object key would let the operator enumerate who
   * holds a locker and how many objects each has, purely from a bucket
   * listing — the operator cannot read the bytes but should not get a census
   * for free either.
   */
  readonly subjectPepper: string;

  /**
   * How often housekeeping runs, and how old an incomplete upload must be
   * before the reaper takes it.
   *
   * Overridable because the production defaults (15 minutes, and a six-hour
   * TTL for the datastore) are deliberately far too slow to observe in a
   * verification run — and a reaper nobody can watch work is a reaper nobody
   * can prove works. Lowering the TTL in production would be dangerous: an
   * upload still in flight is indistinguishable from an abandoned one except
   * by age, so a short TTL reaps live uploads and causes the failure it exists
   * to contain.
   */
  readonly housekeepingIntervalMs: number;
  readonly abandonedUploadTtlMsOverride: number | null;
}

function requireEnv(name: string, env: NodeJS.ProcessEnv): string {
  const value = env[name];
  if (!value || value.trim().length === 0) {
    throw new Error(
      `${name} is not set. The locker refuses to start rather than run with an absent ` +
        'secret — an unauthenticated or unpseudonymised locker is a worse failure than ' +
        'one that will not boot.',
    );
  }
  return value;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): LockerConfig {
  const port = Number(env.LOCKER_PORT ?? '4540');
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new Error(`LOCKER_PORT must be a valid TCP port, got '${env.LOCKER_PORT}'.`);
  }

  const policy = policyForRole(env.LOCKER_ROLE ?? '');
  const subjectPepper = requireEnv('LOCKER_SUBJECT_PEPPER', env);
  const s3SecretAccessKey = requireEnv('LOCKER_S3_SECRET_ACCESS_KEY', env);

  if (subjectPepper === s3SecretAccessKey) {
    throw new Error(
      'LOCKER_SUBJECT_PEPPER and LOCKER_S3_SECRET_ACCESS_KEY must differ. One pseudonymises ' +
        'subjects, the other authenticates to object storage; sharing a value couples two ' +
        'unrelated blast radii.',
    );
  }

  return {
    port,
    policy,
    dbPath: env.LOCKER_DB_PATH ?? '/data/locker.sqlite',
    s3Endpoint: requireEnv('LOCKER_S3_ENDPOINT', env),
    s3Region: env.LOCKER_S3_REGION ?? 'us-east-1',
    s3AccessKeyId: requireEnv('LOCKER_S3_ACCESS_KEY_ID', env),
    s3SecretAccessKey,
    s3Bucket: requireEnv('LOCKER_S3_BUCKET', env),
    s3ForcePathStyle: (env.LOCKER_S3_FORCE_PATH_STYLE ?? 'true') !== 'false',
    didResolverUrl: requireEnv('LOCKER_DID_RESOLVER_URL', env),
    didResolverTimeoutMs: Number(env.LOCKER_DID_RESOLVER_TIMEOUT_MS ?? '5000'),
    subjectPepper,
    housekeepingIntervalMs: Number(env.LOCKER_HOUSEKEEPING_INTERVAL_MS ?? String(15 * 60 * 1000)),
    abandonedUploadTtlMsOverride:
      env.LOCKER_ABANDONED_UPLOAD_TTL_MS === undefined
        ? null
        : Number(env.LOCKER_ABANDONED_UPLOAD_TTL_MS),
  };
}

/** The TTL actually in force: the override if one is set, else the role's default. */
export function abandonedUploadTtlMs(config: LockerConfig): number {
  return config.abandonedUploadTtlMsOverride ?? config.policy.abandonedUploadTtlMs;
}
