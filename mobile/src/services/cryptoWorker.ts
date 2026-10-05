/**
 * CPU-bound crypto on a worker runtime's thread, so the UI stays alive.
 *
 * The wallet's scrypt (N=2^15, r=8, p=1) takes seconds per derivation — 275 ms
 * for this port on a workstation, **37.4 s on the handset through this worker**
 * (20 Sep 2026, parity MATCH at N=256 against the RN-side noble) — and on the
 * single RN JS thread it would freeze the screen for the whole derivation.
 * This module moves it to a `createWorkletRuntime` thread (probe-confirmed
 * available, no new native dependency) executing the ported noble subset in
 * `@ssi-healthcare/shared/worklet-crypto`.
 *
 * RANDOMNESS STAYS ON THE RN SIDE. The worker runtime has no `crypto` global
 * (probe: TextEncoder=true, crypto=false), which is deliberate here: scrypt,
 * PBKDF2 and HMAC need no entropy at all, and anything that does (salts, IVs,
 * ephemeral keys) is generated here and passed in as bytes. That keeps the
 * worker free of a random source rather than shipping a weakened one into it.
 *
 * UNTIL THIS IS ADOPTED, `passphraseEnvelope` keeps its noble path on the RN
 * thread; a caller switches to `scryptOffThread` only after the on-device
 * parity check passes (see probes/workletCryptoProbe.ts), and the derived key
 * must match the RN path bit-for-bit because it wraps keys that already exist.
 */
import {
  createWorkletRuntime,
  scheduleOnRuntime,
  scheduleOnRN,
  type WorkletRuntime,
} from 'react-native-worklets';
import { scrypt as scryptOnRuntime } from '@ssi-healthcare/shared/worklet-crypto';

export interface ScryptParams {
  N: number;
  r: number;
  p: number;
  dkLen: number;
}

export interface ScryptWorkerResult {
  derived: Uint8Array;
  /** Time inside the worker, measured with the runtime's own performance.now. */
  workerMs: number;
  /** Wall time from dispatch to settlement, including the runtime hop. */
  roundTripMs: number;
}

interface PendingCall {
  startedAt: number;
  resolve: (result: ScryptWorkerResult) => void;
  reject: (error: Error) => void;
}

let runtime: WorkletRuntime | null = null;
let nextId = 0;
const pending = new Map<number, PendingCall>();

/**
 * Settlement, called from the worker via `scheduleOnRN`. Module scope on
 * purpose: the worklet passes a reference, so the function must be reachable
 * by the same name on both sides.
 */
function settle(
  id: number,
  ok: boolean,
  message: string,
  bytes: number[],
  workerMs: number,
): void {
  const call = pending.get(id);
  if (!call) return;
  pending.delete(id);
  if (!ok) {
    call.reject(new Error(message || 'crypto worker failed'));
    return;
  }
  call.resolve({
    derived: Uint8Array.from(bytes),
    workerMs,
    roundTripMs: Date.now() - call.startedAt,
  });
}

/**
 * The scheduled unit of work. Everything it touches is either a captured value
 * or a workletized import; the ported scrypt carries its own directives,
 * which is why the Metro resolver points this import at SOURCE (see
 * metro.config.js) — the Babel plugin has to see those files.
 */
function scryptJob(
  id: number,
  password: number[],
  salt: number[],
  N: number,
  r: number,
  p: number,
  dkLen: number,
): void {
  'worklet';
  const started = performance.now();
  try {
    const derived = scryptOnRuntime(new Uint8Array(password), new Uint8Array(salt), {
      N,
      r,
      p,
      dkLen,
    });
    scheduleOnRN(settle, id, true, '', Array.from(derived), performance.now() - started);
  } catch (error) {
    scheduleOnRN(
      settle,
      id,
      false,
      String((error as Error)?.message ?? error),
      [],
      performance.now() - started,
    );
  }
}

function getRuntime(): WorkletRuntime {
  if (!runtime) {
    runtime = createWorkletRuntime({
      name: 'crypto',
      initializer: () => {
        'worklet';
        console.log('[crypto-worker] runtime ready');
      },
    });
  }
  return runtime;
}

/** True once the first call has created the runtime; cheap to log at a boundary. */
export function isCryptoWorkerStarted(): boolean {
  return runtime !== null;
}

/**
 * Derive a key with scrypt on the worker thread.
 *
 * Inputs are copied to plain number arrays because they are the shareable
 * representation the runtime accepts; 16–64 byte inputs make the encoding cost
 * irrelevant next to the derivation itself.
 */
export function scryptOffThread(
  password: Uint8Array,
  salt: Uint8Array,
  params: ScryptParams,
): Promise<ScryptWorkerResult> {
  const id = (nextId += 1);
  return new Promise<ScryptWorkerResult>((resolve, reject) => {
    pending.set(id, { startedAt: Date.now(), resolve, reject });
    try {
      scheduleOnRuntime(
        getRuntime(),
        scryptJob,
        id,
        Array.from(password),
        Array.from(salt),
        params.N,
        params.r,
        params.p,
        params.dkLen,
      );
    } catch (error) {
      pending.delete(id);
      reject(error instanceof Error ? error : new Error(String(error)));
    }
  });
}
