/**
 * SSI Healthcare Backend — who is asking, carried without threading it.
 *
 * The signing services take an `Agent` and a spec; they do not take an Express
 * `Request`, and they must not start to. But #277/#293 require the signing log
 * to record source IP and device, which only the transport knows. An
 * `AsyncLocalStorage` is the seam: the presentation layer PUTS the context in,
 * the domain layer READS an interface, and neither imports the other.
 *
 * ABSENCE IS A VALUE, NOT A NULL. A signing operation run from a script or a
 * test genuinely has no IP, and that is different from an HTTP request whose IP
 * we failed to capture. `actorSource` distinguishes them so a reader of the log
 * never has to guess which happened.
 */

import { AsyncLocalStorage } from 'node:async_hooks';
import { randomUUID } from 'node:crypto';

export type ActorSource =
  /** An authenticated HTTP request reached the signing path. */
  | 'http'
  /** A CLI script, a migration, a probe. No transport, so no IP by definition. */
  | 'process'
  /** The regression suite. Kept distinct so live-test rows never read as real. */
  | 'test'
  /** An HTTP request whose context the middleware failed to establish. */
  | 'unknown';

export interface ActorContext {
  readonly source: ActorSource;
  /**
   * Filled in by `requireAuth`, not by the context middleware.
   *
   * The middleware runs globally, before any per-route authentication, so the
   * identity is not known when the context is created. This is the one mutable
   * field, and it is mutable so that the IP and device — which only the
   * transport knows and only the outermost middleware can see — do not have to
   * be re-derived deeper in the stack just to attach a user id.
   */
  userId?: string;
  readonly sourceIp?: string;
  readonly userAgent?: string;
  /** Inherited at the true entry point, never regenerated mid-flight. */
  readonly requestId: string;
}

const storage = new AsyncLocalStorage<ActorContext>();

/**
 * Name the authenticated user on the ambient context.
 *
 * Set-once: an already-identified request being re-identified means two
 * authentications collided on one context, which would make the audit log
 * attribute a signature to whoever won the race.
 */
export function attachActorUserId(userId: string): void {
  const store = storage.getStore();
  if (!store || store.userId) return;
  store.userId = userId;
}

/**
 * What a signing operation records when nothing established a context.
 *
 * `'process'` rather than `'unknown'`: reaching a service function with no
 * ambient context is the normal shape of a script, and calling that "unknown"
 * would cry wolf on every legitimate one. The HTTP middleware always sets a
 * context, so an HTTP request can never land here.
 */
export function currentActorContext(): ActorContext {
  return storage.getStore() ?? { source: 'process', requestId: `process-${randomUUID()}` };
}

export function runWithActorContext<T>(context: ActorContext, fn: () => T): T {
  return storage.run(context, fn);
}

/** Build a context from the request-shaped fields the transport can supply. */
export function actorContextFromRequest(input: {
  readonly ip?: string;
  readonly userAgent?: string;
  readonly userId?: string;
  readonly requestId?: string;
}): ActorContext {
  return {
    source: 'http',
    userId: input.userId,
    sourceIp: input.ip,
    userAgent: input.userAgent,
    requestId: input.requestId ?? randomUUID(),
  };
}
