/**
 * Turn a thrown error into something a holder can act on, and keep the raw
 * text out of the interface.
 *
 * ===========================================================================
 * WHY
 * ===========================================================================
 * Nine screens rendered `error.message` directly. What reached the holder was
 * text written for whoever was debugging it:
 *
 *   "Request failed with status 401 at /api/users/me/credentials"
 *   "Could not read your credentials (AUTH_TOKEN_EXPIRED): Invalid or expired
 *    session"
 *
 * Neither names anything the holder can do, both name internals they should
 * not have to think about, and the second appeared on a screen that was at
 * that moment displaying the credential it claimed it could not read.
 *
 * The raw text is not discarded, it is redirected: it goes to the dev client,
 * where the person who can act on it is looking.
 *
 * The mapping is deliberately coarse. A holder needs to know which of three
 * things to do: wait and retry, sign in again, or report it. Anything finer is
 * detail they cannot use.
 */

export interface FailureDescription {
  /** One sentence, plain, no identifiers, no status codes. */
  readonly message: string;
  /** True when retrying might work. Drives whether a retry control is shown. */
  readonly retryable: boolean;
}

const NETWORK = /network request failed|fetch failed|timeout|timed out|ECONN|ENOTFOUND|unreachable|offline/i;
const AUTH = /401|unauthor|AUTH_TOKEN|session expired|invalid or expired|not authenticated/i;
const RATE = /429|too many|rate limit/i;
const NOTFOUND = /404|not found/i;
const SERVER = /50[0-9]|internal server/i;

export function describeFailure(error: unknown, action = 'do that'): FailureDescription {
  const raw = error instanceof Error ? error.message : String(error ?? '');

  // The one place the detail is allowed to exist.
  if (__DEV__) {
    // eslint-disable-next-line no-console
    console.warn(`[failure] while trying to ${action}:`, raw);
  }

  if (NETWORK.test(raw)) {
    return {
      message: 'No connection. Check your network and try again.',
      retryable: true,
    };
  }
  if (AUTH.test(raw)) {
    return {
      message: 'Your session has ended. Sign in again to continue.',
      retryable: false,
    };
  }
  if (RATE.test(raw)) {
    return {
      message: 'Too many attempts. Wait a few minutes and try again.',
      retryable: true,
    };
  }
  if (NOTFOUND.test(raw)) {
    return {
      message: `Could not find what was needed to ${action}.`,
      retryable: false,
    };
  }
  if (SERVER.test(raw)) {
    return {
      message: 'The service is having trouble. Try again shortly.',
      retryable: true,
    };
  }
  // Unrecognised. Says what failed and admits the cause is unknown, rather
  // than inventing one or pasting the original.
  return {
    message: `Could not ${action}. Try again, and report it if it keeps happening.`,
    retryable: true,
  };
}

/** Convenience for call sites that only need the sentence. */
export function failureMessage(error: unknown, action?: string): string {
  return describeFailure(error, action).message;
}
