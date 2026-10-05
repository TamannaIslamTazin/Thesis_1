import { useCallback, useEffect, useReducer, useRef } from 'react';
import { getRequestDetail, type RequestDetail, type WrappedContentKey } from '@/lib/api';

/**
 * State machine for one submission's single-use content-key release
 * (IDENTITY-VERIFICATION-API.md §5: "GET releases the wrapped content key on
 * the first read; a second request returns the submission without the key").
 *
 * The backend already enforces single use with a compare-and-swap on
 * `keyReleasedAt`. This machine is the client-side half: it makes a second
 * *call* structurally unreachable from the UI, rather than reachable-but-
 * refused. `release` only appears on the `idle` and `error` variants of
 * {@link ReleaseState} — once the state is `releasing` or `released`, the
 * type returned to a component has no `release` field at all, so a caller
 * that narrows on `status` before calling it cannot compile a second call.
 * A caller that ignores the discriminant and holds a stale reference to an
 * old `release` closure is still caught by {@link useSingleUseKeyRelease}'s
 * own one-shot ref guard below, which does not depend on the caller's
 * behaviour.
 */
export type ReleaseState =
  | { readonly status: 'idle' }
  | { readonly status: 'releasing' }
  | { readonly status: 'released'; readonly detail: RequestDetail; readonly key: WrappedContentKey | null }
  | { readonly status: 'error'; readonly message: string };

type ReleaseAction =
  | { readonly type: 'START' }
  | {
      readonly type: 'SUCCESS';
      readonly detail: RequestDetail;
      /**
       * The key to hold, decided by the caller rather than read off `detail`.
       * A reload spends nothing at the backend but also receives nothing, so
       * the caller merges the cached copy in here — see {@link readCachedKey}.
       */
      readonly key: WrappedContentKey | null;
    }
  | { readonly type: 'FAILURE'; readonly message: string };

export function releaseReducer(state: ReleaseState, action: ReleaseAction): ReleaseState {
  switch (action.type) {
    case 'START':
      // Only 'idle' and 'error' may start a release. A release already in
      // flight or already completed ignores a second START rather than
      // restarting — restarting would be indistinguishable from a second
      // call at the network layer, which is exactly what must not happen.
      if (state.status === 'idle' || state.status === 'error') {
        return { status: 'releasing' };
      }
      return state;
    case 'SUCCESS':
      if (state.status !== 'releasing') return state;
      return {
        status: 'released',
        detail: action.detail,
        // May be null: `keyReleased` was already true before this call and no
        // cached copy exists on this device (a second officer opening the same
        // request, or a different browser). The UI must show "already released
        // by someone else" rather than treat an absent key as an error.
        key: action.key,
      };
    case 'FAILURE':
      if (state.status !== 'releasing') return state;
      return { status: 'error', message: action.message };
  }
}

/**
 * `tryClaim()` returns `true` exactly once per guard instance; every call
 * after that returns `false` without side effects. Extracted so the
 * one-shot property {@link useSingleUseKeyRelease} relies on is unit-testable
 * without mounting a component.
 */
export function createOnceGuard(): { tryClaim: () => boolean; reset: () => void } {
  let claimed = false;
  return {
    tryClaim: () => {
      if (claimed) return false;
      claimed = true;
      return true;
    },
    reset: () => {
      claimed = false;
    },
  };
}

/**
 * ===========================================================================
 * THE RELEASED KEY SURVIVES A RELOAD, IN sessionStorage
 * ===========================================================================
 * This module deliberately persisted nothing until 9 Sep 2026. That was the
 * wrong call, and the reason is worth writing down because the instinct that
 * produced it is a good one applied to the wrong asymmetry.
 *
 * The key is spent at the BACKEND on first read — `UPDATE ... WHERE
 * keyReleasedAt IS NULL`, committed before the response is built (#384). So
 * the officer gets exactly one chance to receive it. Holding it only in React
 * state meant a page reload, an accidental back-navigation, or a dev-server
 * hot reload destroyed the one copy in existence, and the submitted document
 * became permanently undecryptable BY ANYONE: the holder's capability names
 * that authority, the backend will not re-release, and the officer can only
 * reject a request whose contents they can no longer see. That is an
 * unrecoverable availability failure, and #276's ruling applies — an
 * unrecoverable failure mode loses to a recoverable one even at the cost of
 * the stronger property.
 *
 * What is actually given up is small and bounded:
 *   - `sessionStorage`, not `localStorage`: the copy dies with the TAB. It
 *     does not survive the browser closing and is not shared with another tab.
 *   - It holds the WRAPPED key, exactly as the backend sent it. Unwrapping
 *     still needs `ISSUER_LOCKER_SIGNING_SEED`, which lives on the console's
 *     own server and never reaches the browser. A reader of this storage
 *     alone decrypts nothing.
 *   - It is erased the moment the request leaves the officer's hands
 *     ({@link clearCachedKey}, called on approve and on reject), so the window
 *     is the review itself and not the working day.
 *
 * It is NOT a way around single use: nothing here re-requests the key, and the
 * backend would refuse if it did.
 */
const CACHE_PREFIX = 'bdht.issuer-console.released-key.';

function cacheKeyFor(requestId: string): string {
  return `${CACHE_PREFIX}${requestId}`;
}

/**
 * Every access is wrapped: `sessionStorage` throws outright in some privacy
 * modes, and a storage fault must degrade to "no cache" rather than break the
 * review. It is also absent entirely during server rendering.
 */
export function readCachedKey(requestId: string): WrappedContentKey | null {
  if (typeof window === 'undefined') return null;
  try {
    const raw = window.sessionStorage.getItem(cacheKeyFor(requestId));
    if (!raw) return null;
    return JSON.parse(raw) as WrappedContentKey;
  } catch {
    return null;
  }
}

export function writeCachedKey(requestId: string, key: WrappedContentKey): void {
  if (typeof window === 'undefined') return;
  try {
    window.sessionStorage.setItem(cacheKeyFor(requestId), JSON.stringify(key));
  } catch {
    // Quota or a blocked store. The officer keeps the in-memory copy for as
    // long as the page lives; only reload-survival is lost, and silently
    // losing that is better than failing the release that already succeeded.
  }
}

export function clearCachedKey(requestId: string): void {
  if (typeof window === 'undefined') return;
  try {
    window.sessionStorage.removeItem(cacheKeyFor(requestId));
  } catch {
    // Nothing to do. See writeCachedKey.
  }
}

export interface UseSingleUseKeyRelease {
  readonly state: ReleaseState;
  /** Present only while a release can legitimately be started. */
  readonly release?: () => void;
}

/**
 * One release per hook instance, enforced twice over:
 *
 *   1. STRUCTURALLY: `release` is omitted from the returned object once
 *      `state.status` leaves `idle`/`error`, so `const { release } = ...`
 *      destructured once at render time goes stale and a component that
 *      re-reads the hook's return value each render cannot get a fresh
 *      `release` back after a release has started.
 *   2. AT THE CALL SITE: `calledRef` below refuses a second invocation of
 *      the same closure even if a component holds on to it anyway (e.g. in
 *      an event handler captured before the state changed) — this does not
 *      rely on React re-rendering to be the enforcement mechanism.
 *
 * A released key is cached in `sessionStorage` and re-adopted on mount, so a
 * reload does not destroy the only copy of a key the backend will never issue
 * again — see the block above {@link readCachedKey} for why that trade is the
 * right way round. Re-adoption claims the one-shot guard too, so hydrating
 * from cache cannot be followed by a network release.
 */
export function useSingleUseKeyRelease(requestId: string): UseSingleUseKeyRelease {
  const [state, dispatch] = useReducer(releaseReducer, { status: 'idle' } as ReleaseState);
  const guardRef = useRef(createOnceGuard());

  const release = useCallback(() => {
    if (!guardRef.current.tryClaim()) return;
    dispatch({ type: 'START' });
    getRequestDetail(requestId)
      .then((detail) => {
        // The key comes from THIS response when the backend released it, and
        // from the cache when it did not — a reload after a release reads a
        // detail with no key, and that is the case the cache exists for.
        // Preferring the response keeps the fresh value authoritative.
        const key = detail.wrappedContentKey ?? readCachedKey(requestId);
        if (detail.wrappedContentKey) writeCachedKey(requestId, detail.wrappedContentKey);
        dispatch({ type: 'SUCCESS', detail, key: key ?? null });
      })
      .catch((error: unknown) => {
        // A failed release is retriable: reset the guard so a network error
        // (as opposed to "the key was already spent") does not permanently
        // strand the officer with no way to try again.
        guardRef.current.reset();
        dispatch({ type: 'FAILURE', message: error instanceof Error ? error.message : String(error) });
      });
  }, [requestId]);

  // Re-adopt a key this browser tab already holds, WITHOUT asking the backend
  // to release anything — the request that spent it happened before the
  // reload. The guard is claimed first so the automatic path and a manual
  // "reveal" can never both run.
  useEffect(() => {
    if (!readCachedKey(requestId)) return;
    if (!guardRef.current.tryClaim()) return;
    dispatch({ type: 'START' });
    getRequestDetail(requestId)
      .then((detail) => {
        const key = detail.wrappedContentKey ?? readCachedKey(requestId);
        if (detail.wrappedContentKey) writeCachedKey(requestId, detail.wrappedContentKey);
        dispatch({ type: 'SUCCESS', detail, key: key ?? null });
      })
      .catch((error: unknown) => {
        guardRef.current.reset();
        dispatch({ type: 'FAILURE', message: error instanceof Error ? error.message : String(error) });
      });
  }, [requestId]);

  if (state.status === 'idle' || state.status === 'error') {
    return { state, release };
  }
  return { state };
}
