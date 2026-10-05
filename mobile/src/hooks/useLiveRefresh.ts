/**
 * Re-run a check when the screen is focused AND when the app returns from the
 * background.
 *
 * ===========================================================================
 * FOCUS ALONE IS NOT ENOUGH, AND MOUNT ALONE IS MUCH WORSE
 * ===========================================================================
 * Screens showing something that can change WITHOUT the user acting — an
 * emergency grant raised by a hospital, a credential offer created by an
 * authority — cannot fetch on mount and stop. A tab screen stays mounted for
 * the life of the session, so "on mount" means "once, hours ago".
 *
 * `useFocusEffect` fixes navigating away and back. It does NOT fire when the
 * whole app is backgrounded and brought forward again, because the screen never
 * lost navigation focus: React Navigation saw nothing happen. That is the
 * ordinary case for a phone in a pocket.
 *
 * Measured 9 Sep 2026: a hospital opened a patient's records through the HMS
 * while the wallet sat on the emergency screen in the background. Bringing the
 * phone out showed "No Active Emergency Access" — the exact opposite of the
 * truth, on the one screen whose whole purpose is to say otherwise, and the
 * screen a patient would check precisely because they suspected something.
 *
 * Under an auto-grant model detection latency IS the security control, so a
 * stale "nothing is happening" is not a cosmetic problem.
 */
import { useCallback, useEffect, useMemo, useRef } from 'react';
import { AppState, type AppStateStatus } from 'react-native';
import { useFocusEffect } from '@react-navigation/native';

export function useLiveRefresh(
  refresh: () => void | Promise<void>,
  options: { readonly onFocus?: boolean } = {},
): void {
  // Kept in a ref so a caller passing an inline closure does not re-subscribe
  // on every render — the subscription's identity must not depend on theirs.
  const refreshRef = useRef(refresh);
  refreshRef.current = refresh;

  const run = useCallback(() => {
    void refreshRef.current();
  }, []);

  // `onFocus: false` keeps the return-from-background edge but drops the
  // focus edge. Use it for data that must be re-checked whenever the holder
  // comes back to the app, but is expensive to refetch on every tab switch —
  // the credential status is exactly that: revocation matters after the phone
  // has been in a pocket, not after tapping between tabs.
  const focusEffect = useMemo(
    () => (options.onFocus === false ? () => {} : run),
    [options.onFocus, run],
  );
  useFocusEffect(focusEffect);

  useEffect(() => {
    const previous = { state: AppState.currentState };
    const subscription = AppState.addEventListener('change', (next: AppStateStatus) => {
      // Only the background -> active EDGE. 'active' also arrives on transient
      // states (a permission dialog, the notification shade), and refreshing on
      // every one of those would hammer the endpoint and, on this backend, spend
      // the auth rate limit that recovery itself needs.
      const returned = /inactive|background/.test(previous.state) && next === 'active';
      previous.state = next;
      if (returned) run();
    });
    return () => subscription.remove();
  }, [run]);
}
