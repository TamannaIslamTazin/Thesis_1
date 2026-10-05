/**
 * `@ssi-healthcare/sdk/verifier` — the relying-party half, under its target name.
 *
 * An alias, deliberately. The target layout calls this module `verifier`, but
 * `@ssi-healthcare/sdk/verify` is already public API that the health-dashboard
 * consumes. Renaming it would break an integrator to satisfy a naming
 * convention. So both names resolve to the same code, `verify` stays supported,
 * and new integrations are pointed here.
 *
 * There is no second implementation behind this file and there must never be:
 * it re-exports `../verify`, so the two names cannot drift. Adding a symbol here
 * that `../verify` does not have would reintroduce exactly the divergence the
 * SDK move exists to end (steno #341, where two verifiers had already drifted on
 * key binding).
 */
export * from '../verify';
