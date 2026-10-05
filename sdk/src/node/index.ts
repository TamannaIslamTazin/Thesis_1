/**
 * `sdk/node` — adapters that genuinely need Node, and the guard's forbidden target.
 *
 * Everything here may use `node:` builtins freely. Nothing device-shippable may
 * import it: `core`, `shared`, `ledger`, `verifier` and `holder` reaching this
 * directory is a hard failure in tools/dependencyDirection.mjs, transitively and
 * by design. That rule is what makes this module safe to be un-portable in.
 *
 * The bar for putting something here is that it CANNOT be written portably —
 * not that it currently is not. A Node-only adapter is a decision to exclude the
 * handset from a capability, so prefer a port the backend implements over an
 * adapter every consumer inherits.
 *
 * FIRST TENANT, ALREADY IDENTIFIED. `src/webhooks.ts` calls require('crypto')
 * and is reached from the main barrel that React Native imports; it is waived in
 * tools/guard.config.mjs pending the move. Webhook signature verification is a
 * server concern. Moving it changes the public API, so it needs its own batch.
 */
export {};
