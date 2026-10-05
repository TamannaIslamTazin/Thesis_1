/**
 * `@ssi-healthcare/sdk/shared` — the shared vocabulary, re-exported.
 *
 * `import { ERROR_CODES, type WalletCredential } from '@ssi-healthcare/sdk/shared'`
 *
 * WHY THIS IS A RE-EXPORT AND NOT A MOVE. `packages/shared` stays exactly where
 * it is. Moving it would rewrite every import in the backend and the mobile app
 * for no behavioural gain. This file costs one line and fixes a real problem:
 * an integrator links only `@ssi-healthcare/sdk`, so until now they could
 * receive a `WalletCredential` from the SDK and have no way to NAME its type.
 * One package, one import path.
 *
 * RESOLUTION, checked rather than assumed. `@ssi-healthcare/shared` is `external`
 * in tsup.config.ts, so the built output re-exports it by name instead of
 * inlining a second copy — two copies would break every identity comparison on a
 * shared constant. That name resolves for a consumer because Node resolves from
 * this package's REAL path, where packages/sdk/node_modules/@ssi-healthcare/shared
 * symlinks to packages/shared. The health-dashboard integration is a `file:` link
 * into this monorepo, so it inherits that.
 *
 * THE CAVEAT THAT COMES WITH IT. `packages/shared` is `private: true` and depended
 * on as `workspace:^`. If this SDK is ever published as a tarball to a registry,
 * this subpath breaks at install time, because the name it re-exports will not be
 * on npm. Publishing therefore requires either publishing shared too, or flipping
 * it to bundled for this one entry. Recorded here because the failure would
 * otherwise surface as a confusing MODULE_NOT_FOUND in someone else's build.
 */
export * from '@ssi-healthcare/shared';
