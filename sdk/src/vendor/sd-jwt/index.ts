/**
 * Barrel for the vendored sd-jwt-js 0.19.0 subtree.
 *
 * READ ./NOTICE BEFORE CHANGING ANYTHING UNDER THIS DIRECTORY. It is a modified
 * third-party copy under Apache-2.0, and it carries four security divergences
 * from upstream that a well-meaning re-sync would otherwise revert:
 *
 *   grep -rn "BDHT DIVERGENCE" packages/sdk/src/vendor/sd-jwt
 *
 * WHAT THIS IS NOT. This is the DISCLOSURE layer — digests, frames, the `~`
 * wire format. It knows nothing about nonces, audiences, holder binding or DID
 * resolution, so it cannot on its own decide whether a presentation should be
 * accepted. `src/verify/presentation.ts` is the thing that decides that, and it
 * is what a relying party should be calling. Reaching past it into this
 * directory is supported for the advanced cases (issuance, wallet-side
 * presentation building) and is a mistake for verification.
 */
export * from './types';
export * from './utils';
export * from './decode';
export * from './present';
export * from './core';
