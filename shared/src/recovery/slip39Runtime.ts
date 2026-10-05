/**
 * The second Node assumption `slip39@0.1.9` makes, after `crypto`: the `Buffer` global.
 *
 * ===========================================================================
 * WHY THIS EXISTS AT ALL — #355 WAS INCOMPLETE
 * ===========================================================================
 * #355 named three missing APIs — `pbkdf2Sync`, `randomBytes`, `createHmac` —
 * and they are all reached through `require("crypto")`, so a resolver redirect
 * fixes them. Redirecting them and re-running the bundle in a host with no Node
 * builtins produced a NEW failure, `ReferenceError: Buffer is not defined`:
 * `slip39_helper.js` also uses the `Buffer` GLOBAL, at four sites
 * (lines 184, 185, 228, 230). React Native has no `Buffer`, and a global cannot
 * be redirected by a module resolver, so the crypto shim alone is not enough.
 *
 * ===========================================================================
 * WHY THE POLYFILL IS SCOPED TO A CALL AND NOT INSTALLED AT APP START
 * ===========================================================================
 * The conventional fix is `global.Buffer = require('buffer').Buffer` at the app
 * entry point. That is a permanent, app-wide change of a global for the benefit
 * of one library, and it has a specific failure mode: any dependency that
 * branches on `typeof Buffer !== 'undefined'` will start taking its Node path on
 * a device. It also means a partial implementation can be observed by code that
 * has nothing to do with recovery.
 *
 * Instead the global exists only for the duration of one SYNCHRONOUS SLIP-39
 * call and is removed in a `finally`. Nothing else can run in that window —
 * there is no `await` inside it — so no other module can observe it. The damage
 * surface is a few milliseconds of CPU-bound arithmetic rather than the process
 * lifetime.
 *
 * MEASURED, not assumed: the four call sites are the ONLY `Buffer` references in
 * the shipped library (`test/` has a fifth, which is not bundled), all four are
 * `Buffer.from(<number[]>)`, and all four results are passed straight into the
 * crypto shim, which normalises array-likes anyway. So `from` is the whole
 * contract.
 *
 * ON NODE THIS IS A NO-OP. The backend already has a real `Buffer`, sees it, and
 * calls straight through — the polyfill is unreachable there, which is what
 * keeps the backend's behaviour byte-identical to before this change.
 */

/** Exactly what `Buffer.from` is used for here, and nothing more. */
function bytesFrom(value: ArrayLike<number> | Iterable<number>): Uint8Array {
  return Uint8Array.from(value as ArrayLike<number>);
}

/**
 * Keys that must answer quietly rather than throw.
 *
 * Engines and debuggers touch these during ordinary introspection — logging the
 * value, string coercion, promise resolution checks — and a throw there would
 * fire far from any real misuse and be attributed to the wrong code.
 */
const SILENT_KEYS = new Set(['then', 'toJSON', 'inspect', 'constructor', 'prototype']);

/**
 * A `Buffer` that supports `from` and REFUSES everything else by name.
 *
 * The alternative, a plain `{ from }`, answers `undefined` for `Buffer.alloc`
 * and fails one frame later as "undefined is not a function" — an error that
 * names neither Buffer nor this file. Refusing loudly costs one Proxy and turns
 * a future mystery into a sentence that says where to look.
 */
function createMinimalBuffer(): unknown {
  return new Proxy(
    { from: bytesFrom },
    {
      get(target, property) {
        if (property === 'from') {
          return target.from;
        }
        if (typeof property === 'symbol' || SILENT_KEYS.has(property)) {
          return undefined;
        }
        throw new Error(
          `Buffer.${String(property)} was called, but the only Buffer in this runtime is the ` +
            'minimal one shared/src/recovery/slip39Runtime.ts installs around a SLIP-39 call, ' +
            'which implements Buffer.from and nothing else. If a dependency now needs a real ' +
            'Buffer on this platform, add a real polyfill deliberately rather than widening ' +
            'this one.',
        );
      },
    },
  );
}

/**
 * Run a synchronous SLIP-39 operation with the globals the library assumes.
 *
 * FAILSAFE: `finally` restores the previous value whether the operation returns
 * or throws, and an existing `Buffer` is never overwritten — a real polyfill
 * installed by the app always wins over this one.
 *
 * The callback must stay synchronous. If it ever needs to await, this scoping
 * argument collapses and the polyfill has to move to the app entry point
 * instead; that is a deliberate decision, not something to slip in.
 */
export function withSlip39Runtime<T>(operation: () => T): T {
  const globals = globalThis as { Buffer?: unknown };

  if (typeof globals.Buffer !== 'undefined') {
    return operation();
  }

  globals.Buffer = createMinimalBuffer();
  try {
    const result = operation();
    if (typeof (result as { then?: unknown } | null)?.then === 'function') {
      // The scoping argument above rests entirely on nothing else running inside
      // the window. An async operation would resume after `finally` has removed
      // the polyfill and fail somewhere unrelated, so refuse it here instead.
      throw new Error(
        'withSlip39Runtime was given an async operation. The Buffer polyfill it installs is ' +
          'removed synchronously, so the continuation would run without it.',
      );
    }
    return result;
  } finally {
    delete globals.Buffer;
  }
}
