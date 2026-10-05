/**
 * Minimal `slip39@0.1.9` types for THIS package's compilation unit.
 *
 * The canonical, fully documented declaration lives at
 * `packages/shared/src/recovery/slip39.d.ts`, next to the only production code
 * that uses the library. This copy exists because a `declare module` shim is
 * per-project and the backend's vector test drives `recoverSecret` directly —
 * it deliberately declares ONLY that, so the duplicated surface is one method
 * rather than the whole API.
 *
 * If the library is ever replaced, the shared file is the one to change; this
 * one only has to keep compiling the test.
 */
declare module 'slip39' {
  export default class Slip39 {
    /** Throws on a below-threshold, mixed or checksum-invalid share set. */
    static recoverSecret(mnemonics: string[], passphrase?: string): number[];
  }
}
