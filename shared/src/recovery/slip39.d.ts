/**
 * Types for `slip39@0.1.9`, which ships none.
 *
 * DELIBERATELY NARROW. Only the two entry points we use are declared, and they
 * are declared precisely rather than as `any`. A wrong shape here is a wrong
 * shape in the custody of an unrepairable key, and `declare module 'slip39'`
 * would have turned every call in `guardianShares.ts` into an unchecked one.
 *
 * The runtime behaviour these signatures describe was VERIFIED against the
 * official Trezor SLIP-39 vectors (45/45: 15 positive, 30 negative correctly
 * refused) rather than read off the README — see `tests/fast/guardianShares.test.ts`,
 * which keeps asserting it.
 */
declare module 'slip39' {
  /** `[threshold, shareCount, label]` for one group. */
  export type Slip39GroupSpec = [number, number, string];

  export interface Slip39BuildOptions {
    readonly passphrase?: string;
    /** How many GROUPS must be satisfied, not how many shares. */
    readonly threshold: number;
    readonly groups: readonly Slip39GroupSpec[];
  }

  export interface Slip39Node {
    readonly mnemonics: string[];
  }

  export default class Slip39 {
    /** `secret` is a byte array; SLIP-39 requires an even length >= 16. */
    static fromArray(secret: number[], options: Slip39BuildOptions): Slip39;

    /** Throws on a below-threshold, mixed or checksum-invalid share set. */
    static recoverSecret(mnemonics: string[], passphrase?: string): number[];

    static validateMnemonic(mnemonic: string): boolean;

    /** e.g. `'r/0'` — the first group under the root. */
    fromPath(path: string): Slip39Node;
  }
}
