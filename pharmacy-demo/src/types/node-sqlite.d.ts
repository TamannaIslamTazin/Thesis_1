/**
 * Minimal typings for Node's built-in `node:sqlite`.
 *
 * WHY HAND-WRITTEN. The module is built into Node 22 but `@types/node@20` here
 * predates it, so TypeScript cannot see it. The alternative — bumping
 * @types/node across the workspace — is a much larger change than the three
 * methods this pharmacy actually uses, and a bump can shift types elsewhere.
 *
 * Only the surface `lib/db.ts` calls is declared, deliberately: a wider
 * declaration would claim API this code has never exercised.
 */
declare module 'node:sqlite' {
  export interface StatementSync {
    run(...params: unknown[]): { lastInsertRowid: number | bigint; changes: number | bigint };
    get(...params: unknown[]): unknown;
    all(...params: unknown[]): unknown[];
  }

  export class DatabaseSync {
    constructor(path: string);
    exec(sql: string): void;
    prepare(sql: string): StatementSync;
    close(): void;
  }
}
