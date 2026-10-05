/**
 * The codemod's behaviour, including the property the owner asked for by name:
 * running it twice changes nothing the second time.
 *
 * These test the rewriter, not the relocation. A batch that has moved is proven
 * by the compiler and the existing suites; what needs proving here is that the
 * tool splits an import list correctly and cannot be run into a mess.
 */

import { describe, it, expect } from 'vitest';

// @ts-expect-error -- plain .mjs tool, deliberately unbuilt.
import { planFile } from '../../tools/repointImports.mjs';

interface Plan {
  text: string;
  changes: { symbols: string[]; from: string; to: string; merged: boolean }[];
}

const RULES = [
  { fromSpecifier: './shapes.js', to: '@ssi-healthcare/sdk/ledger', symbols: ['didPartOf', 'isCheqdDid'] },
];

const plan = (source: string, rules = RULES): Plan | null =>
  planFile('/tmp/example.ts', source, rules) as Plan | null;

describe('splitting an import list', () => {
  it('moves the named symbols and leaves the rest behind', () => {
    const result = plan(`import { didPartOf, assertIsCheqdDid } from './shapes.js';\n`);
    expect(result!.text).toContain(`import { assertIsCheqdDid } from './shapes.js';`);
    expect(result!.text).toContain(`import { didPartOf } from '@ssi-healthcare/sdk/ledger';`);
  });

  it('replaces the statement entirely when every symbol moves', () => {
    const result = plan(`import { didPartOf, isCheqdDid } from './shapes.js';\n`);
    expect(result!.text.trim()).toBe(`import { didPartOf, isCheqdDid } from '@ssi-healthcare/sdk/ledger';`);
    expect(result!.text).not.toContain('./shapes.js');
  });

  it('preserves an alias', () => {
    const result = plan(`import { didPartOf as didOf } from './shapes.js';\n`);
    expect(result!.text).toContain(`import { didPartOf as didOf } from '@ssi-healthcare/sdk/ledger';`);
  });

  it('keeps a declaration-level type-only import type-only', () => {
    const result = plan(`import type { didPartOf, other } from './shapes.js';\n`);
    expect(result!.text).toContain(`import type { other } from './shapes.js';`);
    expect(result!.text).toContain(`import type { didPartOf } from '@ssi-healthcare/sdk/ledger';`);
  });

  it('carries a per-specifier type modifier across, hoisting it when it is the only one', () => {
    const result = plan(`import { type didPartOf, other } from './shapes.js';\n`);
    expect(result!.text).toContain(`import type { didPartOf } from '@ssi-healthcare/sdk/ledger';`);
    expect(result!.text).toContain(`import { other } from './shapes.js';`);
  });
});

describe('merging rather than duplicating', () => {
  it('merges into an existing import from the target module', () => {
    const result = plan(
      `import { existing } from '@ssi-healthcare/sdk/ledger';\n` +
        `import { didPartOf } from './shapes.js';\n`,
    );
    const occurrences = result!.text.match(/from '@ssi-healthcare\/sdk\/ledger'/g) ?? [];
    expect(occurrences).toHaveLength(1);
    expect(result!.text).toContain(`import { existing, didPartOf } from '@ssi-healthcare/sdk/ledger';`);
    expect(result!.changes[0].merged).toBe(true);
  });

  it('does not re-add a symbol the target import already has', () => {
    const result = plan(
      `import { didPartOf } from '@ssi-healthcare/sdk/ledger';\n` +
        `import { didPartOf, other } from './shapes.js';\n`,
    );
    const matches = result!.text.match(/didPartOf/g) ?? [];
    expect(matches).toHaveLength(1);
  });
});

describe('leaving alone what it should', () => {
  it('ignores an import of unlisted symbols', () => {
    expect(plan(`import { somethingElse } from './shapes.js';\n`)).toBeNull();
  });

  it('ignores a different module', () => {
    expect(plan(`import { didPartOf } from './elsewhere.js';\n`)).toBeNull();
  });

  it('ignores a default import, which has no exported name to match', () => {
    expect(plan(`import didPartOf from './shapes.js';\n`)).toBeNull();
  });

  it('ignores an import already pointing at the target', () => {
    expect(plan(`import { didPartOf } from '@ssi-healthcare/sdk/ledger';\n`)).toBeNull();
  });

  it('does not touch code that merely mentions the symbol', () => {
    const source = `// didPartOf used to live in './shapes.js'\nexport const didPartOf = 1;\n`;
    expect(plan(source)).toBeNull();
  });
});

describe('idempotence', () => {
  it('changes nothing on a second pass', () => {
    const source =
      `import { didPartOf, assertIsCheqdDid } from './shapes.js';\n` +
      `import { isCheqdDid } from './shapes.js';\n`;

    const first = plan(source);
    expect(first).not.toBeNull();

    const second = plan(first!.text);
    expect(second).toBeNull();
  });

  it('reaches a fixed point even when merging was involved', () => {
    const source =
      `import { existing } from '@ssi-healthcare/sdk/ledger';\n` +
      `import { didPartOf } from './shapes.js';\n` +
      `import { isCheqdDid, stays } from './shapes.js';\n`;

    const first = plan(source)!;
    const second = plan(first.text);
    expect(second).toBeNull();
    expect(first.text).toContain(`import { stays } from './shapes.js';`);
  });
});

describe('reporting', () => {
  it('names every symbol it moves, so a run can be reviewed rather than trusted', () => {
    const result = plan(`import { didPartOf, isCheqdDid, stays } from './shapes.js';\n`)!;
    expect(result.changes).toHaveLength(1);
    expect(result.changes[0].symbols.sort()).toEqual(['didPartOf', 'isCheqdDid']);
    expect(result.changes[0].to).toBe('@ssi-healthcare/sdk/ledger');
  });
});

/**
 * THE DEFECT BATCH 3 FOUND, kept falsifiable.
 *
 * A file is emptied over SEVERAL batches, so more than one rule legitimately
 * shares a `fromFile`: batch 1 took the did:cheqd vocabulary out of
 * cheqdDidShapes.ts and batch 3 took the key encoding out of the same file. The
 * matcher used `rules.find`, so it saw only the earlier rule, found none of ITS
 * symbols in the import, and skipped the statement. Nothing failed and nothing
 * was reported — the imports simply were not repointed, which is the exact
 * failure this tool exists to prevent. Three real sites were missed, one of them
 * in reissuance/authorisation.ts, which no one had found by hand either.
 */
describe('several rules over one source file', () => {
  const TWO_BATCHES = [
    { fromSpecifier: './shapes.js', to: '@ssi-healthcare/sdk/ledger', symbols: ['didPartOf'] },
    { fromSpecifier: './shapes.js', to: '@ssi-healthcare/sdk/ledger', symbols: ['decodeKey'] },
  ];

  it('applies a later rule even when an earlier one matched the same file', () => {
    const result = plan(`import { decodeKey } from './shapes.js';\n`, TWO_BATCHES);
    expect(result).not.toBeNull();
    expect(result!.text).toContain(`import { decodeKey } from '@ssi-healthcare/sdk/ledger';`);
  });

  it('applies both rules to one import statement in a single pass', () => {
    const result = plan(`import { didPartOf, decodeKey, stays } from './shapes.js';\n`, TWO_BATCHES);
    expect(result!.text).toContain(`import { stays } from './shapes.js';`);
    expect(result!.text).toContain(`didPartOf`);
    expect(result!.text).toContain(`decodeKey`);
    // One merged statement for the shared target, not two parallel ones.
    expect(result!.text.match(/@ssi-healthcare\/sdk\/ledger/g)).toHaveLength(1);
  });

  it('routes symbols to DIFFERENT targets from one statement', () => {
    const split = [
      { fromSpecifier: './shapes.js', to: '@ssi-healthcare/sdk/ledger', symbols: ['didPartOf'] },
      { fromSpecifier: './shapes.js', to: '@ssi-healthcare/sdk/verify', symbols: ['decodeKey'] },
    ];
    const result = plan(`import { didPartOf, decodeKey } from './shapes.js';\n`, split);
    expect(result!.text).toContain(`import { didPartOf } from '@ssi-healthcare/sdk/ledger';`);
    expect(result!.text).toContain(`import { decodeKey } from '@ssi-healthcare/sdk/verify';`);
    expect(result!.text).not.toContain('./shapes.js');
  });

  it('refuses an ambiguous rule set rather than picking a winner', () => {
    const ambiguous = [
      { fromSpecifier: './shapes.js', to: '@ssi-healthcare/sdk/ledger', symbols: ['didPartOf'] },
      { fromSpecifier: './shapes.js', to: '@ssi-healthcare/sdk/verify', symbols: ['didPartOf'] },
    ];
    expect(() => plan(`import { didPartOf } from './shapes.js';\n`, ambiguous)).toThrow(
      /Ambiguous codemod rules/,
    );
  });

  it('is still idempotent once several rules have been applied', () => {
    const once = plan(`import { didPartOf, decodeKey, stays } from './shapes.js';\n`, TWO_BATCHES);
    expect(plan(once!.text, TWO_BATCHES)).toBeNull();
  });
});

/**
 * THE SECOND DEFECT BATCH 3 FOUND.
 *
 * A declaration-level `import type { ... }` carries its type-ness on the
 * STATEMENT, so each of its bindings reports `typeOnly: false`. Merging a VALUE
 * into it therefore made the value type-only, and it would have been erased at
 * runtime. It surfaced on cheqdDid.ts, which already had
 * `import type { CheqdDidDocumentShape } from '@ssi-healthcare/sdk/ledger'`.
 *
 * tsc rejected it (TS1361), so this was never going to reach production — but a
 * tool that emits code the compiler has to reject is a tool nobody runs twice,
 * which returns us to repointing 35 files by hand.
 */
describe('merging into a type-only import', () => {
  const VALUE_RULE = [
    { fromSpecifier: './shapes.js', to: '@ssi-healthcare/sdk/ledger', symbols: ['decodeKey'] },
  ];

  it('does NOT merge a value into a declaration-level type-only import', () => {
    const result = plan(
      `import type { Shape } from '@ssi-healthcare/sdk/ledger';\n` +
        `import { decodeKey } from './shapes.js';\n`,
      VALUE_RULE,
    );
    expect(result!.text).toContain(`import type { Shape } from '@ssi-healthcare/sdk/ledger';`);
    expect(result!.text).toContain(`import { decodeKey } from '@ssi-healthcare/sdk/ledger';`);
    // The type-only statement is untouched, so the value stays a value.
    expect(result!.text).not.toContain(`import type { Shape, decodeKey }`);
  });

  it('still merges a TYPE into a declaration-level type-only import', () => {
    const result = plan(
      `import type { Shape } from '@ssi-healthcare/sdk/ledger';\n` +
        `import type { decodeKey } from './shapes.js';\n`,
      VALUE_RULE,
    );
    expect(result!.text).toContain(
      `import type { Shape, decodeKey } from '@ssi-healthcare/sdk/ledger';`,
    );
  });

  it('still merges a value into a value import from the same target', () => {
    const result = plan(
      `import { other } from '@ssi-healthcare/sdk/ledger';\n` +
        `import { decodeKey } from './shapes.js';\n`,
      VALUE_RULE,
    );
    expect(result!.text).toContain(
      `import { other, decodeKey } from '@ssi-healthcare/sdk/ledger';`,
    );
  });
});
