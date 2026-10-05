/**
 * The guard's own proof, in both directions.
 *
 * A check that cannot fail is worse than no check, and this project has shipped
 * three of those. So the negative cases are not decoration: each one builds a
 * throwaway tree containing a specific leak and asserts the guard catches THAT
 * leak, and the positive case asserts the real tree is clean. If the analyser is
 * ever weakened into a no-op, these fail.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

// @ts-expect-error -- plain .mjs tool, deliberately unbuilt so the guard needs no build step.
import { analyse, extractImports } from '../../tools/dependencyDirection.mjs';
// @ts-expect-error -- see above.
import { roots, workspace, waivers } from '../../tools/guard.config.mjs';

interface Violation {
  kind: string;
  root: string;
  from: string;
  to: string | null;
  typeOnly: boolean;
  reason: string;
  trail: string[];
}

interface Result {
  violations: Violation[];
  filesScanned: number;
  waivedCount: number;
  staleWaivers: { from: string; to: string }[];
}

/** Build a throwaway package tree; returns a workspace descriptor for it. */
function makeFixture(files: Record<string, string>) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'guard-fixture-'));
  for (const [relative, contents] of Object.entries(files)) {
    const target = path.join(root, relative);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, contents, 'utf8');
  }
  return {
    root,
    fixtureWorkspace: {
      root,
      deviceSourceRoots: [path.join(root, 'src')],
      nodeModuleDir: path.join(root, 'src/node'),
      packageEntries: { '@fixture/shared': 'shared/index.ts' },
    },
  };
}

const created: string[] = [];
function fixture(files: Record<string, string>) {
  const made = makeFixture(files);
  created.push(made.root);
  return made;
}

afterAll(() => {
  for (const dir of created) fs.rmSync(dir, { recursive: true, force: true });
});

const strictRoot = [{ name: 'device', entry: 'src/index.ts', mode: 'strict' }];

describe('the guard fails on real violations', () => {
  it('catches a direct Node builtin import', () => {
    const { fixtureWorkspace } = fixture({
      'src/index.ts': `import { readFileSync } from 'node:fs';\nexport const x = readFileSync;\n`,
    });
    const result: Result = analyse({ roots: strictRoot, workspace: fixtureWorkspace });
    expect(result.violations).toHaveLength(1);
    expect(result.violations[0].kind).toBe('node-only');
    expect(result.violations[0].to).toBe('node:fs');
  });

  it('catches an unprefixed Node builtin, which the obvious screen misses', () => {
    const { fixtureWorkspace } = fixture({
      'src/index.ts': `import { createHmac } from 'crypto';\nexport const x = createHmac;\n`,
    });
    const result: Result = analyse({ roots: strictRoot, workspace: fixtureWorkspace });
    expect(result.violations.map((v) => v.to)).toEqual(['crypto']);
  });

  it.each(['express', 'winston', '@prisma/client', '@credo-ts/core', '@ssi-healthcare/backend'])(
    'catches the banned package %s',
    (banned) => {
      const { fixtureWorkspace } = fixture({
        'src/index.ts': `import x from '${banned}';\nexport default x;\n`,
      });
      const result: Result = analyse({ roots: strictRoot, workspace: fixtureWorkspace });
      expect(result.violations).toHaveLength(1);
      expect(result.violations[0].kind).toBe('node-only');
    },
  );

  it('catches a TWO-HOP leak, which is the one that actually happens', () => {
    const { fixtureWorkspace } = fixture({
      'src/index.ts': `export { helper } from './middle.js';\n`,
      'src/middle.ts': `export { helper } from './deep.js';\n`,
      'src/deep.ts': `import { gunzipSync } from 'node:zlib';\nexport const helper = gunzipSync;\n`,
    });
    const result: Result = analyse({ roots: strictRoot, workspace: fixtureWorkspace });
    expect(result.violations).toHaveLength(1);
    expect(result.violations[0].to).toBe('node:zlib');
    // The trail is what makes the failure actionable rather than a riddle.
    expect(result.violations[0].trail.join(' -> ')).toBe('src/index.ts -> src/middle.ts -> src/deep.ts');
  });

  it('follows a workspace package into its source, so shared cannot hide a leak', () => {
    const { fixtureWorkspace } = fixture({
      'src/index.ts': `export { recover } from '@fixture/shared';\n`,
      'shared/index.ts': `export { recover } from './recovery.js';\n`,
      'shared/recovery.ts': `import Slip39 from 'slip39';\nexport const recover = Slip39;\n`,
    });
    const workspaceWithShared = {
      ...fixtureWorkspace,
      deviceSourceRoots: [...fixtureWorkspace.deviceSourceRoots, path.join(fixtureWorkspace.root, 'shared')],
    };
    const result: Result = analyse({ roots: strictRoot, workspace: workspaceWithShared });
    expect(result.violations.map((v) => v.to)).toEqual(['slip39']);
    expect(result.violations[0].from).toBe('shared/recovery.ts');
  });

  it('catches a device module reaching into sdk/node', () => {
    const { fixtureWorkspace } = fixture({
      'src/index.ts': `export { adapter } from './node/adapter.js';\n`,
      'src/node/adapter.ts': `export const adapter = 1;\n`,
    });
    const result: Result = analyse({ roots: strictRoot, workspace: fixtureWorkspace });
    expect(result.violations).toHaveLength(1);
    expect(result.violations[0].kind).toBe('reaches-sdk-node');
  });

  it('catches a relative import escaping the device source roots', () => {
    const { fixtureWorkspace } = fixture({
      'src/index.ts': `export { thing } from '../backend/thing.js';\n`,
      'backend/thing.ts': `export const thing = 1;\n`,
    });
    const result: Result = analyse({ roots: strictRoot, workspace: fixtureWorkspace });
    expect(result.violations[0].kind).toBe('escapes-package');
  });

  it('fails an UNCLASSIFIED dependency rather than assuming it is portable', () => {
    const { fixtureWorkspace } = fixture({
      'src/index.ts': `import lib from 'some-package-nobody-reviewed';\nexport default lib;\n`,
    });
    const result: Result = analyse({ roots: strictRoot, workspace: fixtureWorkspace });
    expect(result.violations[0].kind).toBe('unclassified');
  });

  it('fails an unresolvable relative import instead of skipping it', () => {
    const { fixtureWorkspace } = fixture({
      'src/index.ts': `export { gone } from './does-not-exist.js';\n`,
    });
    const result: Result = analyse({ roots: strictRoot, workspace: fixtureWorkspace });
    expect(result.violations[0].kind).toBe('unresolved');
  });

  it('fails a root that has vanished, so the guard cannot pass by not running', () => {
    const { fixtureWorkspace } = fixture({ 'src/other.ts': `export const x = 1;\n` });
    const result: Result = analyse({ roots: strictRoot, workspace: fixtureWorkspace });
    expect(result.violations[0].kind).toBe('missing-root');
  });

  it('reports a waiver that no longer matches, so the list cannot rot', () => {
    const { fixtureWorkspace } = fixture({ 'src/index.ts': `export const x = 1;\n` });
    const result: Result = analyse({
      roots: strictRoot,
      workspace: fixtureWorkspace,
      waivers: [{ from: 'src/index.ts', to: 'winston', reason: 'fixed long ago' }],
    });
    expect(result.violations).toHaveLength(0);
    expect(result.staleWaivers).toHaveLength(1);
  });
});

describe('the guard distinguishes what actually breaks a bundle', () => {
  const typeOnlyTree = {
    'src/index.ts': `import type { Router } from 'express';\nexport type R = Router;\n`,
  };

  it('fails a type-only server import in a strict device module', () => {
    const { fixtureWorkspace } = fixture(typeOnlyTree);
    const result: Result = analyse({ roots: strictRoot, workspace: fixtureWorkspace });
    expect(result.violations).toHaveLength(1);
    expect(result.violations[0].typeOnly).toBe(true);
  });

  it('tolerates it in a runtime-mode barrel, where it is erased', () => {
    const { fixtureWorkspace } = fixture(typeOnlyTree);
    const result: Result = analyse({
      roots: [{ name: 'barrel', entry: 'src/index.ts', mode: 'runtime' }],
      workspace: fixtureWorkspace,
    });
    expect(result.violations).toHaveLength(0);
  });

  it('still fails a VALUE import in a runtime-mode barrel', () => {
    const { fixtureWorkspace } = fixture({
      'src/index.ts': `import express from 'express';\nexport default express;\n`,
    });
    const result: Result = analyse({
      roots: [{ name: 'barrel', entry: 'src/index.ts', mode: 'runtime' }],
      workspace: fixtureWorkspace,
    });
    expect(result.violations).toHaveLength(1);
  });
});

describe('import extraction is not fooled by prose', () => {
  it('ignores module specifiers that appear inside comments', () => {
    const source = `
      /**
       * Upstream is four re-exports of \`js-base64\`:
       *     import { Base64 } from 'js-base64';
       * Also available as \`@ssi-healthcare/sdk/verify\`.
       */
      // import { readFileSync } from 'node:fs';
      export const x = 1;
    `;
    expect(extractImports(source, 'sample.ts')).toHaveLength(0);
  });

  it('sees dynamic import, require, and import-equals', () => {
    const source = `
      const a = await import('node:fs');
      const b = require('express');
      import c = require('winston');
      export { a, b, c };
    `;
    const found = extractImports(source, 'sample.ts') as { specifier: string }[];
    expect(found.map((f) => f.specifier).sort()).toEqual(['express', 'node:fs', 'winston']);
  });

  it('sees a multi-line import that a line-oriented regex would split', () => {
    const source = `
      import {
        one,
        two,
      } from '@credo-ts/core';
      export { one, two };
    `;
    const found = extractImports(source, 'sample.ts') as { specifier: string }[];
    expect(found.map((f) => f.specifier)).toEqual(['@credo-ts/core']);
  });

  it('treats a re-export and a type-position import() as edges', () => {
    const source = `
      export * from './neighbour.js';
      export type Req = import('@ssi-healthcare/sdk').PresentationRequest;
    `;
    const found = extractImports(source, 'sample.ts') as { specifier: string }[];
    expect(found.map((f) => f.specifier).sort()).toEqual(['./neighbour.js', '@ssi-healthcare/sdk']);
  });
});

describe('the guard passes on the real tree', () => {
  let result: Result;
  beforeAll(() => {
    result = analyse({ roots, workspace, waivers });
  });

  it('reports no unwaived violation', () => {
    const summary = result.violations.map(
      (v) => `[${v.root}] ${v.from} -> ${v.to} (${v.kind})`,
    );
    expect(summary).toEqual([]);
  });

  it('has no stale waiver', () => {
    expect(result.staleWaivers).toEqual([]);
  });

  it('actually scanned the tree, rather than passing on an empty graph', () => {
    // Guards that pass because they looked at nothing are this project's
    // recurring failure. Assert the work happened.
    expect(result.filesScanned).toBeGreaterThan(20);
  });
});
