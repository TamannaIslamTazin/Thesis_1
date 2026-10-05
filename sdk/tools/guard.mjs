#!/usr/bin/env node
/**
 * CLI for the dependency-direction guard: `pnpm guard` in packages/sdk.
 *
 * Exit 0 only when every device-shippable root is clean. The same analyser runs
 * inside the SDK's vitest suite, so the check cannot be forgotten by anyone who
 * skips the script.
 */

import { analyse } from './dependencyDirection.mjs';
import { roots, workspace, waivers } from './guard.config.mjs';

const result = analyse({ roots, workspace, waivers });

const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;

if (result.violations.length > 0) {
  console.error(`\nDependency-direction guard FAILED — ${plural(result.violations.length, 'violation')}.\n`);
  for (const v of result.violations) {
    console.error(`  [${v.root}] ${v.from}${v.line ? `:${v.line}` : ''}`);
    if (v.to === null) {
      console.error(`      ${v.kind}`);
    } else {
      console.error(`      imports '${v.to}'${v.typeOnly ? ' (type-only)' : ''} — ${v.kind}`);
    }
    console.error(`      ${v.reason}`);
    if (v.trail && v.trail.length > 1) {
      console.error(`      reached via: ${v.trail.join(' -> ')}`);
    }
    console.error('');
  }
}

if (result.staleWaivers.length > 0) {
  console.error(`Stale waivers — ${plural(result.staleWaivers.length, 'entry')} no longer match anything.`);
  console.error('The violation was fixed; remove the waiver so it cannot mask a future one.\n');
  for (const w of result.staleWaivers) {
    console.error(`  ${w.from} -> ${w.to}`);
  }
  console.error('');
}

const failed = result.violations.length > 0 || result.staleWaivers.length > 0;

if (!failed) {
  console.log(
    `Dependency-direction guard passed. ${plural(result.filesScanned, 'file')} scanned across ` +
      `${plural(roots.length, 'root')}, ${plural(result.waivedCount, 'waived violation')}.`,
  );
  if (result.waivedCount > 0) {
    console.log('Waived violations are real defects, tracked in tools/guard.config.mjs.');
  }
}

process.exit(failed ? 1 : 0);
