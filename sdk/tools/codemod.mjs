#!/usr/bin/env node
/**
 * CLI for the import codemod: `pnpm codemod` (dry run), `pnpm codemod --apply`.
 *
 *   --apply    write the changes; without it nothing is written
 *   --verify   apply, then re-plan and fail if a second pass would change
 *              anything. This is the idempotence proof, run against the real
 *              tree rather than asserted in a comment.
 *
 * Rules are checked in at tools/codemod.rules.mjs, so every batch's repointing
 * stays re-runnable and reviewable after the fact.
 */

import fs from 'node:fs';
import { run, planFile } from './repointImports.mjs';
import { rules, searchRoots } from './codemod.rules.mjs';

const args = new Set(process.argv.slice(2));
const apply = args.has('--apply') || args.has('--verify');
const verify = args.has('--verify');

if (rules.length === 0) {
  console.log('No codemod rules defined. Nothing to do.');
  process.exit(0);
}

const results = run({ searchRoots, rules });

if (results.length === 0) {
  console.log(`No changes. ${rules.length} rule(s) matched nothing — already repointed, or nothing imports the moved symbols.`);
  process.exit(0);
}

let changedSymbols = 0;
console.log(`${apply ? 'Repointing' : 'Would repoint'} imports in ${results.length} file(s):\n`);
for (const result of results) {
  console.log(`  ${result.file}`);
  for (const change of result.changes) {
    changedSymbols += change.symbols.length;
    const how = change.merged ? 'merged into existing import' : 'new import';
    console.log(`      ${change.symbols.join(', ')}`);
    console.log(`        '${change.from}' -> '${change.to}'  (${how})`);
  }
}
console.log(`\n${changedSymbols} symbol reference(s) across ${results.length} file(s).`);

if (!apply) {
  console.log('\nDry run — nothing written. Re-run with --apply.');
  process.exit(0);
}

for (const result of results) {
  fs.writeFileSync(result.file, result.text, 'utf8');
}
console.log('Written.');

if (verify) {
  const second = [];
  for (const result of results) {
    const text = fs.readFileSync(result.file, 'utf8');
    const plan = planFile(result.file, text, rules);
    if (plan && plan.text !== text) second.push(result.file);
  }
  if (second.length > 0) {
    console.error('\nNOT IDEMPOTENT — a second pass would still change:');
    for (const file of second) console.error(`  ${file}`);
    console.error('A codemod that keeps rewriting is one that cannot be trusted to have finished.');
    process.exit(1);
  }
  console.log('Idempotence verified: a second pass over the same files changes nothing.');
}
