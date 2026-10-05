/**
 * Repoint imports of symbols that have moved into the SDK.
 *
 * When `didPartOf` moves from backend/src/services/cheqdDidShapes.ts to
 * `@ssi-healthcare/sdk/ledger`, every importer has to be repointed. Doing that
 * by hand across a monorepo is where a wholesale restructure quietly goes wrong:
 * a missed site still compiles against the old file, and the duplicate the move
 * existed to prevent survives. This does it mechanically, from a checked-in rule
 * set, so the same move can be re-run, reviewed and repeated.
 *
 * SYMBOL-LEVEL, NOT FILE-LEVEL. A batch usually moves SOME exports of a file and
 * leaves the rest, so `import { didPartOf, assertIsCheqdDid } from './x.js'`
 * must become two imports, not one rewritten one. Splitting an import list is
 * the whole job; anything cruder would force whole-file moves and that is the
 * approach that proved too slow.
 *
 * IDEMPOTENT BY CONSTRUCTION. A rewritten import no longer names the source
 * module, so it cannot match a second time. Moved symbols merge into an existing
 * import from the target rather than adding a parallel one, so re-running cannot
 * accumulate statements. `--verify` asserts a second pass is a no-op.
 *
 * DRY RUN BY DEFAULT. It prints what it would change and writes nothing without
 * `--apply`. A codemod that rewrites your tree the moment you get an argument
 * wrong is a tool that has to be undone from git rather than read.
 */

import ts from 'typescript';
import fs from 'node:fs';
import path from 'node:path';
import { resolveRelative } from './dependencyDirection.mjs';

const SOURCE_FILE_PATTERN = /\.(ts|tsx|mts|cts)$/;
const SKIP_DIRECTORIES = new Set(['node_modules', 'dist', '.git', 'build', 'coverage', '.next']);

/** Every source file under `dir`, skipping build output. */
export function collectSourceFiles(dir) {
  const found = [];
  const walk = (current) => {
    let entries;
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (entry.isDirectory()) {
        if (!SKIP_DIRECTORIES.has(entry.name)) walk(path.join(current, entry.name));
      } else if (SOURCE_FILE_PATTERN.test(entry.name) && !entry.name.endsWith('.d.ts')) {
        found.push(path.join(current, entry.name));
      }
    }
  };
  walk(dir);
  return found;
}

/** The named bindings of an import, with their type-only and alias detail preserved. */
function readNamedBindings(declaration) {
  const clause = declaration.importClause;
  if (!clause || !clause.namedBindings || !ts.isNamedImports(clause.namedBindings)) return null;
  return clause.namedBindings.elements.map((element) => ({
    exported: (element.propertyName ?? element.name).text,
    text: element.getText(),
    typeOnly: element.isTypeOnly,
  }));
}

/**
 * Long import lists wrap, because this repo writes them wrapped and there is no
 * prettier config to normalise the difference afterwards. A codemod whose output
 * has to be reformatted by hand is one nobody runs twice.
 */
const MAX_IMPORT_LINE_LENGTH = 100;

function renderImport(bindings, specifier, declarationIsTypeOnly) {
  // If every binding carries its own `type`, hoist it to the declaration and
  // drop the per-specifier modifiers — `import type { a, b }` reads better than
  // `import { type a, type b }` and means exactly the same thing.
  const allTypeOnly = bindings.length > 0 && bindings.every((b) => b.typeOnly);
  const hoist = declarationIsTypeOnly || allTypeOnly;
  const names = bindings.map((b) =>
    hoist && b.typeOnly ? b.text.replace(/^type\s+/, '') : b.text,
  );

  const keyword = `import ${hoist ? 'type ' : ''}`;
  const singleLine = `${keyword}{ ${names.join(', ')} } from '${specifier}';`;
  if (singleLine.length <= MAX_IMPORT_LINE_LENGTH) return singleLine;

  return `${keyword}{\n${names.map((n) => `  ${n},`).join('\n')}\n} from '${specifier}';`;
}

/**
 * Plan the rewrite of one file. Returns the new text and a description of each
 * change, or null when nothing matches.
 */
export function planFile(filePath, sourceText, rules) {
  const source = ts.createSourceFile(filePath, sourceText, ts.ScriptTarget.Latest, true);
  const edits = [];
  const changes = [];

  // Targets already imported in this file, so moved symbols merge instead of
  // producing a second import from the same module.
  const existingTargetImports = new Map();
  for (const statement of source.statements) {
    if (!ts.isImportDeclaration(statement) || !ts.isStringLiteral(statement.moduleSpecifier)) continue;
    const bindings = readNamedBindings(statement);
    if (bindings) existingTargetImports.set(statement.moduleSpecifier.text, statement);
  }

  for (const statement of source.statements) {
    if (!ts.isImportDeclaration(statement) || !ts.isStringLiteral(statement.moduleSpecifier)) continue;

    const specifier = statement.moduleSpecifier.text;
    const bindings = readNamedBindings(statement);
    if (!bindings) continue;

    const resolved = specifier.startsWith('.') ? resolveRelative(specifier, filePath) : null;

    // EVERY matching rule, not the first. A file is emptied over SEVERAL
    // batches, so more than one rule legitimately shares a `fromFile` — batch 1
    // took the did:cheqd vocabulary out of cheqdDidShapes.ts and batch 3 took
    // the key encoding out of the same file. `rules.find` returned only the
    // earlier rule, found no symbols of its own in the import, and skipped the
    // statement, so every rule after the first for a given source was silently
    // dead. Nothing failed; the imports simply were not repointed, which is the
    // exact failure this tool exists to prevent.
    const matching = rules.filter((candidate) => {
      if (candidate.to === specifier) return false; // Already repointed.
      if (candidate.fromSpecifier && candidate.fromSpecifier === specifier) return true;
      if (candidate.fromFile && resolved) {
        return path.resolve(candidate.fromFile) === path.resolve(resolved);
      }
      return false;
    });
    if (matching.length === 0) continue;

    // One binding must not be claimed by two rules; that is an ambiguous rule
    // set, and guessing which target wins would move a symbol somewhere nobody
    // chose. Refuse instead.
    const claimedBy = new Map();
    for (const candidate of matching) {
      for (const binding of bindings) {
        if (!candidate.symbols.includes(binding.exported)) continue;
        const previous = claimedBy.get(binding.exported);
        if (previous && previous !== candidate.to) {
          throw new Error(
            `Ambiguous codemod rules: '${binding.exported}' imported by ${filePath} from ` +
              `'${specifier}' is claimed for both '${previous}' and '${candidate.to}'. ` +
              'A symbol has one home; fix tools/codemod.rules.mjs.',
          );
        }
        claimedBy.set(binding.exported, candidate.to);
      }
    }
    if (claimedBy.size === 0) continue;

    const staying = bindings.filter((b) => !claimedBy.has(b.exported));

    const declarationIsTypeOnly = statement.importClause?.isTypeOnly ?? false;
    const start = statement.getStart(source);
    const end = statement.getEnd();

    // Group by destination, so one import statement can feed several targets in
    // a single pass and the order of rules does not change the output.
    const byTarget = new Map();
    for (const binding of bindings) {
      const target = claimedBy.get(binding.exported);
      if (!target) continue;
      if (!byTarget.has(target)) byTarget.set(target, []);
      byTarget.get(target).push(binding);
    }

    const pieces = [];
    if (staying.length > 0) pieces.push(renderImport(staying, specifier, declarationIsTypeOnly));

    for (const [target, moving] of byTarget) {
      const mergeTarget = existingTargetImports.get(target);
      // A declaration-level `import type { ... }` carries its type-ness on the
      // STATEMENT, so its bindings each report `typeOnly: false`. Merging a
      // value into it therefore silently makes the value type-only, and the
      // symbol vanishes at runtime. tsc catches it as TS1361 — it did, on
      // cheqdDid.ts, the first time this ran — but a tool that emits code the
      // compiler has to reject is a tool that stops being trusted. Merge into a
      // type-only statement only when everything joining it is also type-only.
      const mergeTargetIsTypeOnly = mergeTarget?.importClause?.isTypeOnly ?? false;
      const compatible =
        !mergeTargetIsTypeOnly || moving.every((b) => b.typeOnly || declarationIsTypeOnly);
      const canMerge = mergeTarget && mergeTarget !== statement && compatible;

      if (canMerge) {
        const targetBindings = readNamedBindings(mergeTarget) ?? [];
        const known = new Set(targetBindings.map((b) => b.exported));
        const additions = moving.filter((b) => !known.has(b.exported));
        if (additions.length > 0) {
          const merged = [...targetBindings, ...additions];
          edits.push({
            start: mergeTarget.getStart(source),
            end: mergeTarget.getEnd(),
            text: renderImport(merged, target, mergeTarget.importClause?.isTypeOnly ?? false),
          });
        }
      } else {
        pieces.push(renderImport(moving, target, declarationIsTypeOnly));
      }

      changes.push({
        file: filePath,
        from: specifier,
        to: target,
        symbols: moving.map((b) => b.exported),
        merged: Boolean(canMerge),
        removedStatement: staying.length === 0,
      });
    }

    edits.push({ start, end, text: pieces.join('\n') });
  }

  if (edits.length === 0) return null;

  // Apply back-to-front so earlier offsets stay valid.
  edits.sort((a, b) => b.start - a.start);
  let text = sourceText;
  for (const edit of edits) {
    text = text.slice(0, edit.start) + edit.text + text.slice(edit.end);
  }
  // An import list emptied to nothing leaves a stray blank statement.
  text = text.replace(/^\s*import (?:type )?\{\s*\} from '[^']*';\n/gm, '');

  return { text, changes };
}

/** Run every rule over every source file under `searchRoots`. */
export function run({ searchRoots, rules }) {
  const results = [];
  for (const root of searchRoots) {
    for (const file of collectSourceFiles(root)) {
      const original = fs.readFileSync(file, 'utf8');
      const plan = planFile(file, original, rules);
      if (plan && plan.text !== original) {
        results.push({ file, original, ...plan });
      }
    }
  }
  return results;
}
