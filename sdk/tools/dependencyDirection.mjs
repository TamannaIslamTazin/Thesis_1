/**
 * Dependency-direction guard for the SDK's device-shippable modules.
 *
 * WHAT IT ENFORCES. `sdk/core`, `sdk/shared`, `sdk/ledger`, `sdk/verifier` and
 * `sdk/holder` ship to a React Native handset. They must never — transitively —
 * reach `sdk/node`, a Node builtin, Express, Prisma, Credo, winston, or the
 * backend package. One-hop screens miss the leak that actually happens: winston
 * blocked every extraction in the #341 plan precisely because it is none of the
 * obvious four, and `slip39` reaches `require('crypto')` two hops down from
 * `shared`'s barrel. So this resolves the whole graph.
 *
 * WHY AN AST AND NOT A REGEX. A `from '...'` regex over this tree reports
 * `js-base64` and `@ssi-healthcare/sdk/verify` as imports; both are prose inside
 * comments, and the vendored SD-JWT NOTICE is full of them. It also misses
 * multi-line and dynamic forms. The TypeScript scanner is the only thing that
 * reliably tells an import from a sentence about an import, and it is the only
 * thing that knows `import type` from `import`.
 *
 * WHY UNKNOWN DEPENDENCIES FAIL. Classification is an allowlist, not just a
 * denylist. A denylist only ever catches the blockers we already know about,
 * which is how winston got as far as it did. A new bare import is a violation
 * until someone classifies it here.
 */

import ts from 'typescript';
import fs from 'node:fs';
import path from 'node:path';
import { builtinModules } from 'node:module';

const NODE_BUILTINS = new Set([...builtinModules, ...builtinModules.map((m) => `node:${m}`)]);

/** Bare specifiers that cannot run on React Native, with the evidence for each. */
export const NODE_ONLY_PACKAGES = new Map([
  ['express', 'HTTP server; server-side only.'],
  ['winston', 'Logs via fs/os/streams. Use the LoggerPort in shared (steno #350).'],
  ['slip39', "slip39@0.1.9 src/slip39_helper.js does require('crypto') — Node crypto, unshimmed on RN."],
  ['@ssi-healthcare/backend', 'The backend is a deployment, not a library. Dependencies point the other way.'],
]);

/** Prefixes that are node-only regardless of subpath. */
const NODE_ONLY_PREFIXES = ['@prisma/', '@credo-ts/', '@cheqd/'];

/** Reviewed as safe to run on a handset. Additions need a reason in the PR. */
export const PORTABLE_PACKAGES = new Set([
  'jose',
  'zod',
  'react',
  'react-dom',
  'react/jsx-runtime',
  '@ssi-healthcare/shared',
]);

const PORTABLE_PREFIXES = ['@noble/'];

const SOURCE_EXTENSIONS = ['.ts', '.tsx', '.mts', '.cts'];

/** Classify a bare (non-relative) module specifier. */
function classifyBareSpecifier(specifier) {
  if (NODE_BUILTINS.has(specifier)) {
    return { verdict: 'node-only', reason: `'${specifier}' is a Node builtin.` };
  }
  if (specifier.startsWith('node:')) {
    return { verdict: 'node-only', reason: `'${specifier}' is a Node builtin.` };
  }
  const denied = NODE_ONLY_PACKAGES.get(specifier);
  if (denied) return { verdict: 'node-only', reason: denied };

  for (const prefix of NODE_ONLY_PREFIXES) {
    if (specifier.startsWith(prefix)) {
      return { verdict: 'node-only', reason: `'${prefix}*' is node-only (Credo/Prisma/cheqd server stack).` };
    }
  }
  if (PORTABLE_PACKAGES.has(specifier)) return { verdict: 'portable' };
  for (const prefix of PORTABLE_PREFIXES) {
    if (specifier.startsWith(prefix)) return { verdict: 'portable' };
  }
  // Fail closed: an unclassified dependency is a violation, not a pass.
  return {
    verdict: 'unclassified',
    reason: `'${specifier}' is not classified. Add it to PORTABLE_PACKAGES or NODE_ONLY_PACKAGES in tools/dependencyDirection.mjs.`,
  };
}

/**
 * Extract every module specifier in a source file, flagging the type-only ones.
 * Type-only imports are erased at runtime, so they break a build rather than a
 * bundle — the caller decides whether that is fatal.
 */
export function extractImports(sourceText, fileName) {
  const source = ts.createSourceFile(fileName, sourceText, ts.ScriptTarget.Latest, true);
  const found = [];

  const record = (specifierNode, typeOnly) => {
    if (specifierNode && ts.isStringLiteral(specifierNode)) {
      const { line } = source.getLineAndCharacterOfPosition(specifierNode.getStart(source));
      found.push({ specifier: specifierNode.text, typeOnly, line: line + 1 });
    }
  };

  const visit = (node) => {
    if (ts.isImportDeclaration(node)) {
      // `import type X`, and also `import { type A }` where every binding is type-only.
      const clause = node.importClause;
      let typeOnly = clause?.isTypeOnly ?? false;
      const bindings = clause?.namedBindings;
      if (!typeOnly && bindings && ts.isNamedImports(bindings) && !clause.name) {
        typeOnly = bindings.elements.length > 0 && bindings.elements.every((e) => e.isTypeOnly);
      }
      record(node.moduleSpecifier, typeOnly);
    } else if (ts.isExportDeclaration(node)) {
      record(node.moduleSpecifier, node.isTypeOnly);
    } else if (ts.isImportEqualsDeclaration(node)) {
      if (ts.isExternalModuleReference(node.moduleReference)) {
        record(node.moduleReference.expression, false);
      }
    } else if (ts.isCallExpression(node)) {
      const callee = node.expression;
      const isDynamicImport = callee.kind === ts.SyntaxKind.ImportKeyword;
      const isRequire = ts.isIdentifier(callee) && callee.text === 'require';
      if (isDynamicImport || isRequire) record(node.arguments[0], false);
    } else if (ts.isImportTypeNode(node)) {
      // `import('@ssi-healthcare/sdk').PresentationRequest` in a type position.
      const arg = node.argument;
      if (ts.isLiteralTypeNode(arg)) record(arg.literal, true);
    }
    ts.forEachChild(node, visit);
  };

  visit(source);
  return found;
}

/** Resolve a relative specifier to a real file, honouring ESM `.js` -> `.ts`. */
export function resolveRelative(specifier, fromFile) {
  const base = path.resolve(path.dirname(fromFile), specifier);
  const candidates = [];

  if (/\.(js|mjs|cjs)$/.test(base)) {
    candidates.push(base.replace(/\.js$/, '.ts'), base.replace(/\.js$/, '.tsx'),
      base.replace(/\.mjs$/, '.mts'), base.replace(/\.cjs$/, '.cts'));
  }
  candidates.push(base, ...SOURCE_EXTENSIONS.map((ext) => base + ext),
    ...SOURCE_EXTENSIONS.map((ext) => path.join(base, `index${ext}`)));

  for (const candidate of candidates) {
    if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) return candidate;
  }
  return null;
}

/**
 * Walk the import graph from `roots` and return every violation.
 *
 * `mode` per root: 'strict' fails on type-only reaches too (a device module must
 * not even name a server type); 'runtime' fails only on value imports, for
 * deliberately mixed barrels whose server half is erased at runtime.
 */
export function analyse({ roots, workspace, waivers = [] }) {
  const violations = [];
  const visited = new Set();
  const waiverHits = new Set();
  let filesScanned = 0;

  const waiverKey = (w) => `${w.from}=>${w.to}`;
  const waiverIndex = new Map(waivers.map((w) => [waiverKey(w), w]));

  const rel = (absolute) => path.relative(workspace.root, absolute).split(path.sep).join('/');

  const isInsideDeviceSource = (absolute) =>
    workspace.deviceSourceRoots.some((dir) => absolute.startsWith(dir + path.sep));

  for (const root of roots) {
    const rootFile = path.resolve(workspace.root, root.entry);
    if (!fs.existsSync(rootFile)) {
      violations.push({
        kind: 'missing-root', root: root.name, from: root.entry, to: null,
        reason: `Guard root '${root.entry}' does not exist. A root that vanished is a guard that stopped guarding.`,
      });
      continue;
    }

    const queue = [{ file: rootFile, trail: [rootFile] }];
    while (queue.length > 0) {
      const { file, trail } = queue.shift();
      const key = `${root.name}:${file}`;
      if (visited.has(key)) continue;
      visited.add(key);
      filesScanned += 1;

      const text = fs.readFileSync(file, 'utf8');
      for (const imp of extractImports(text, file)) {
        const { specifier, typeOnly, line } = imp;
        const tolerated = root.mode === 'runtime' && typeOnly;

        const report = (kind, reason) => {
          const record = {
            kind, root: root.name, from: rel(file), to: specifier, line, typeOnly, reason,
            trail: trail.map(rel),
          };
          const waiver = waiverIndex.get(waiverKey({ from: record.from, to: specifier }));
          if (waiver) {
            waiverHits.add(waiverKey({ from: record.from, to: specifier }));
            return;
          }
          if (!tolerated) violations.push(record);
        };

        if (specifier.startsWith('.')) {
          const resolved = resolveRelative(specifier, file);
          if (!resolved) {
            report('unresolved', `Cannot resolve '${specifier}'. An unresolvable edge is an unguarded edge.`);
            continue;
          }
          if (!isInsideDeviceSource(resolved)) {
            report('escapes-package', `'${specifier}' resolves to ${rel(resolved)}, outside the device-shippable source roots.`);
            continue;
          }
          if (workspace.nodeModuleDir && resolved.startsWith(workspace.nodeModuleDir + path.sep)) {
            report('reaches-sdk-node', `'${specifier}' reaches sdk/node, which is backend-only.`);
            continue;
          }
          if (!visited.has(`${root.name}:${resolved}`)) {
            queue.push({ file: resolved, trail: [...trail, resolved] });
          }
          continue;
        }

        // Workspace package: traverse its source so two-hop leaks are visible.
        const workspaceEntry = workspace.packageEntries?.[specifier];
        if (workspaceEntry) {
          const entryFile = path.resolve(workspace.root, workspaceEntry);
          if (fs.existsSync(entryFile) && !visited.has(`${root.name}:${entryFile}`)) {
            queue.push({ file: entryFile, trail: [...trail, entryFile] });
          }
          continue;
        }

        const { verdict, reason } = classifyBareSpecifier(specifier);
        if (verdict === 'node-only') report('node-only', reason);
        else if (verdict === 'unclassified') report('unclassified', reason);
      }
    }
  }

  const staleWaivers = waivers.filter((w) => !waiverHits.has(waiverKey(w)));
  return {
    violations,
    filesScanned,
    waivedCount: waiverHits.size,
    staleWaivers,
  };
}
