#!/usr/bin/env node
/**
 * Regenerate `src/worklet-crypto/vendor/` from the installed @noble/hashes.
 *
 * WHY THIS EXISTS. The wallet's CPU-bound crypto (scrypt at N=2^15 first) must
 * run on a worklet runtime's thread, not the RN JS thread. A function reaches a
 * worklet runtime only if it is WORKLETIZED, and imported functions are not:
 * the probe on 20 Sep 2026 showed the runtime rejecting an imported noble call
 * with "[Worklets] Tried to synchronously call a non-worklet function". Bundle
 * Mode would forward imports automatically, but it is experimental and would sit
 * under Reanimated's UI worklets, so the owner chose the port instead: keep
 * noble, change the host.
 *
 * WHAT THIS SCRIPT DOES, MECHANICALLY, so the vendored code stays auditable
 * against its upstream rather than being hand-edited:
 *
 *   1. Copies the dependency closure for scrypt out of @noble/hashes/src.
 *   2. Adds a `'worklet';` directive to EVERY function body — inert under
 *      Node, so the same files are unit-testable against upstream.
 *   3. Removes the ONE environment dependency in the closure: `utils.ts`
 *      imports `crypto` from '@noble/hashes/crypto' solely for `randomBytes`,
 *      and a worklet runtime has no `crypto` global (probe: TextEncoder=true,
 *      crypto=false). Neither is used by scrypt/hmac/sha256, so both the import
 *      and the function are excised. Entropy is drawn on the RN side and passed
 *      in as bytes.
 *   4. Rewrites `./x.ts` import specifiers to extensionless, which both tsc and
 *      tsup resolve.
 *   5. Prepends a provenance header naming the upstream version.
 *
 * The script REFUSES to run when an expected shape is missing (a renamed
 * import, a moved function), so an upstream bump fails loudly here instead of
 * silently vendoring something different.
 *
 * Usage:  node tools/make-worklet-subset.mjs
 * Then:   pnpm --filter @ssi-healthcare/shared build
 */
import { readFileSync, writeFileSync, mkdirSync, copyFileSync, existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const here = dirname(fileURLToPath(import.meta.url));
const packageRoot = resolve(here, '..');
const require = createRequire(import.meta.url);

// `@noble/hashes/package.json` is not in the package's exports map, so resolve
// the main entry and take its directory instead.
const NOBLE_ROOT = dirname(require.resolve('@noble/hashes'));
const UPSTREAM = JSON.parse(readFileSync(join(NOBLE_ROOT, 'package.json'), 'utf8')).version;

/** scrypt's closure, in dependency order. */
const FILES = ['utils.ts', '_md.ts', '_u64.ts', 'sha2.ts', 'hmac.ts', 'pbkdf2.ts', 'scrypt.ts'];

const ts = require('typescript');
const factory = ts.factory;
const OUT_DIR = join(packageRoot, 'src', 'worklet-crypto', 'vendor');

const directive = () => factory.createExpressionStatement(factory.createStringLiteral('worklet'));

function withDirectiveBody(node, block) {
  switch (node.kind) {
    case ts.SyntaxKind.FunctionDeclaration:
      return factory.updateFunctionDeclaration(
        node, node.modifiers, node.asteriskToken, node.name, node.typeParameters,
        node.parameters, node.type, block,
      );
    case ts.SyntaxKind.FunctionExpression:
      return factory.updateFunctionExpression(
        node, node.modifiers, node.asteriskToken, node.name, node.typeParameters,
        node.parameters, node.type, block,
      );
    case ts.SyntaxKind.ArrowFunction:
      return factory.updateArrowFunction(
        node, node.modifiers, node.typeParameters, node.parameters, node.type,
        node.equalsGreaterThanToken, block,
      );
    case ts.SyntaxKind.MethodDeclaration:
      return factory.updateMethodDeclaration(
        node, node.modifiers, node.asteriskToken, node.name, node.questionToken,
        node.typeParameters, node.parameters, node.type, block,
      );
    case ts.SyntaxKind.Constructor:
      return factory.updateConstructorDeclaration(node, node.modifiers, node.parameters, block);
    case ts.SyntaxKind.GetAccessor:
      return factory.updateGetAccessorDeclaration(
        node, node.modifiers, node.name, node.parameters, node.type, block,
      );
    case ts.SyntaxKind.SetAccessor:
      return factory.updateSetAccessorDeclaration(
        node, node.modifiers, node.name, node.parameters, block,
      );
    default:
      throw new Error(`unhandled function-like kind ${ts.SyntaxKind[node.kind]}`);
  }
}

function hasNobleImport(text) {
  const parsed = ts.createSourceFile('check.ts', text, ts.ScriptTarget.Latest, true);
  let found = false;
  const walk = (node) => {
    if (found) return;
    if (
      ts.isImportDeclaration(node) &&
      ts.isStringLiteral(node.moduleSpecifier) &&
      node.moduleSpecifier.text.startsWith('@noble/')
    ) {
      found = true;
    }
    if (
      ts.isCallExpression(node) &&
      ts.isIdentifier(node.expression) &&
      node.expression.text === 'require' &&
      node.arguments[0] &&
      ts.isStringLiteral(node.arguments[0]) &&
      node.arguments[0].text.startsWith('@noble/')
    ) {
      found = true;
    }
    ts.forEachChild(node, walk);
  };
  walk(parsed);
  return found;
}

function workletize(source, fileName) {
  const sf = ts.createSourceFile(fileName, source, ts.ScriptTarget.Latest, true);

  // HOST-DEPENDENT DECLARATIONS, all in utils.ts. They are present in the
  // closure but never called by it, and each drags in a host API a worklet
  // runtime does not provide (`crypto`) or this project's TypeScript lib does
  // not describe (`Uint8Array#toHex/#fromHex`, newer lib targets). Removing
  // them keeps the vendored code typecheckable WITHOUT @ts-ignore comments,
  // which the AST printer does not preserve. Upstream drift fails loudly.
  const STRIP = [
    'randomBytes',
    'bytesToHex',
    'hexToBytes',
    'hasHexBuiltin',
    // Leftovers of the hex helpers above; unused code fails this project's
    // noUnusedLocals rather than lingering.
    'hexes',
    'asciis',
    'asciiToBase16',
  ];
  const stripsHostHelpers = fileName === 'utils.ts';
  const isStrippedDeclaration = (s) =>
    (ts.isFunctionDeclaration(s) && !!s.name && STRIP.includes(s.name.text)) ||
    (ts.isVariableStatement(s) &&
      s.declarationList.declarations.some(
        (d) => ts.isIdentifier(d.name) && STRIP.includes(d.name.text),
      ));
  const cryptoImport = stripsHostHelpers
    ? sf.statements.find(
        (s) =>
          ts.isImportDeclaration(s) &&
          ts.isStringLiteral(s.moduleSpecifier) &&
          s.moduleSpecifier.text === '@noble/hashes/crypto',
      )
    : undefined;
  const stripped = stripsHostHelpers ? sf.statements.filter(isStrippedDeclaration) : [];
  if (stripsHostHelpers && (!cryptoImport || stripped.length !== STRIP.length)) {
    throw new Error(
      `${fileName}: expected the crypto import and ${STRIP.join(', ')}; upstream changed`,
    );
  }
  const strippedSet = new Set(stripped);

  // A PLAIN visitor, not ts.transform: the transform context applies emit
  // semantics (function-body hoisting) to manually rewritten nodes and aborts
  // with "Too many nodes written to output" on noble's constructors. A plain
  // visitNode + printer is exactly equivalent for a mechanical rewrite.
  const visit = (node) => {
    if (node === cryptoImport || strippedSet.has(node)) return undefined;

    if (ts.isFunctionLike(node) && node.body) {
      const original = node.body;
      const statements = ts.isBlock(original) ? [...original.statements] : null;
      const already = statements?.some(
        (s) =>
          ts.isExpressionStatement(s) &&
          ts.isStringLiteral(s.expression) &&
          s.expression.text === 'worklet',
      );
      if (!already) {
        const body = ts.isBlock(original)
          ? factory.createBlock([directive(), ...original.statements], true)
          : factory.createBlock([directive(), factory.createReturnStatement(original)], true);
        // Keep descending: noble has nested functions, and each one needs the
        // directive too or the runtime refuses it from the enclosing worklet.
        return ts.visitEachChild(withDirectiveBody(node, body), visit, undefined);
      }
    }

    return ts.visitEachChild(node, visit, undefined);
  };

  const transformed = ts.visitNode(sf, visit);
  const printer = ts.createPrinter({ newLine: ts.NewLineKind.LineFeed });
  let output = printer.printFile(transformed);

  // Extensionless relative imports (tsc + tsup both resolve these).
  output = output.replace(/from '(\.[^']*)\.ts'/g, "from '$1'");
  output = output.replace(/from "(\.[^"]*)\.ts"/g, 'from "$1"');

  // Guard BEFORE the provenance header is prepended, and by AST rather than by
  // text: noble's own docstrings contain `from '@noble/hashes/...'` examples,
  // which a string match reports as live imports.
  if (hasNobleImport(output)) {
    throw new Error(`${fileName}: output still imports @noble — the closure is incomplete`);
  }

  const header = `/**
 * VENDORED from @noble/hashes@${UPSTREAM} (${fileName}).
 *
 * MIT licensed (see LICENSE in this directory). DO NOT EDIT BY HAND —
 * regenerate with \`node tools/make-worklet-subset.mjs\` from packages/shared.
 * The only changes are mechanical: a 'worklet'; directive in every function
 * body so the worklet runtime can execute this code, and (in utils) the
 * removal of the host-only helpers the closure never calls (randomBytes and
 * its crypto import, bytesToHex, hexToBytes, hasHexBuiltin). See NOTICE.md
 * for the full provenance.
 */
`;

  return header + output;
}

mkdirSync(OUT_DIR, { recursive: true });
for (const file of FILES) {
  let source = readFileSync(join(NOBLE_ROOT, 'src', file), 'utf8');

  // ---------------------------------------------------------------------
  // SEMANTIC PATCH: build the SHA-256 wrapper INSIDE the runtime.
  //
  // noble's `sha256` is a function with `create`/`outputLen`/`blockLen`
  // grafted on by createHasher. Worklet serialization carries the function
  // but NOT its own properties — measured on the handset 20 Sep 2026: the
  // imported wrapper arrived as typeof=function with create=undefined,
  // outputLen=undefined, and ahash refuses that shape with "Hash should be
  // wrapped by utils.createHasher". A wrapper created in-runtime keeps its
  // properties, so scrypt's two pbkdf2 call sites use a factory instead.
  // ---------------------------------------------------------------------
  if (file === 'scrypt.ts') {
    const before = source;
    source = source.replace(
      "import { sha256 } from './sha2.ts';",
      "import { sha256ForWorklet } from './sha2.ts';",
    );
    source = source.replace(/pbkdf2\(sha256,/g, 'pbkdf2(sha256ForWorklet(),');
    if (source === before || source.includes('pbkdf2(sha256,')) {
      throw new Error('scrypt.ts: expected the sha256 import and two pbkdf2 call sites; upstream changed');
    }
  }
  if (file === 'sha2.ts') {
    if (!source.includes('export class SHA256')) {
      throw new Error('sha2.ts: SHA256 is no longer exported; upstream changed');
    }
    source += `
/**
 * WORKLET-SAFE SHA-256 factory (this port's divergence from upstream).
 *
 * Build the createHasher wrapper where it will be USED. Function properties do
 * not survive worklet serialization, so a wrapper imported into a runtime
 * arrives without \`create\`/\`outputLen\`/\`blockLen\` and \`ahash\` refuses it.
 * The object this returns is created inside the runtime, properties included.
 */
export function sha256ForWorklet(): CHash {
  'worklet';
  return createHasher(() => new SHA256());
}
`;
  }

  const vendored = workletize(source, file);
  writeFileSync(join(OUT_DIR, file), vendored);
  const directives = (vendored.match(/["']worklet["'];/g) ?? []).length;
  console.log(`vendored ${file} (${directives} worklet directives)`);
}

const license = join(NOBLE_ROOT, 'LICENSE');
if (!existsSync(license)) throw new Error('missing LICENSE in the noble package');
copyFileSync(license, join(OUT_DIR, 'LICENSE'));
console.log(`done; vendored @noble/hashes@${UPSTREAM} -> ${OUT_DIR}`);
