#!/usr/bin/env node
/**
 * A verifier for the holder-initiated exchange, in one process.
 *
 * WHY THIS EXISTS. The wallet's "Share Credential" / "Generate QR Code" produce
 * an OFFER; the counterparty answers with a CHALLENGE and then receives a
 * signed PRESENTATION (see packages/mobile/src/services/presentationOffer.ts).
 * Nothing else in this repo consumes a holder-initiated exchange yet, so
 * without this harness the feature could only be "looks right on screen" —
 * which is exactly the kind of evidence this project has been burned by.
 *
 * It drives the real cryptographic loop for a single device under test:
 *
 *   1. You give it the offer URL the wallet displayed.
 *   2. It prints a challenge deep link (and serves the response endpoint).
 *   3. The wallet receives the challenge (scanned, or delivered with
 *      `adb shell am start -a android.intent.action.VIEW -d '<link>'`), the
 *      holder approves with their fingerprint, and the wallet POSTs here.
 *   4. It verifies the presentation with the SDK's own verifier — issuer
 *      signature, holder signature, disclosure integrity, nonce, audience,
 *      holder binding — resolving the issuer's key from the ledger through the
 *      backend, and prints the verdict.
 *
 * The nonce and audience are generated HERE, which is the whole point: a
 * presentation the verifier did not challenge is a bearer token, and this
 * harness refuses to accept one.
 *
 * Usage:
 *   node tools/verifyHolderExchange.mjs --offer 'ssi-healthcare://presentation-offer?o=...'
 *   options: --host 0.0.0.0 --port 4590 --audience https://verifier.bdht.test
 *            --backend http://127.0.0.1:3001 --timeout 300
 */
import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { verifySdJwtPresentation } from '../dist/verify/index.mjs';

const args = process.argv.slice(2);
const opt = (name, fallback) => {
  const index = args.indexOf(`--${name}`);
  return index >= 0 && args[index + 1] ? args[index + 1] : fallback;
};

const offerUrl = opt('offer');
const host = opt('host', '0.0.0.0');
const port = Number(opt('port', '4590'));
const audience = opt('audience', 'https://verifier.bdht.test');
const backend = opt('backend', 'http://127.0.0.1:3001');
const timeoutSeconds = Number(opt('timeout', '300'));

if (!offerUrl) {
  console.error("usage: node tools/verifyHolderExchange.mjs --offer 'ssi-healthcare://presentation-offer?o=...'");
  process.exit(2);
}

const b64u = (value) => Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');

function decodeOffer(url) {
  const param = url.includes('?o=') ? url.split('?o=')[1].split('&')[0] : url;
  return JSON.parse(Buffer.from(decodeURIComponent(param), 'base64url').toString('utf8'));
}

const b64uToBytes = (value) => Buffer.from(value.replace(/-/g, '+').replace(/_/g, '/'), 'base64');

/** `z6Mk…` (base58btc, 0xed01 prefix) -> OKP JWK. */
function multibaseEd25519ToJwk(multibase) {
  const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let value = 0n;
  for (const char of multibase.slice(1)) {
    const index = ALPHABET.indexOf(char);
    if (index < 0) throw new Error(`bad multibase char '${char}'`);
    value = value * 58n + BigInt(index);
  }
  const bytes = [];
  while (value > 0n) {
    bytes.unshift(Number(value % 256n));
    value /= 256n;
  }
  // Strip the multicodec varint for Ed25519 (0xed 0x01).
  const raw = Buffer.from(bytes).subarray(2);
  return { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(raw).toString('base64url') };
}

/** Resolve the key the credential's `kid` names, from the ledger via the backend. */
async function resolveVerificationKey({ kid, did }) {
  const response = await fetch(`${backend}/api/dids/${encodeURIComponent(did)}`);
  if (!response.ok) throw new Error(`cannot resolve ${did}: HTTP ${response.status}`);
  const body = await response.json();
  const doc = body?.data ?? body;
  const methods = doc.verificationMethod ?? doc.didDocument?.verificationMethod ?? [];
  const method = methods.find((m) => m.id === kid) ?? methods[0];
  if (!method) throw new Error(`no verification method on ${did}`);
  const multibase = method.publicKeyMultibase ?? method.publicKeyBase58;
  if (typeof multibase !== 'string') throw new Error(`method ${method.id} carries no public key`);
  return multibaseEd25519ToJwk(multibase);
}

function readPresentationEnvelope(vpToken) {
  const [headerB64] = vpToken.split('.');
  const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString('utf8'));
  const payload = JSON.parse(Buffer.from(vpToken.split('.')[1], 'base64url').toString('utf8'));
  const enveloped = payload.verifiableCredential?.[0];
  if (!enveloped || typeof enveloped.id !== 'string') {
    throw new Error('presentation carries no enveloped credential');
  }
  const dataUri = enveloped.id;
  const compact = decodeURIComponent(dataUri.slice(dataUri.indexOf(',') + 1));
  const credentialPayload = JSON.parse(
    Buffer.from(compact.split('.')[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'),
  );
  const credentialHeader = JSON.parse(Buffer.from(compact.split('.')[0], 'base64url').toString('utf8'));
  const kid = credentialHeader.kid;
  // The issuer is named on the envelope's `iss` when present; for older
  // envelopes fall back to the key id's DID prefix, which is the same value the
  // signature check anchored on.
  const issuerDid =
    (typeof credentialPayload.iss === 'string' ? credentialPayload.iss : credentialPayload.iss?.id) ??
    (typeof kid === 'string' ? kid.split('#')[0] : undefined);
  const disclosures = compact.split('~').filter(Boolean).length;
  return { header, payload, issuerDid, kid, disclosures, compact };
}

const offer = decodeOffer(offerUrl);
const nonce = randomBytes(24).toString('base64url');
const challenge = {
  v: 1,
  type: 'ssi-presentation-challenge',
  offerId: offer.offerId,
  nonce,
  audience,
  audienceName: 'Exchange verification harness',
  responseUri: opt('response-uri', `http://127.0.0.1:${port}/response`),
  exp: Math.floor(Date.now() / 1000) + 120,
};
const challengeUrl = `ssi-healthcare://presentation-challenge?c=${b64u(challenge)}`;

console.log('offer      :', offer.offerId);
console.log('claims     :', (offer.claims ?? []).join(', ') || '(none)');
console.log('challenge  : same nonce printed below; it expires in 120s');
console.log('');
console.log(challengeUrl);
console.log('');
console.log(`listening on http://${host}:${port}/response for ${timeoutSeconds}s ...`);

const server = createServer((req, res) => {
  if (req.method !== 'POST') {
    res.writeHead(405).end();
    return;
  }
  let body = '';
  req.on('data', (chunk) => {
    body += chunk;
  });
  req.on('end', async () => {
    try {
      const submitted = JSON.parse(body);
      if (submitted.state !== offer.offerId) {
        throw new Error(`state '${submitted.state}' does not match the offer`);
      }
      const included = readPresentationEnvelope(submitted.vp_token);
      if (included.payload.nonce !== nonce) throw new Error('presentation nonce does not match the challenge');
      if (included.payload.aud !== audience) throw new Error('presentation audience does not match the challenge');

      const verdict = await verifySdJwtPresentation({
        presentation: submitted.vp_token,
        challenge: nonce,
        audience,
        resolveVerificationKey,
        allowedAlgorithms: ['EdDSA'],
      });

      console.log('\n--- received ---');
      console.log('issuer     :', included.issuerDid);
      console.log('holder     :', included.payload.holder);
      console.log('disclosures:', included.disclosures);
      console.log('receipt    :', submitted.consent_receipt ? 'present' : 'ABSENT');
      console.log('\n--- SDK verifier verdict ---');
      console.log('isValid    :', verdict.isValid);
      for (const [name, passed] of Object.entries(verdict.checks)) {
        console.log(`  ${passed ? 'ok  ' : 'FAIL'} ${name}`);
      }
      if (verdict.errors?.length) console.log('errors     :', verdict.errors);
      if (!verdict.isValid) {
        res.writeHead(400).end('verification failed');
        server.close(() => process.exit(1));
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ verified: true }));
      console.log('\nVERIFIED — closing.');
      server.close(() => process.exit(0));
    } catch (error) {
      console.error('\nrejected:', error.message);
      res.writeHead(400).end(String(error.message));
    }
  });
});

server.listen(port, host);
setTimeout(() => {
  console.error(`no presentation after ${timeoutSeconds}s`);
  server.close(() => process.exit(1));
}, timeoutSeconds * 1000).unref();
