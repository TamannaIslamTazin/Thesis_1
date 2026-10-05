/**
 * P4 EXECUTION PROBE — can a user still click into the dead
 * `/api/credentials/store-external` route?
 *
 * Drives the real Next.js app in a real browser. Logs a real user in, pastes a
 * real third-party OID4VCI credential-offer URI into the wallet scan page, and
 * then asserts on what the browser actually did:
 *
 *   1. A visible, explicit "not available yet" message is shown.
 *   2. The review/authorize step is NOT reached — no Accept button appears, so
 *      there is nothing to click into.
 *   3. NO request to `/api/credentials/store-external` was ever issued.
 *   4. NO request to the third-party issuer was issued either — the old flow
 *      redeemed the single-use pre-authorized code BEFORE hitting the 404, so
 *      a "safe" 404 would still have cost the user their offer.
 *
 * The control case at the end proves the probe can actually fail: it asserts
 * that a genuinely unparseable QR produces the DIFFERENT, pre-existing error,
 * so we know assertion (1) is matching our new message and not any error.
 *
 * Run with backend (3001) and web dev server up:
 *   cd packages/web && npx tsx scripts/probe-p4-external-offer.mts
 */

import { chromium, type Request } from 'playwright';
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';

const WEB = process.env.PROBE_WEB_URL ?? 'http://localhost:3002';
const API = process.env.PROBE_API_URL ?? 'http://localhost:3001';
const ISSUER = 'https://hospital.probe.invalid';

/** A well-formed OID4VCI offer from an issuer that is NOT this backend. */
function externalOfferUri(): string {
  const offer = {
    credential_issuer: ISSUER,
    credentials: ['VaccinationCredential'],
    grants: {
      'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
        'pre-authorized_code': 'PROBE-SINGLE-USE-CODE',
        user_pin_required: false,
      },
    },
  };
  return `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(offer))}`;
}

async function registerProbeUser(): Promise<string> {
  const email = `p4probe+${Date.now()}@example.com`;
  // Per-run generated credential. The password is never reused after
  // registration — the returned token drives the rest of the probe — so a
  // committed fixed value provides nothing and is a credential leak waiting
  // to be copied into a real environment.
  const password = process.env.PROBE_USER_PASSWORD ?? `P4Probe-${randomUUID()}`;
  const res = await fetch(`${API}/api/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password, name: 'P4 Probe', role: 'PATIENT' }),
  });
  const json = (await res.json()) as { success: boolean; data?: { token: string } };
  if (!json.success || !json.data?.token) throw new Error('probe user registration failed');

  // /wallet/scan is wrapped in <ProtectedRoute requireWallet>, so the user needs
  // `walletSetup` and a `did`. Set them directly rather than running real wallet
  // setup: this probe is about the credential-offer branch, and a real setup
  // would write a DID to the chain for no benefit here. The values are never
  // resolved on this code path.
  // Connection string comes from the environment only — no credentials are
  // committed. DATABASE_URL is accepted as a fallback because the dev backend
  // that just registered the user already reads it.
  const psql = process.env.PROBE_DATABASE_URL ?? process.env.DATABASE_URL;
  if (!psql) {
    throw new Error(
      'PROBE_DATABASE_URL (or DATABASE_URL) is required so the probe can set walletSetup on the probe user',
    );
  }
  execFileSync('psql', [
    psql,
    '-v', 'ON_ERROR_STOP=1',
    '-c',
    `UPDATE "User" SET "walletSetup" = true, did = 'did:cheqd:bdhealthtestnet:p4probe-${Date.now()}' WHERE email = '${email}'`,
  ], { stdio: 'pipe' });

  return json.data.token;
}

const token = await registerProbeUser();

// This machine's playwright-core (1.58.2) expects chromium-1208, but the
// installed browser cache has chromium-1228. Point at it explicitly rather than
// downloading a second copy; the probe only needs navigation, typing and
// request interception, all stable across those builds.
const CHROMIUM =
  process.env.PROBE_CHROMIUM ??
  '/home/ahsan/.cache/ms-playwright/chromium-1228/chrome-linux64/chrome';

const browser = await chromium.launch({ executablePath: CHROMIUM });
const context = await browser.newContext();

const requests: string[] = [];
context.on('request', (req: Request) => requests.push(`${req.method()} ${req.url()}`));

await context.addInitScript(
  ([t]: string[]) => {
    localStorage.setItem('ssi_access_token', t!);
    localStorage.setItem('ssi_token_expires_at', String(Date.now() + 15 * 60 * 1000));
  },
  [token],
);

const page = await context.newPage();
const consoleErrors: string[] = [];
page.on('console', (m) => { if (m.type() === 'error') consoleErrors.push(m.text()); });

await page.goto(`${WEB}/wallet/scan?mode=receive`, { waitUntil: 'networkidle' });

const textarea = page.locator('textarea');
await textarea.waitFor({ state: 'visible', timeout: 20_000 });

// --- Case 1: the external issuer offer ------------------------------------
await textarea.fill(externalOfferUri());
await page.getByRole('button', { name: 'Submit' }).click();
await page.waitForTimeout(3000);

const bodyText = (await page.locator('body').innerText()).replace(/\s+/g, ' ');
const acceptVisible = await page.getByRole('button', { name: /accept|authorize|confirm/i }).count();

const failures: string[] = [];

if (!/Importing credentials from an outside issuer is not available yet/i.test(bodyText)) {
  failures.push(`the explicit "not available yet" message was not shown. Body was: ${bodyText.slice(0, 600)}`);
}
if (acceptVisible > 0) {
  failures.push(`the review step was reached — ${acceptVisible} accept/authorize button(s) are clickable`);
}

const storeExternalCalls = requests.filter((r) => r.includes('store-external'));
if (storeExternalCalls.length > 0) {
  failures.push(`the dead route was still called: ${storeExternalCalls.join(', ')}`);
}

const issuerCalls = requests.filter((r) => r.includes('hospital.probe.invalid'));
if (issuerCalls.length > 0) {
  failures.push(`the third-party issuer was contacted (pre-auth code would be burned): ${issuerCalls.join(', ')}`);
}

console.log('=== Case 1: external issuer credential offer ===');
console.log('visible message matched:', /not available yet/i.test(bodyText));
console.log('accept/authorize buttons on screen:', acceptVisible);
console.log('requests to store-external:', storeExternalCalls.length);
console.log('requests to the third-party issuer:', issuerCalls.length);

// --- Case 2 (control): an unparseable QR must give the OTHER error ---------
// Proves assertion (1) above is matching our new message specifically, not
// merely "some error appeared".
await page.reload({ waitUntil: 'networkidle' });
const textarea2 = page.locator('textarea');
await textarea2.waitFor({ state: 'visible', timeout: 20_000 });
await textarea2.fill('this-is-not-a-qr-payload');
await page.getByRole('button', { name: 'Submit' }).click();
await page.waitForTimeout(2000);
const controlText = (await page.locator('body').innerText()).replace(/\s+/g, ' ');

console.log('\n=== Case 2 (control): unparseable QR ===');
console.log('shows "Unrecognized QR code format":', /Unrecognized QR code format/i.test(controlText));
console.log('shows the external-issuer message (must be false):', /not available yet/i.test(controlText));

if (!/Unrecognized QR code format/i.test(controlText)) {
  failures.push('control case did not produce the pre-existing unrecognized-QR error — the probe may not be exercising the page');
}
if (/not available yet/i.test(controlText)) {
  failures.push('control case ALSO showed the external-issuer message — assertion (1) is not specific');
}

await browser.close();

console.log('\nconsole errors:', consoleErrors.length ? consoleErrors : 'none');
if (failures.length === 0) {
  console.log('\nPASS — a user cannot click into the 404.');
  process.exit(0);
}
console.log('\nFAIL:\n  - ' + failures.join('\n  - '));
process.exit(1);
