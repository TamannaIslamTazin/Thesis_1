import { NextResponse } from 'next/server';
import { backend, BackendError, VERIFIER_DID } from '@/lib/backend';

interface CreatedRequest {
  requestId: string;
  requestUri: string;
  requestByReference: string;
  expiresAt: string;
  nonce: string;
}

/**
 * Ask the backend for a presentation request and hand the page its QR payload.
 *
 * `requestByReference` is what goes in the QR, not `requestUri`. The full
 * request inlined as a query parameter makes a large, dense QR that a cheap
 * camera struggles with; by reference the code carries one short URL and the
 * wallet fetches the definition over HTTP. Both are `openid4vp://`, which is
 * what the wallet's scanner matches on.
 */
export async function POST() {
  try {
    const created = await backend<CreatedRequest>('/oid4vp/authorization-request', {
      method: 'POST',
      body: {
        verifierDid: VERIFIER_DID,
        verifierName: 'Dhaka Community Pharmacy',
        purpose: 'Confirm this prescription was issued by a verified doctor before dispensing',
        // 15 minutes, not 5. A real counter would want a short window, but in
        // testing the holder has to walk a phone to a screen and a stale code
        // left on display is decoded instead of the fresh one — which then
        // fails as CREDENTIAL_EXPIRED and reads like a scanning fault.
        expiresInMinutes: 15,
        requestedCredentials: [
          {
            type: 'PrescriptionCredential',
            required: true,
            // ONLY what a pharmacy needs to dispense. The point of the exchange
            // is that the prescription is signed by a doctor the issuer
            // vouched for, so the medication is what must be shown; the
            // holder's identifier travels with the presentation regardless.
            claims: [
              { path: 'medication.name', required: true },
              { path: 'medication.dosage', required: true },
            ],
          },
        ],
      },
    });

    return NextResponse.json({
      requestId: created.requestId,
      qr: created.requestByReference,
      expiresAt: created.expiresAt,
    });
  } catch (error) {
    const status = error instanceof BackendError ? error.status : 500;
    return NextResponse.json(
      { error: error instanceof Error ? error.message : String(error) },
      { status },
    );
  }
}
