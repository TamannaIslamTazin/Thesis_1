'use client';

/**
 * Onboard an L2 institution — a hospital, clinic, pharmacy or laboratory.
 *
 * ===========================================================================
 * WHY THIS IS NOT THE ISSUANCE QUEUE
 * ===========================================================================
 * Everything else in this console has one shape: a person submits a document, an
 * officer reviews it, a credential is issued to that person. Onboarding shares
 * none of it — there is no document to fetch, no single-use key to release, and
 * no holder wallet to deliver to. The subject is an ENTITY and what the officer
 * judges is a PLACE.
 *
 * ===========================================================================
 * THE QR PAIRS. THE OFFICER'S CONFIRMATION MINTS.
 * ===========================================================================
 * Scanning the code pairs the institution's software to this session and creates
 * NOTHING. The officer then confirms what they actually saw on site, and that
 * confirmation mints the DID. If the QR alone minted, the authorisation would
 * come from a bitmap and the site visit — the one thing that separates a real
 * pharmacy from a shell entity — would be decorative.
 *
 * The screen is built so that ORDER IS VISIBLE: the officer can see that a
 * machine has paired and WHICH machine, before deciding anything.
 */
import { useCallback, useEffect, useRef, useState } from 'react';
import { useRouter } from 'next/navigation';
import QRCode from 'react-qr-code';

import { useAuth } from '@/lib/AuthContext';
import { permissionsForRole } from '@/lib/permissions';
import {
  ApiError,
  createEnrolment,
  getEnrolment,
  completeEnrolment,
  type EnrolmentStatus,
  type MintedInstitution,
} from '@/lib/api';
import { Card } from '@/components/ui/card';
import { Input, Label } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';

/**
 * What the QR encodes.
 *
 * A COMPACT, VERSIONED PREFIX rather than a URL. The software that scans this is
 * on a different origin (or no browser at all) and knows its own backend address
 * from its own configuration; embedding a host here would only encode where THIS
 * console happens to be, which the scanner may not be able to reach. The prefix
 * exists so the scanner can recognise the payload unambiguously and refuse
 * anything else it might decode.
 */
const ENROLMENT_URI_PREFIX = 'bdht-enrol:v1:';

type Step =
  | { name: 'idle' }
  | { name: 'showing'; enrolmentId: string; token: string; expiresAt: string; status: EnrolmentStatus }
  | { name: 'minted'; institution: MintedInstitution };

export default function OnboardPage() {
  const { status, identity } = useAuth();
  const router = useRouter();

  const [step, setStep] = useState<Step>({ name: 'idle' });
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // The officer's confirmation form — what they saw on site.
  const [name, setName] = useState('');
  const [type, setType] = useState<'HOSPITAL' | 'CLINIC' | 'PHARMACY' | 'LABORATORY'>('PHARMACY');
  const [address, setAddress] = useState('');
  const [licenceNumber, setLicenceNumber] = useState('');
  const [phone, setPhone] = useState('');

  // `identity?.member &&` rather than Boolean(...): it NARROWS the discriminated
  // union, so `identity.role` is known to exist. Wrapping it in Boolean() loses
  // that and the compiler is right to object.
  const canOnboard = Boolean(identity?.member && permissionsForRole(identity.role).canOnboardInstitution);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    if (status === 'signed-out') {
      router.replace('/sign-in');
      return;
    }
    if (status !== 'signed-in') return;
    if (!identity?.member) {
      router.replace('/bootstrap');
    }
  }, [status, identity, router]);

  // Poll only while a token is on screen and unclaimed. Claiming is the moment
  // the officer needs to see, so this stops as soon as it happens.
  useEffect(() => {
    if (step.name !== 'showing' || step.status.status !== 'PENDING') {
      if (pollRef.current) {
        clearInterval(pollRef.current);
        pollRef.current = null;
      }
      return;
    }

    pollRef.current = setInterval(async () => {
      try {
        const latest = await getEnrolment(step.enrolmentId);
        setStep((current) =>
          current.name === 'showing' ? { ...current, status: latest } : current,
        );
      } catch {
        // A failed poll is not a failed enrolment. Leave the token on screen; the
        // next tick tries again, and the expiry clock is the backstop.
      }
    }, 2000);

    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
      pollRef.current = null;
    };
  }, [step]);

  const start = useCallback(async () => {
    setError(null);
    setBusy(true);
    try {
      const created = await createEnrolment('On-site verification');
      setStep({
        name: 'showing',
        enrolmentId: created.enrolmentId,
        token: created.token,
        expiresAt: created.expiresAt,
        // The token was JUST created, so PENDING is known rather than guessed —
        // no extra round trip to learn what this response already told us.
        status: {
          id: created.enrolmentId,
          status: 'PENDING',
          claimedBy: null,
          claimedAt: null,
          expiresAt: created.expiresAt,
          institutionId: null,
        },
      });
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Could not start the onboarding.');
    } finally {
      setBusy(false);
    }
  }, []);

  const complete = useCallback(async () => {
    if (step.name !== 'showing') return;
    setError(null);
    setBusy(true);
    try {
      const institution = await completeEnrolment(step.enrolmentId, {
        name: name.trim(),
        type,
        address: address.trim(),
        licenceNumber: licenceNumber.trim() || undefined,
        phone: phone.trim() || undefined,
      });
      setStep({ name: 'minted', institution });
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'The institution could not be created.');
    } finally {
      setBusy(false);
    }
  }, [step, name, type, address, licenceNumber, phone]);

  if (status !== 'signed-in' || !identity?.member) {
    return <p className="text-sm text-muted">Checking your access…</p>;
  }

  if (!canOnboard) {
    return (
      <Card>
        <div className="mb-4 space-y-1">
          <h2 className="text-base font-semibold text-foreground">Onboarding institutions needs an ADMIN</h2>
          <p className="text-sm text-muted">
            You are signed in as {identity.role}. Two officers agreeing an institution did not
            visit would be worse than one, so this is deliberately one role and not a queue.
          </p>
        </div>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      <Card>
        {/* STACKED, not the shared side-by-side CardHeader: a long description in
            a 50% column squeezes the title into a ragged three-line stack. */}
        <div className="mb-4 space-y-1">
          <h2 className="text-base font-semibold text-foreground">Onboard an institution</h2>
          <p className="text-sm text-muted">
            Show the code to the institution&rsquo;s own software. Scanning it pairs that machine
            to you and creates nothing — you confirm what you verified on site, and that is what
            creates the institution.
          </p>
        </div>

        {error && (
          <p className="px-6 pb-4 text-sm text-red-600" role="alert">
            {error}
          </p>
        )}

        {step.name === 'idle' && (
          <div className="px-6 pb-6">
            <Button onClick={start} disabled={busy}>
              {busy ? 'Preparing…' : 'Show a pairing code'}
            </Button>
          </div>
        )}

        {step.name === 'showing' && (
          <div className="grid gap-6 px-6 pb-6 md:grid-cols-2">
            <div>
              <div className="rounded-lg border border-border bg-white p-4">
                <QRCode value={`${ENROLMENT_URI_PREFIX}${step.token}`} size={208} />
              </div>
              <p className="mt-2 break-all font-mono text-xs text-muted">
                {ENROLMENT_URI_PREFIX}
                {step.token}
              </p>
              <p className="mt-2 text-xs text-muted">
                Valid until {new Date(step.expiresAt).toLocaleTimeString()}. Single use — a second
                scan is refused.
              </p>
            </div>

            <div>
              <div className="mb-4">
                {step.status.status === 'PENDING' ? (
                  <Badge>Waiting for the software to scan…</Badge>
                ) : step.status.status === 'CLAIMED' ? (
                  <Badge>
                    Paired with {step.status.claimedBy ?? 'an unnamed machine'}
                  </Badge>
                ) : (
                  <Badge>{step.status.status}</Badge>
                )}
              </div>

              {/* The confirmation form appears only AFTER a machine has paired,
                  so the officer is never asked to attest before the thing they
                  are attesting to is present. */}
              {step.status.status === 'CLAIMED' ? (
                <div className="space-y-3">
                  <p className="text-sm text-muted">
                    Now record what you verified on site. These details and your name are kept as
                    the attestation.
                  </p>
                  <div>
                    <Label htmlFor="inst-name">Institution name</Label>
                    <Input id="inst-name" value={name} onChange={(e) => setName(e.target.value)} />
                  </div>
                  <div>
                    <Label htmlFor="inst-type">Type</Label>
                    <select
                      id="inst-type"
                      className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
                      value={type}
                      onChange={(e) => setType(e.target.value as typeof type)}
                    >
                      <option value="PHARMACY">Pharmacy</option>
                      <option value="HOSPITAL">Hospital</option>
                      <option value="CLINIC">Clinic</option>
                      <option value="LABORATORY">Laboratory</option>
                    </select>
                  </div>
                  <div>
                    <Label htmlFor="inst-address">Address you stood at</Label>
                    <Input
                      id="inst-address"
                      value={address}
                      onChange={(e) => setAddress(e.target.value)}
                      placeholder="House, road, area, city"
                    />
                  </div>
                  <div>
                    <Label htmlFor="inst-licence">Premises licence number (if displayed)</Label>
                    <Input
                      id="inst-licence"
                      value={licenceNumber}
                      onChange={(e) => setLicenceNumber(e.target.value)}
                    />
                  </div>
                  <div>
                    <Label htmlFor="inst-phone">Phone (optional)</Label>
                    <Input id="inst-phone" value={phone} onChange={(e) => setPhone(e.target.value)} />
                  </div>
                  <Button
                    onClick={complete}
                    disabled={busy || name.trim().length < 2 || address.trim().length < 4}
                  >
                    {busy ? 'Creating…' : 'Confirm and create the institution'}
                  </Button>
                </div>
              ) : (
                <p className="text-sm text-muted">
                  The confirmation step appears once the software has paired.
                </p>
              )}
            </div>
          </div>
        )}

        {step.name === 'minted' && (
          <div className="space-y-3 px-6 pb-6">
            <Badge>Created</Badge>
            <p className="text-sm">
              <strong>{step.institution.name}</strong> is verified and holds its own key.
            </p>
            <p className="break-all font-mono text-xs text-muted">{step.institution.did}</p>
            {step.institution.institutionHoldsKey === false && (
              <p className="text-sm text-amber-700">
                This software supplied no key of its own, so the document is currently held by the
                ministry only. That is repairable later, but the institution does not yet control
                its own identity.
              </p>
            )}
            <Button onClick={() => setStep({ name: 'idle' })}>Onboard another</Button>
          </div>
        )}
      </Card>
    </div>
  );
}
