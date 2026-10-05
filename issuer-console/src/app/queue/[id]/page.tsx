'use client';

import { use, useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/lib/AuthContext';
import { ApiError, approveRequest, getQueue, rejectRequest, type QueueEntry } from '@/lib/api';
import { clearCachedKey, useSingleUseKeyRelease } from '@/lib/singleUseKey';
import { unwrapReleasedContentKey, decryptLockerObject, DocumentCryptoError } from '@/lib/documentCrypto';
import { fetchLockerObject, LockerClientError } from '@/lib/lockerClient';
import { Card, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input, Label, Textarea } from '@/components/ui/input';

interface DocumentReadState {
  status: 'idle' | 'reading' | 'ready' | 'error';
  message?: string;
  previewText?: string;
  blobUrl?: string;
}

export default function ReviewPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const { status: authStatus, identity } = useAuth();
  const router = useRouter();

  const [entry, setEntry] = useState<QueueEntry | null | undefined>(undefined);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [decisionError, setDecisionError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [reason, setReason] = useState('');
  const [licenceNumber, setLicenceNumber] = useState('');
  const [reads, setReads] = useState<Record<string, DocumentReadState>>({});

  const { state: releaseState, release } = useSingleUseKeyRelease(id);

  useEffect(() => {
    if (authStatus === 'signed-out') {
      router.replace('/sign-in');
      return;
    }
    if (authStatus !== 'signed-in') return;
    if (!identity?.member) {
      router.replace('/bootstrap');
      return;
    }
    // Metadata only — the queue listing never releases the key. Loading this
    // page must not spend it; only the explicit "Reveal key" action may.
    getQueue()
      .then((r) => setEntry(r.requests.find((x) => x.id === id) ?? null))
      .catch((err) => setLoadError(err instanceof ApiError ? err.message : 'Could not load this request.'));
  }, [authStatus, identity, id, router]);

  async function handleApprove() {
    setDecisionError(null);
    setBusy(true);
    try {
      // ONE optional field, not a claims payload. Approval requires nothing:
      // the officer has just LOOKED at the certificate, and everything the
      // credential needs — scope, validity, register — is derivable from the
      // authority that is approving it. The licence number is the exception,
      // because it is the only value on the document that no other party can
      // derive, and it is the join a hospital uses to match a presented
      // licence to the appointment its admin recorded. Typing it is
      // transcription of one number already on screen, not data entry.
      const trimmed = licenceNumber.trim();
      await approveRequest(id, trimmed.length > 0 ? { licenceNumber: trimmed } : undefined);
      // The review is over, so the cached key has no further legitimate use.
      // Erased on the DECISION rather than on unmount: navigating away and
      // coming back is an ordinary thing for an officer to do mid-review.
      clearCachedKey(id);
      router.replace('/queue');
    } catch (err) {
      setDecisionError(err instanceof ApiError ? err.message : 'Approval failed.');
    } finally {
      setBusy(false);
    }
  }

  async function handleReject() {
    setDecisionError(null);
    setBusy(true);
    try {
      await rejectRequest(id, reason);
      clearCachedKey(id);
      router.replace('/queue');
    } catch (err) {
      setDecisionError(err instanceof ApiError ? err.message : 'Rejection failed.');
    } finally {
      setBusy(false);
    }
  }

  async function handleReadDocument(lockerObjectId: string) {
    setReads((prev) => ({ ...prev, [lockerObjectId]: { status: 'reading' } }));
    try {
      if (releaseState.status !== 'released' || !releaseState.key) {
        throw new DocumentCryptoError('Reveal the decryption key before fetching the document.');
      }
      // The capability travelled WITH the submission (OFFICER-DOCUMENT-ACCESS.md
      // §6a) — it is on every GET /api/authority/requests/:id response, so it
      // is already sitting on releaseState.detail. No paste, no second channel.
      const capability = releaseState.detail.lockerCapability;
      const contentKey = await unwrapReleasedContentKey(releaseState.key, id);
      const objectBytes = await fetchLockerObject(lockerObjectId, capability);
      const plaintext = decryptLockerObject(lockerObjectId, contentKey, objectBytes);
      const blob = new Blob([new Uint8Array(plaintext)]);
      const blobUrl = URL.createObjectURL(blob);
      let previewText: string | undefined;
      try {
        previewText = new TextDecoder('utf-8', { fatal: true }).decode(plaintext).slice(0, 500);
      } catch {
        previewText = undefined;
      }
      setReads((prev) => ({ ...prev, [lockerObjectId]: { status: 'ready', blobUrl, previewText } }));
    } catch (error) {
      const message =
        error instanceof DocumentCryptoError || error instanceof LockerClientError
          ? error.message
          : error instanceof Error
            ? error.message
            : String(error);
      setReads((prev) => ({ ...prev, [lockerObjectId]: { status: 'error', message } }));
    }
  }

  if (loadError) return <p className="text-sm text-danger">{loadError}</p>;
  if (entry === undefined) return <p className="text-sm text-muted">Loading…</p>;
  if (entry === null) return <p className="text-sm text-muted">This request is not in your queue (already decided, or not yours).</p>;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-lg font-semibold">{entry.documentType}</h1>
        <p className="text-sm text-muted">
          {entry.holder.firstName ?? entry.holder.email ?? entry.holderDid} · {entry.holderDid}
        </p>
      </div>

      <Card>
        <CardHeader>
          <div>
            <CardTitle>Single-use decryption key</CardTitle>
            <CardDescription>
              Released once per submission. A second read of this request returns no key.
            </CardDescription>
          </div>
          <Badge tone={releaseState.status === 'released' ? 'warn' : entry.keyReleased ? 'warn' : 'default'}>
            {releaseState.status === 'released'
              ? releaseState.key
                ? 'released just now'
                : 'already released earlier'
              : entry.keyReleased
                ? 'already released'
                : 'unreleased'}
          </Badge>
        </CardHeader>
        {releaseState.status === 'idle' && release && (
          <Button onClick={release} disabled={entry.keyReleased}>
            {entry.keyReleased ? 'Already released — no key available' : 'Reveal decryption key'}
          </Button>
        )}
        {releaseState.status === 'releasing' && <p className="text-sm text-muted">Releasing…</p>}
        {releaseState.status === 'error' && (
          <div className="space-y-2">
            <p className="text-sm text-danger">{releaseState.message}</p>
            {release && <Button onClick={release}>Retry</Button>}
          </div>
        )}
        {releaseState.status === 'released' && !releaseState.key && (
          <p className="text-sm text-muted">
            The key for this request was already released — to this officer or another — before this page loaded it.
          </p>
        )}
        {releaseState.status === 'released' && releaseState.key && (
          // Says exactly what is true. This line previously read "held in
          // memory... will not survive a reload", which stopped being true the
          // moment the key was cached — and a reassurance that has quietly
          // become false is worse than none, because it is believed.
          <p className="text-sm text-ok">
            Key held for this review, in this browser tab only. It survives a reload so a refresh cannot
            strand this submission, and is erased when you approve or reject.
          </p>
        )}
      </Card>

      <Card>
        <CardHeader>
          <div>
            <CardTitle>Documents</CardTitle>
            <CardDescription>
              Fetched from the locker under the capability the holder&apos;s wallet signed and submitted
              alongside this request (OFFICER-DOCUMENT-ACCESS.md §6a) — it travels with the request, so
              there is nothing to paste here.
            </CardDescription>
          </div>
        </CardHeader>
        <div className="space-y-3">
          <ul className="space-y-2">
            {entry.documents.map((doc) => {
              const read = reads[doc.lockerObjectId];
              return (
                <li key={doc.id} className="rounded-md border border-border p-3">
                  <div className="flex items-center justify-between gap-3">
                    <div className="text-sm">
                      <p className="font-mono text-xs text-muted">{doc.lockerObjectId}</p>
                      <p className="text-muted">{doc.mediaType}</p>
                    </div>
                    <Button
                      variant="outline"
                      onClick={() => handleReadDocument(doc.lockerObjectId)}
                      disabled={read?.status === 'reading' || releaseState.status !== 'released' || !releaseState.key}
                    >
                      {read?.status === 'reading' ? 'Fetching…' : 'Fetch & decrypt'}
                    </Button>
                  </div>
                  {read?.status === 'error' && <p className="mt-2 text-sm text-danger">{read.message}</p>}
                  {read?.status === 'ready' && (
                    <div className="mt-2 space-y-2">
                      {/* SHOW THE DOCUMENT, do not offer to download it.
                          The officer's whole job here is to LOOK at what was
                          submitted and decide. A link labelled "download
                          decrypted bytes" asks them to leave the review, open a
                          file manager and find it again — for a scan of a
                          certificate that the browser can simply render. It also
                          scatters plaintext copies of a medical document across
                          the reviewer's disk, which the single-use key and the
                          in-memory handling exist to avoid. */}
                      {read.blobUrl && doc.mediaType?.startsWith('image/') && (
                        // eslint-disable-next-line @next/next/no-img-element
                        <img
                          src={read.blobUrl}
                          alt={`Submitted document ${doc.lockerObjectId}`}
                          className="max-h-[70vh] w-full rounded border border-subtle bg-white object-contain"
                        />
                      )}
                      {read.blobUrl && doc.mediaType === 'application/pdf' && (
                        <object data={read.blobUrl} type="application/pdf" className="h-[70vh] w-full rounded border border-subtle">
                          <p className="p-3 text-sm">
                            This browser cannot display the PDF inline.{' '}
                            <a href={read.blobUrl} download={doc.lockerObjectId} className="text-primary underline">
                              Open it instead
                            </a>
                            .
                          </p>
                        </object>
                      )}
                      {read.previewText && (
                        <pre className="max-h-40 overflow-auto rounded bg-surface-raised p-2 text-xs">{read.previewText}</pre>
                      )}
                      {read.blobUrl && !doc.mediaType?.startsWith('image/') && doc.mediaType !== 'application/pdf' && (
                        // Only where the browser genuinely cannot render it.
                        <a href={read.blobUrl} download={doc.lockerObjectId} className="text-sm text-primary underline">
                          Open this file ({doc.mediaType ?? 'unknown type'})
                        </a>
                      )}
                    </div>
                  )}
                </li>
              );
            })}
          </ul>
        </div>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Decision</CardTitle>
        </CardHeader>
        <div className="space-y-3">
          {decisionError && <p className="text-sm text-danger">{decisionError}</p>}
          <div>
            <Label htmlFor="licenceNumber">Licence number, as printed on the document</Label>
            <Input
              id="licenceNumber"
              value={licenceNumber}
              onChange={(e) => setLicenceNumber(e.target.value)}
              placeholder="e.g. A-12345"
            />
            <p className="mt-1 text-xs text-muted">
              Optional. Leave blank and the credential records{' '}
              <span className="font-mono">UNTRANSCRIBED</span> — the licence is still valid and still
              revocable, but a hospital cannot match it to an appointment it recorded by number.
            </p>
          </div>
          <div className="flex gap-3">
            <Button onClick={handleApprove} disabled={busy}>
              Approve
            </Button>
          </div>
          <div>
            <Label htmlFor="reason">Rejection reason</Label>
            <Textarea id="reason" rows={2} value={reason} onChange={(e) => setReason(e.target.value)} />
            <Button variant="destructive" className="mt-2" onClick={handleReject} disabled={busy || reason.trim().length === 0}>
              Reject
            </Button>
          </div>
        </div>
      </Card>
    </div>
  );
}
