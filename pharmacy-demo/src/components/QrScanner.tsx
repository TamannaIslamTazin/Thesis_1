'use client';

/**
 * Camera QR scanner for the pairing code.
 *
 * ===========================================================================
 * WHY SCANNING AND NOT TYPING
 * ===========================================================================
 * The pairing code is a 32-character random string. Typing it by hand is both
 * error-prone and not what happens in the room: the officer holds a screen up and
 * the pharmacy points a camera at it. A text box also quietly invites someone to
 * paste a code from anywhere, which is not a flow that should exist — the token
 * is meant to be consumed in the presence of the officer who issued it.
 *
 * ===========================================================================
 * THE DECODER REFUSES ANYTHING THAT IS NOT A PAIRING CODE
 * ===========================================================================
 * A camera sees the whole room: price labels, stock stickers, other screens.
 * Decoding one of those must not produce a network call. The payload is filtered
 * by prefix HERE as well as on the server — here so the user gets a quiet
 * non-event rather than an error, there because the client is never the control.
 *
 * ===========================================================================
 * THE CAMERA IS RELEASED ON UNMOUNT
 * ===========================================================================
 * A live camera the user cannot see is a privacy problem and a battery one. Every
 * exit path — success, error, unmount — stops the tracks and cancels the frame
 * loop. The red indicator otherwise stays on after the sheet is gone.
 */
import { useCallback, useEffect, useRef, useState } from 'react';
import jsQR from 'jsqr';

// The PURE module, never '@/lib/identity' — that one reaches node:crypto and
// node:sqlite, which cannot be bundled for the browser.
import { ENROLMENT_URI_PREFIX } from '@/lib/enrolmentUri';

interface Props {
  /** Called once, with the recognised payload. The scanner stops itself. */
  onScan: (payload: string) => void;
}

export function QrScanner({ onScan }: Props) {
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const rafRef = useRef<number | null>(null);
  const doneRef = useRef(false);

  const [error, setError] = useState<string | null>(null);
  const [active, setActive] = useState(false);

  const stop = useCallback(() => {
    if (rafRef.current !== null) {
      cancelAnimationFrame(rafRef.current);
      rafRef.current = null;
    }
    for (const track of streamRef.current?.getTracks() ?? []) track.stop();
    streamRef.current = null;
    setActive(false);
  }, []);

  useEffect(() => stop, [stop]);

  const start = useCallback(async () => {
    setError(null);
    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        // `environment` is the rear camera. On a counter PC it is whatever is
        // plugged in; the constraint is a preference, not a requirement.
        video: { facingMode: 'environment' },
      });
      streamRef.current = stream;
      const video = videoRef.current;
      if (!video) return;
      video.srcObject = stream;
      await video.play();
      setActive(true);

      const tick = () => {
        if (doneRef.current) return;
        const canvas = canvasRef.current;
        if (!video || !canvas || video.readyState !== video.HAVE_ENOUGH_DATA) {
          rafRef.current = requestAnimationFrame(tick);
          return;
        }
        canvas.width = video.videoWidth;
        canvas.height = video.videoHeight;
        const ctx = canvas.getContext('2d', { willReadFrequently: true });
        if (!ctx) {
          rafRef.current = requestAnimationFrame(tick);
          return;
        }
        ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
        const frame = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const found = jsQR(frame.data, frame.width, frame.height, { inversionAttempts: 'dontInvert' });

        if (found?.data?.startsWith(ENROLMENT_URI_PREFIX)) {
          doneRef.current = true;
          stop();
          onScan(found.data);
          return;
        }
        // A decoded-but-unrecognised code is a NON-EVENT, not an error: pointing
        // the camera at a price label should do nothing at all.
        rafRef.current = requestAnimationFrame(tick);
      };
      rafRef.current = requestAnimationFrame(tick);
    } catch (err) {
      stop();
      const name = err instanceof DOMException ? err.name : '';
      setError(
        name === 'NotAllowedError'
          ? 'Camera permission was refused. Allow it, or use the typed fallback below.'
          : name === 'NotFoundError'
            ? 'No camera was found on this machine.'
            : 'The camera could not be started.',
      );
    }
  }, [onScan, stop]);

  return (
    <div className="space-y-2">
      <div className="relative overflow-hidden rounded border border-[var(--color-border)] bg-black">
        <video
          ref={videoRef}
          className="h-56 w-full object-cover"
          playsInline
          muted
          // Not mirrored: the camera points AWAY from the operator at a screen.
        />
        {!active && (
          <div className="absolute inset-0 flex items-center justify-center bg-black/60">
            <button
              className="rounded bg-[var(--color-primary)] px-4 py-2 text-sm font-medium text-white"
              onClick={start}
              type="button"
            >
              Start camera
            </button>
          </div>
        )}
      </div>
      <canvas ref={canvasRef} className="hidden" />
      {active && (
        <button className="text-xs underline" onClick={stop} type="button">
          Stop camera
        </button>
      )}
      {error && <p className="text-xs text-[var(--color-danger)]">{error}</p>}
      <p className="text-xs text-[var(--color-muted)]">
        Point the camera at the code on the officer&rsquo;s screen.
      </p>
    </div>
  );
}
