/**
 * Shows the authorization sheet for a request that arrived from ANYWHERE.
 *
 * Mounted once, above the navigator, because a deep link can land while the
 * holder is on any screen — or while the app was not running at all. Hanging
 * this off the scanner screen would mean a link only worked if the holder
 * happened to be looking at the camera.
 *
 * The sheet itself is the same component the scanner uses, deliberately. A
 * request delivered by a link gets no shorter path to the holder's key than one
 * read off a printed code: same disclosure choices, same fingerprint, same
 * consent receipt.
 */
import React, { useCallback } from 'react';

import { QRResultSheet } from './sheets/QRResultSheet';
import { useIncomingRequestStore } from '../store/incomingRequestStore';

export function IncomingRequestHost() {
  const request = useIncomingRequestStore((s) => s.request);
  const dismiss = useIncomingRequestStore((s) => s.dismiss);

  const handleClose = useCallback(() => dismiss(), [dismiss]);

  return (
    <QRResultSheet
      visible={request !== null}
      onClose={handleClose}
      scanResult={request}
      onSuccess={handleClose}
      onError={(message) => {
        // Kept visible on failure: the sheet renders its own error state, and
        // closing here would replace a legible explanation with silence.
        console.warn('[deep-link] request failed:', message);
      }}
    />
  );
}
