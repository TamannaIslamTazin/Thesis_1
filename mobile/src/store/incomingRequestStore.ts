/**
 * The one request the wallet is currently being asked to act on.
 *
 * Exists so a request can arrive from somewhere OTHER than the scanner screen —
 * a deep link from the browser — and still reach the same authorization sheet.
 * Holding it in a store rather than in navigation params keeps the sheet's own
 * code unaware of how the request got here, which is the point: a link and a
 * scanned code must be treated identically.
 *
 * Single-slot on purpose. Two simultaneous authorization requests is not a
 * situation to queue gracefully; it is a situation where the holder cannot tell
 * which one they are approving.
 */
import { create } from 'zustand';

import type { ParsedQRCode } from '../services/qrScanner';

interface IncomingRequestState {
  request: ParsedQRCode | null;
  /** Where it came from, for the sheet to say so. */
  source: 'scan' | 'link' | null;
  present: (request: ParsedQRCode, source: 'scan' | 'link') => void;
  dismiss: () => void;
}

export const useIncomingRequestStore = create<IncomingRequestState>((set) => ({
  request: null,
  source: null,
  present: (request, source) => set({ request, source }),
  dismiss: () => set({ request: null, source: null }),
}));
