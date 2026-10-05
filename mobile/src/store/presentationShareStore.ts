/**
 * The verifier's answer, delivered to whichever screen is mid-exchange.
 *
 * A challenge arrives from OUTSIDE the share sheet — a camera scan on the
 * scanner screen, or a deep link from the verifier's app — while the sheet that
 * created the offer stays mounted underneath. The store is the join between
 * them, so neither has to know how the other is reached.
 */
import { create } from 'zustand';

interface PresentationShareState {
  /** Raw challenge payload; parsed and offer-matched by the sheet that reads it. */
  pendingChallenge: string | null;
  setPendingChallenge: (raw: string | null) => void;
}

export const usePresentationShareStore = create<PresentationShareState>((set) => ({
  pendingChallenge: null,
  setPendingChallenge: (raw) => set({ pendingChallenge: raw }),
}));
