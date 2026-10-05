import { NextResponse } from 'next/server';
import { backend, BackendError } from '@/lib/backend';

interface SessionResult {
  requestId: string;
  status: string;
  verifiedAt?: string | null;
  holderDid?: string | null;
  credentials?: Array<{ type?: string[]; claims?: Record<string, unknown> }>;
}

/**
 * Poll one presentation session.
 *
 * The pharmacy learns the outcome from the BACKEND, never from the wallet. A
 * verifier that took the holder's word for whether verification succeeded would
 * not be verifying anything.
 */
export async function GET(_req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  try {
    const data = await backend<SessionResult>(`/oid4vp/sessions/${encodeURIComponent(id)}`);
    return NextResponse.json(data);
  } catch (error) {
    const status = error instanceof BackendError ? error.status : 500;
    return NextResponse.json(
      { error: error instanceof Error ? error.message : String(error) },
      { status },
    );
  }
}
