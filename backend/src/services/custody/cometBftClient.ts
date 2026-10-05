/**
 * SSI Healthcare Backend — the narrow CometBFT RPC surface the watcher needs.
 *
 * Four calls, over plain `fetch`, deliberately not the CosmJS Tendermint client:
 * that client is built around a long-lived connection and a subscription model,
 * and this watcher needs neither. What it needs is to read specific committed
 * heights on demand, including heights that went past while it was not running.
 *
 * EVERY CALL HAS A TIMEOUT. A watcher blocked forever on a hung socket is a
 * watcher that is off, and it looks identical to one that is on and quiet.
 */

import { logger } from '../../utils/logger.js';

export interface ChainStatus {
  readonly chainId: string;
  readonly latestHeight: number;
  /** Below this the node has pruned; those heights can never be examined. */
  readonly earliestHeight: number;
  readonly catchingUp: boolean;
}

export interface BlockTxs {
  readonly height: number;
  readonly time: Date;
  /** Base64, in block order. Index is the position CometBFT hashes against. */
  readonly txs: readonly string[];
}

/** `null` means the node could not answer, NOT that the transaction succeeded. */
export interface DeliveredTxResult {
  readonly code: number;
  readonly log: string;
}

export class CometBftRpcError extends Error {
  constructor(
    message: string,
    readonly endpoint: string,
  ) {
    super(message);
    this.name = 'CometBftRpcError';
  }
}

export class CometBftClient {
  constructor(
    private readonly rpcUrl: string,
    private readonly timeoutMs = 10_000,
  ) {}

  async status(): Promise<ChainStatus> {
    const result = await this.rpc<{
      node_info: { network: string };
      sync_info: {
        latest_block_height: string;
        earliest_block_height: string;
        catching_up: boolean;
      };
    }>('/status');

    return {
      chainId: result.node_info.network,
      latestHeight: Number(result.sync_info.latest_block_height),
      earliestHeight: Number(result.sync_info.earliest_block_height),
      catchingUp: result.sync_info.catching_up,
    };
  }

  async block(height: number): Promise<BlockTxs> {
    const result = await this.rpc<{
      block: { header: { time: string }; data: { txs: string[] | null } };
    }>(`/block?height=${height}`);

    return {
      height,
      time: new Date(result.block.header.time),
      txs: result.block.data.txs ?? [],
    };
  }

  /**
   * The DELIVERTX code, read from the transaction index.
   *
   * NOT the broadcast code. Cosmos SDK v0.50 does not execute the message in
   * `CheckTx`, so a sync broadcast reports `code: 0` for transactions the DID
   * module will reject; every rejection during spikes S-1 and S-4 was initially
   * read wrong for exactly that reason.
   *
   * Returns `null` when the node cannot answer — typically because the tx
   * indexer is off (`[tx_index] indexer = "null"`). THE CALLER MUST TREAT NULL
   * AS "IT PROBABLY HAPPENED". A watcher that assumed an unreadable result was
   * a failure would silently discard the alarm for a successful eviction, which
   * is precisely the direction this system must never fail in.
   */
  async deliveredTxResult(txHashHex: string): Promise<DeliveredTxResult | null> {
    try {
      const result = await this.rpc<{ tx_result: { code?: number; log?: string } }>(
        `/tx?hash=0x${txHashHex}`,
      );
      return { code: result.tx_result.code ?? 0, log: result.tx_result.log ?? '' };
    } catch (error) {
      logger.warn('comet_tx_result_unavailable', {
        txHash: txHashHex,
        error: error instanceof Error ? error.message : String(error),
        consequence:
          'The delivery code is unknown. It is being treated as a committed change, because ' +
          'the alternative is discarding the alarm for a successful one.',
      });
      return null;
    }
  }

  private async rpc<T>(path: string): Promise<T> {
    const endpoint = `${this.rpcUrl}${path}`;
    let response: Response;
    try {
      response = await fetch(endpoint, { signal: AbortSignal.timeout(this.timeoutMs) });
    } catch (error) {
      throw new CometBftRpcError(
        `unreachable: ${error instanceof Error ? error.message : String(error)}`,
        endpoint,
      );
    }

    const body = (await response.json()) as { result?: T; error?: { data?: string } };
    if (body.error) {
      throw new CometBftRpcError(body.error.data ?? JSON.stringify(body.error), endpoint);
    }
    if (!body.result) throw new CometBftRpcError('no result in RPC response', endpoint);
    return body.result;
  }
}
