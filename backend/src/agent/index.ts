/**
 * SSI Healthcare Backend - Credo TS Agent Setup
 *
 * Initializes the Credo (formerly Aries Framework JavaScript) agent with:
 * - Askar wallet for key/credential storage
 * - Cheqd module for DID registration on our sovereign chain (bdhealthtestnet)
 * - DID and VC module configuration
 *
 * The agent is the core SSI engine that handles all DID, VC, and VP operations.
 *
 * Updated for Credo TS 0.6.x (ESM, new AskarModule API)
 */

// IMPORTANT: askar-nodejs MUST be imported before @credo-ts/askar.
// @credo-ts/askar uses ESM static imports of @openwallet-foundation/askar-shared,
// which captures `askar` as undefined if loaded before askar-nodejs calls registerAskar().
// Importing askar-nodejs first ensures registerAskar() runs before the ESM namespace
// for askar-shared is created, so the binding resolves to the real NodeJSAskar instance.
import { askar } from '@openwallet-foundation/askar-nodejs';
import {
  Agent,
  DidsModule,
  KeyDidRegistrar,
  KeyDidResolver,
  W3cCredentialsModule,
  W3cV2CredentialsModule,
  ConsoleLogger,
  LogLevel,
} from '@credo-ts/core';
import { agentDependencies } from '@credo-ts/node';
import { AskarModule } from '@credo-ts/askar';
import {
  CheqdModule,
  CheqdDidRegistrar,
  CheqdDidResolver,
} from '@credo-ts/cheqd';
import { config } from '../config/index.js';
import { logger } from '../utils/logger.js';

/** Singleton agent instance. */
let agentInstance: Agent | null = null;

/**
 * Create and initialize the Credo TS agent.
 *
 * This agent handles:
 * - DID creation/resolution (did:key for local, did:cheqd for on-ledger)
 * - Verifiable Credential issuance (W3C Data Model v2)
 * - Verifiable Presentation creation and verification
 *
 * @returns Initialized Credo Agent
 */
export async function createAgent(): Promise<Agent> {
  if (agentInstance) {
    return agentInstance;
  }

  logger.info('Initializing Credo TS agent', {
    label: config.agentLabel,
    cheqdNetwork: config.cheqdNetwork,
  });

  // Credo 0.6.x uses a new configuration structure
  const agent = new Agent({
    config: {
      logger: new ConsoleLogger(
        config.nodeEnv === 'development' ? LogLevel.debug : LogLevel.warn,
      ),
    },
    dependencies: agentDependencies,
    modules: {
      // Secure wallet storage via Aries Askar (new 0.6 API)
      askar: new AskarModule({
        askar,
        store: {
          id: config.agentWalletId,
          key: config.agentWalletKey,
        },
      }),

      // DID methods: did:key (local/ephemeral) + did:cheqd (on-ledger)
      dids: new DidsModule({
        registrars: [new KeyDidRegistrar(), new CheqdDidRegistrar()],
        resolvers: [new KeyDidResolver(), new CheqdDidResolver()],
      }),

      // Cheqd network for DID and credential status.
      //
      // `rpcUrl` is forwarded deliberately. It was previously omitted, so Credo
      // fell back to `DefaultRPCUrl` for the named network and every read went
      // to PUBLIC cheqd testnet — a chain we do not control, which has already
      // destroyed ~1.5 days of state (including DIDs) in a documented upgrade
      // incident. It now points at our sovereign fork, where identity writes
      // are free and the ledger cannot be reset out from under a demo.
      //
      // That fallback no longer exists to be relied on: the @credo-ts/cheqd
      // patch deletes `DefaultRPCUrl` and throws when `rpcUrl` is absent, so
      // this can never again silently degrade to a public endpoint. Forwarding
      // it is now mandatory rather than merely correct.
      //
      // `network` is our own name (`bdhealthtestnet`), not cheqd's `testnet`.
      // Credo selects the SDK instance by matching this against the network
      // segment of the DID being operated on, so it must equal what
      // `didService` puts into new DIDs — which is why both read it from
      // `config` rather than repeating a literal.
      cheqd: new CheqdModule({
        networks: [
          {
            network: config.cheqdNetwork,
            rpcUrl: config.cheqdRpcUrl,
            // The key that signs DID writes. Reads work without it; writes do
            // not. It is a freshly generated 24-word mnemonic held only in
            // packages/backend/.env — deliberately NOT one of the chain's
            // genesis accounts, all of which use cheqd's upstream test
            // mnemonics published in plaintext in a public repository.
            //
            // Empty is a legal value meaning "this deployment only resolves".
            // See the COSMOS_PAYER_SEED block in config/index.ts.
            cosmosPayerSeed: config.cosmosPayerSeed,
          },
        ],
      }),

      // W3C Verifiable Credentials — BOTH data models, deliberately.
      //
      // Credo 0.6 implements VC 2.0 as a wholly separate stack rather than an
      // option on the v1 one: W3cV2CredentialsModule / W3cV2Credential /
      // ClaimFormat.JwtW3cVc, with its own service, repository and record type
      // (`W3cV2CredentialRecord` vs `W3cCredentialRecord`).
      //
      // THE TWO COEXIST, so this is a phased migration and not a cutover.
      // Verified in the installed package, not assumed:
      //   - The two modules register disjoint singletons. The only shared token
      //     is `SignatureSuiteRegistry`, and both register the same class, so
      //     the second registration is a no-op rather than a conflict.
      //     (W3cCredentialsModule.mjs / W3cV2CredentialsModule.mjs)
      //   - Storage cannot collide: the record `type` discriminators differ.
      //   - v1 is a DEFAULT module — `getDefaultAgentModules()` at
      //     agent/AgentModules.mjs:33 always adds `w3cCredentials`, and
      //     `extendModulesWithDefaultModules` gives no way to remove it. So v1
      //     is registered whether we ask for it or not; "cutting over" is not
      //     something Credo offers.
      //   - Conversely `BaseAgent` resolves `W3cV2CredentialsApi`
      //     unconditionally at BaseAgent.mjs:36, so `agent.w3cV2Credentials`
      //     exists regardless. Registering the module here is what makes its
      //     services singletons rather than per-resolution instances.
      //
      // Consequence we depend on: credentials issued as VC 1.1 before this
      // migration stay verifiable through `agent.w3cCredentials`, while new
      // issuance goes through `agent.w3cV2Credentials`.
      w3cCredentials: new W3cCredentialsModule(),
      w3cV2Credentials: new W3cV2CredentialsModule(),
    },
  });

  await agent.initialize();

  logger.info('Credo TS agent initialized successfully');
  agentInstance = agent;
  return agent;
}

/**
 * Get the current agent instance.
 * @throws If agent has not been initialized.
 */
export function getAgent(): Agent {
  if (!agentInstance) {
    throw new Error('Agent not initialized. Call createAgent() first.');
  }
  return agentInstance;
}

/**
 * Gracefully shut down the agent and release resources.
 */
export async function shutdownAgent(): Promise<void> {
  if (agentInstance) {
    logger.info('Shutting down Credo TS agent');
    await agentInstance.shutdown();
    agentInstance = null;
  }
}
