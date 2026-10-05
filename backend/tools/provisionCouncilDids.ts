/**
 * Mint the three professional council DIDs on chain.
 *
 * BMDC, BNMC and PCB have been placeholders since the trust roots were written
 * — `did:cheqd:…:11111111-…` and friends, which resolve to nothing. Everything
 * downstream is built and blocked on them: `authoriseProfessional` reduces to
 * "the issuer must be a pinned root", professional licences cannot be issued at
 * all, and the HMS refuses every clinical login because the accreditation it
 * checks can never verify.
 *
 * One agent for all three, deliberately: three separate script runs mean three
 * Credo startups and three chances to mint one, fail, and leave the registry
 * half real — which is worse than all-placeholder, because it looks finished.
 *
 *   npx tsx tools/provisionCouncilDids.ts
 */
import { createAgent, shutdownAgent } from '../src/agent/index.js';
import { provisionInstitutionalDid } from '../src/services/institutionalDid.js';
import { resolveOnChain } from '../src/services/cheqdLedger.js';

const COUNCILS = [
  { shortName: 'BMDC', name: 'Bangladesh Medical and Dental Council' },
  { shortName: 'BNMC', name: 'Bangladesh Nursing and Midwifery Council' },
  { shortName: 'PCB', name: 'Pharmacy Council of Bangladesh' },
] as const;

async function main() {
  const agent = await createAgent();
  const minted: Array<{ shortName: string; did: string; officers: number }> = [];

  for (const council of COUNCILS) {
    // Three officers, matching MOHFW. A council that can issue licences for a
    // whole profession must not be a 1-of-1 whose single lost key freezes every
    // future licence in that register (#276).
    const result = await provisionInstitutionalDid(agent, {
      officers: [
        { kind: 'agent-generated' },
        { kind: 'agent-generated' },
        { kind: 'agent-generated' },
      ],
      purpose: `${council.name} (${council.shortName}) — L1 professional licence authority`,
    });

    // READ IT BACK FROM THE CHAIN, not from the agent's cache: a cached document
    // is exactly what a failed write looks like.
    const onChain = await resolveOnChain(agent, result.did);
    const officers = onChain?.verificationMethod?.length ?? 0;
    if (officers !== 3) {
      throw new Error(`${council.shortName}: expected 3 verification methods on chain, saw ${officers}`);
    }

    minted.push({ shortName: council.shortName, did: result.did, officers });
    console.log(`${council.shortName.padEnd(5)} ${result.did}  (${officers} officer keys, read back from chain)`);
  }

  console.log('\n--- paste into packages/shared/src/accreditation/index.ts ---');
  for (const m of minted) {
    console.log(`${m.shortName}: '${m.did}'`);
  }

  await shutdownAgent();
  process.exit(0);
}

void main();
