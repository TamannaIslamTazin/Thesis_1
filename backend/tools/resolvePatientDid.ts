/**
 * Resolve a patient DID from the chain and print its verification method.
 *
 * Written to verify that enrolment installs the DEVICE's key as `#key-1`. The
 * property being checked is that the key on chain is one this backend cannot
 * sign for; `agentSigner` refusing is the positive signal, not a fault.
 *
 *   npx tsx tools/resolvePatientDid.ts <did>
 */
import { createAgent, shutdownAgent } from '../src/agent/index.js';
import { resolveOnChain, agentSigner } from '../src/services/cheqdLedger.js';

async function main() {
  const did = process.argv[2];
  if (!did) throw new Error('usage: resolvePatientDid.ts <did>');

  const agent = await createAgent();
  const doc: any = await resolveOnChain(agent, did);

  console.log(JSON.stringify({
    id: doc.id,
    controller: doc.controller,
    verificationMethod: (doc.verificationMethod ?? []).map((v: any) => ({
      id: v.id,
      controller: v.controller,
      publicKeyMultibase: v.publicKeyMultibase,
    })),
    authentication: doc.authentication,
  }, null, 2));

  try {
    await agentSigner(agent, did);
    console.log('\nagentSigner: SUCCEEDED — the backend still holds a key for this DID.');
  } catch (error) {
    console.log(`\nagentSigner: refused (${(error as Error).message.slice(0, 120)})`);
    console.log('That refusal is the property: the private half is on the handset.');
  }
  await shutdownAgent();
  process.exit(0);
}

main().catch((error) => {
  console.error('ERR', (error as Error)?.message ?? error);
  process.exit(1);
});
