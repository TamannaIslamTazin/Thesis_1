/**
 * Register a REAL on-chain DID into the stub resolver, in the cheqd Cosmos REST
 * shape the locker parses.
 *
 * WHY THIS IS NEEDED, and what it does NOT claim.
 *
 * The locker authenticates by resolving the holder's DID and checking the
 * signature against a key listed under `authentication`. In production it
 * would read that from the chain's Cosmos REST API. On this deployment it
 * cannot, and the reason is worth writing down because it looks like a
 * configuration mistake and is not:
 *
 *   - The validator's `[api]` address was bound to `tcp://localhost:1317`
 *     INSIDE the container, so docker port publishing forwarded to an
 *     interface nothing was listening on (steno #333). Fixed 8 Sep 2026 by
 *     binding `0.0.0.0`; the LCD now answers.
 *   - But it answers `{"code":12,"message":"Not Implemented"}` for
 *     `/cheqd/did/v2/did_doc/<did>`. The cheqd module does not register
 *     grpc-gateway routes on this build, so the REST DID query does not exist
 *     to be reached. That is a chain-side gap, not a binding one, and it
 *     confirms the open finding in steno #392.
 *   - The locker containers cannot reach the backend (which CAN resolve, via
 *     Credo/ABCI) because this host's firewall drops bridge-to-host traffic
 *     (steno #347), so pointing the locker at `host.docker.internal` is not
 *     available either.
 *
 * So: this script reads the document from the backend resolver — which reads
 * the LEDGER — and hands it to the stub. The KEY MATERIAL AND SHAPE ARE REAL
 * and come from the chain, so the locker's signature verification, multicodec
 * check, `authentication`-relationship check and replay CAS are all genuinely
 * exercised against a real identity.
 *
 * WHAT IT IS STILL NOT EVIDENCE FOR: that we parse a real cheqd node's REST
 * response correctly. A stub cannot prove agreement with the dependency it
 * impersonates. #392 stays open until the chain serves the query itself.
 *
 * Usage:
 *   node scripts/bridge-did-to-stub.mjs <did> [...more dids]
 * Env:
 *   BACKEND_URL  default http://127.0.0.1:3001
 *   STUB_URL     default http://127.0.0.1:4599
 */

const BACKEND = process.env.BACKEND_URL ?? 'http://127.0.0.1:3001';
const STUB = process.env.STUB_URL ?? 'http://127.0.0.1:4599';

/** W3C DID document (backend shape) -> cheqd Cosmos REST envelope (locker shape). */
function toCheqdRestEnvelope(doc) {
  return {
    value: {
      did_doc: {
        id: doc.id,
        controller: doc.controller ?? [],
        verification_method: (doc.verificationMethod ?? []).map((vm) => ({
          id: vm.id,
          // The locker reads `verification_method_type`, not `type`.
          verification_method_type: vm.type,
          controller: vm.controller,
          // ...and `verification_material`, not `publicKeyMultibase`.
          verification_material: vm.publicKeyMultibase ?? vm.publicKeyBase58 ?? '',
        })),
        authentication: doc.authentication ?? [],
        // CARRIED, because the locker now accepts it. An institutional DID can
        // hold only ONE `authentication` key (reserved for the ledger
        // operator), so any other party's key — a council's own issuer console —
        // can only ever appear here. Dropping it during the bridge made the
        // locker's new check silently always false: the code looked right and
        // refused every council.
        assertion_method: doc.assertionMethod ?? [],
      },
      metadata: { deactivated: Boolean(doc.deactivated) },
    },
  };
}

const dids = process.argv.slice(2);
if (dids.length === 0) {
  console.error('usage: node scripts/bridge-did-to-stub.mjs <did> [...]');
  process.exit(2);
}

let failed = 0;
for (const did of dids) {
  try {
    const res = await fetch(`${BACKEND}/api/dids/${encodeURIComponent(did)}`);
    if (!res.ok) throw new Error(`backend answered ${res.status} for ${did}`);
    const body = await res.json();
    const doc = body.data ?? body;
    if (!doc?.id) throw new Error(`backend returned no DID document for ${did}`);

    const envelope = toCheqdRestEnvelope(doc);
    // Refuse to register something the locker could never authenticate with.
    const vmCount = envelope.value.did_doc.verification_method.length;
    const authCount = envelope.value.did_doc.authentication.length;
    if (vmCount === 0 || authCount === 0) {
      throw new Error(
        `${did} has ${vmCount} verification methods and ${authCount} authentication entries; ` +
          'the locker would refuse it, so registering it would only move the failure later',
      );
    }

    const reg = await fetch(`${STUB}/_control/subjects`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ did, document: envelope }),
    });
    if (!reg.ok) throw new Error(`stub answered ${reg.status}`);
    const out = await reg.json();
    console.log(
      `registered ${did}\n  vms=${vmCount} auth=${authCount} assert=${(envelope.value.did_doc.assertion_method ?? []).length} ` +
        `key=${envelope.value.did_doc.verification_method[0].verification_material.slice(0, 12)}… ` +
        `(stub now holds ${out.total})`,
    );
  } catch (error) {
    failed += 1;
    console.error(`FAILED ${did}: ${error.message}`);
  }
}
process.exit(failed === 0 ? 0 : 1);
