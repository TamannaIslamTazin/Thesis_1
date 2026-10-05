#!/usr/bin/env bash
#
# Watch for newly minted patient DIDs and register them into the stub resolver.
#
# WHY IT EXISTS. Enrolment mints a DID and hands it to the locker a few hundred
# milliseconds later, so there is no moment at which the stub could have been
# loaded by hand. The locker cannot read the chain itself on this deployment:
# the LCD answers "Not Implemented" for cheqd DID queries even with `[api]`
# bound to 0.0.0.0 (steno #392), and this host's firewall drops
# container-to-host traffic, so it cannot reach the backend either (#347).
#
# DEVELOPMENT ONLY. Nothing in a production path depends on this.
#
# ---------------------------------------------------------------------------
# IT MUST BE GENTLE WITH THE BACKEND, AND THAT IS NOT A STYLE POINT.
# ---------------------------------------------------------------------------
# `/api/*` sits behind a 100-request / 15-minute per-IP limiter. An earlier
# version of this script polled every 200ms and, on restart, re-registered
# every DID it had ever seen because its in-memory `seen` set began empty. That
# alone tripped the limiter, and the failure surfaced ON THE HANDSET as "Too
# many authentication attempts" during enrolment — the tool broke the thing it
# was written to unblock, and looked like an app bug while doing it (8 Sep).
#
# So: `seen` is primed from the STUB, which is free to query, and the backend
# is called at most once per genuinely new DID.
set -uo pipefail
cd "$(dirname "$0")/.."

STUB="${STUB_URL:-http://127.0.0.1:4599}"
POLL_SECONDS="${POLL_SECONDS:-1}"
seen=""

# Prime from the stub so a restart costs ZERO backend requests.
prime() {
  local dids="$1"
  for d in $dids; do
    if curl -s -o /dev/null -w '%{http_code}' --max-time 3 \
         "$STUB/cheqd/did/v2/$d" 2>/dev/null | grep -q '^200$'; then
      seen="$seen $d"
    fi
  done
  echo "$(date +%H:%M:%S) primed: $(wc -w <<<"$seen") DIDs already in the stub"
}

query_dids() {
  # HOLDERS ('User') *AND* INSTITUTIONS ('Institution').
  #
  # Scanning only "User" left every L1 authority unresolvable, and the failure
  # surfaces far from its cause: the issuer console asks the locker to verify a
  # capability the INSTITUTION's DID signed, the locker resolves that DID, gets
  # nothing, and refuses with
  #
  #   404 {"error":"The resolver answered: no DID document for
  #        'did:cheqd:...cb977556...'","code":"DID_NOT_FOUND"}
  #
  # — while the DID is perfectly valid on the ledger. Measured 23 Sep 2026 on
  # the BMDC medical-licence queue. A holder-only query can never fix it,
  # because institution DIDs are never rows in "User".
  PGPASSWORD=postgres psql -h localhost -U postgres -d ssi_healthcare -At \
    -c "SELECT did FROM \"User\" WHERE did IS NOT NULL AND did LIKE 'did:cheqd:%'
        UNION
        SELECT did FROM \"Institution\" WHERE did IS NOT NULL AND did LIKE 'did:cheqd:%';" 2>/dev/null
}

prime "$(query_dids)"

while true; do
  for d in $(query_dids); do
    case " $seen " in *" $d "*) continue ;; esac
    if node scripts/bridge-did-to-stub.mjs "$d" >/dev/null 2>&1; then
      echo "$(date +%H:%M:%S) bridged $d"
      seen="$seen $d"
    else
      # Mark it seen anyway. Retrying a DID the backend cannot resolve — a
      # malformed probe artefact, or a 429 — every second is exactly how the
      # limiter got tripped. One attempt each; a real one will be caught on the
      # next restart.
      echo "$(date +%H:%M:%S) could not bridge $d (will not retry this run)"
      seen="$seen $d"
    fi
  done
  sleep "$POLL_SECONDS"
done
