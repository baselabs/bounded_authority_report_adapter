# 13. The published conformance corpus is the acceptance oracle

Date: 2026-08-17

## Status

Accepted. Records RA2's acceptance posture (in force since 2026-08-09); until
now the decision lived only in the ROADMAP RA2 row and the harness itself —
`.forge/conformance-surfaces` pointed at "ROADMAP RA2 + charter §6" as its
authority, not an ADR. Authored when the 2026-08-17 alignment audit listed the
gap. Couples to ADR-0010 (the pin-bump policy's corpus clause).

## Context

RA2 needed an acceptance bar for "the adapter's output is byte-compatible with
BAP's verifiers + envelopes." The alternatives:

- **Self-signed fixtures** — BARA invents its own grant/proof pairs and verifies
  them. This proves a round-trip, not conformance: both sides of the test could
  agree on a wire format BAP never published (the self-signed-fixture trap).
- **BAP's published conformance corpus** — the vectors under
  `priv/conformance/v1/` at the pinned ref (`corpus/`, `schemas/`, `vectors/`),
  each case carrying a declared `expected_verdict` BAP's own conformance suite
  asserts.

The corpus is the only oracle whose green MEANS "BAP accepts what BARA produces."

## Decision

1. **BAP's published vector corpus defines BARA's green.** Every published
   ENVELOPE case verifies via `check_envelope/2` and every GRANT-TIME case via
   `verify_grant/3`, matching each declared `expected_verdict` — data-driven
   per verdict, with an exhaustive-coverage guard so a newly published case
   cannot be silently untested.
2. **Defect-injection keeps the harness non-vacuous** (a green harness over a
   broken contract is the failure class this decision exists to prevent):
   signature-flip and `ba_req` tamper tripwires go RED, plus the corpus's own
   published `tamper_verdicts`.
3. **An adapter-coherent round-trip closes the loop from BARA's side:**
   `sign_report/3` → `check_envelope/2` against a freshly issuer-signed grant —
   the corpus proves BARA consumes BAP's format; the round-trip proves BARA
   produces it.
4. **Re-verified at EVERY pin bump** — the corpus at the new pin is the oracle
   for the new pin. This is ADR-0010's corpus clause from the consumption side:
   corpus growth inside an accepted bump span is admitted only with this
   harness green at the new ref (growth can only ADD cases — a stricter oracle,
   never a relaxation).

## Consequences

- Wire-format drift between BARA and BAP surfaces as a RED harness at the next
  build, not as silent divergence in production.
- The harness's own wrongness (a vacuous-green round-trip, a mis-built
  `cast_arguments`, a shared-nonce assumption) ships a broken crypto contract
  QUIETLY — which is why the harness is itself a declared critical surface
  (`.forge/critical-surfaces`) and its re-execution runner exists
  (`.forge/conformance-verify.sh`, layer-iii; not yet wired into CI — the ops
  follow-on it records).
- BARA's green is deliberately defined by ANOTHER repo's published artifacts:
  that coupling is the point (strategy §7), and ADR-0010 governs when the pin
  may move.
