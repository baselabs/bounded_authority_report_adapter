# 1. Report-adapter topology: holder-side signer in a three-role split

Date: 2026-08-10

## Status

Accepted. Records decisions in force since the scaffold (2026-08-09); authored
retroactively when the ADR gap was flagged by the 2026-08-10 alignment audit.

## Context

The bounded-authority model is DPoP-shaped (RFC 9449) with three distinct roles:

- **Issuer** — mints + signs capability *grants*; owns key custody, rotation,
  revocation.
- **Holder** — proves possession of a key bound to a specific request by signing
  a *proof* over the grant + request.
- **Verifier** — checks grants, proofs, and envelopes against published keys.

`bounded_authority_protocol`'s ADR 0001 ("Public protocol verifier and private
authority runtime") fixed where two of the three roles live: BAP is the **public
verifier + signing-input producer**; the `bounded_authority` runtime service is
the **private issuer**. The question this ADR answers is the third role: where
does the **holder-side** signing of application reports live?

The holder role cannot collapse into either existing party:

- Not the verifier (BAP) — BAP refuses to hold keys or sign (its charter); it
  produces signing *inputs* only.
- Not the issuer (runtime) — the whole point is the reporter proves possession
  *locally on the edge*, without a round-trip to the authority.
- Not the verifier (verifier application) — verifier application's dependency-direction wall
  forbids it from depending on anything that signs (so a compromised app cannot
  forge authority; see ADR 0003).

## Decision

The holder-side signing lives in **this repo** — `bounded_authority_report_adapter`,
a separate composable library. The adapter is the **HOLDER**:

- It receives an issuer-signed `grant_compact` as an **input**.
- It signs a **holder proof** binding that grant to the report's request fields.
- It returns `{grant, proof}` — the grant untouched, the proof freshly signed.

It is neither issuer (the runtime) nor verifier (BAP, called by the verifier). The three roles map to three repos:

| Role | Repo | Signs? | Verifies? |
|---|---|---|---|
| Issuer | `bounded_authority` (runtime) | grants at issuance | revocation-sensitive decisions |
| **Holder** | **this adapter** | holder proofs on reports | — |
| Verifier | `bounded_authority_protocol` | — | grants, proofs, envelopes |

The verifier (verifier application) verifies via BAP's `check_envelope/2` and never
depends on this adapter (ADR 0003).

## Consequences

- The holder key is held at the edge, never in the verifier or the
  protocol package. Only the public key + signatures cross the boundary.
- A captured api_key alone cannot forge a report; a captured transport cannot
  re-purpose one. S1 closed transport identity; B2 closes capability authority.
- This ADR is the local counterpart to BAP's ADR 0001 (which fixed the
  verifier/issuer placement). The separate-repo *rationale* and the
  private-not-hex *posture* are recorded in ADR 0005 and ADR 0004.
