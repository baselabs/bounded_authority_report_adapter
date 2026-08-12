# 8. Role-attestation direction (BA-asserted role binding for the C1 gate)

Date: 2026-08-11

## Status

**Proposed.** Not yet decided or implemented. Records the strengthening path for the C1
gate's conceded residual (ADR-0007 §Decision 5) + the three-repo split, so each repo's
session has the full picture when the program elects to pursue it. Becomes `Accepted` if/when
a BAP-side `RoleAttestation` design lands and the program commits to one of the trigger
conditions in §Decision.

## Context

ADR-0007 §Decision 5 states the C1 gate's precise property — **declaration-rejection, not
cryptographic key-role separation**: a handle that consistently mis-declares its role
(`signing_identity/1` returns `{:issuer, holder_key_id, holder_public_key}` while `sign/2`
holds the matching holder private key) signs a grant successfully, because every value is
internally consistent. BARA resolves only the handle's `public_key` and signs against it; it
cannot prove which private key sits behind the handle. Key-role separation is structurally
the custody boundary's job (charter §4 — BA).

This ADR evaluates the natural strengthening: a **BA-signed role-attestation**. Instead of
the handle self-declaring its role, BA (the authority — the embeddable runtime / eventual
Auth0-like service for agents + attestation) signs a `RoleAttestation{key_id, public_key,
role, valid_window}` at key provisioning; BARA consumes it at sign time.

### The load-bearing threat-model fact

A forged-role grant is **already defeated at the verifier, not the signer.** Trace the
"lying handle" case through the full system: a holder handle declares `:issuer`, so
`sign_grant/3` mints a grant signed by the holder key, `kid = holder_kid`. That compact is
handed to a verifier (`BAP.verify_grant/3` / `check_envelope/2`), which checks the grant
signature against `TrustedIssuer.public_key` — the *real* issuer's key. Holder key ≠ real
issuer key → signature verify fails → the grant is rejected at **every** correctly-configured
verifier. The attacker produced a grant that verifies only against *their own* key, which no
relying party trusts as an issuer. For that grant to be *accepted*, the relying party's
`TrustedIssuer` config would have to point at the holder key — and if the trust config is
already compromised, the attacker doesn't need a role lie, they sign with whatever key the
trust root names.

So the declaration gate's conceded "consistent-lie" case does **not** open a
verifiable-against-the-real-issuer forge path. The authority binding is already enforced by
BAP's verifier-side `TrustedIssuer` key check. The role-attestation's value is therefore
**defense-in-depth + three concrete scenarios**, not gap-closing:
1. A library-level correctness property — "BARA cannot be made to *emit* a mis-roled grant,"
   stronger than "the verifier will catch it downstream." Matters if BARA is audited on what
   it emits.
2. **Multi-issuer / multi-tenant** — when BARA signs for several issuers (verifier application,
   commerce_platform, …) and the key→role→issuer mapping is dynamic, a BA-asserted role lets
   BARA enforce the binding without every relying party carrying every `TrustedIssuer`.
3. **Non-repudiation / audit** — a signed attestation is cryptographic evidence of *who*
   authorized a key to act as issuer (compliance/forensics).

## Decision (direction)

Pursue the role-attestation as a **three-repo change**, split exactly along the existing
repo roles. Each repo's session implements its piece:

| Repo | Role | Piece |
|---|---|---|
| **BAP** (`bounded_authority_protocol`) | the protocol | Define `RoleAttestation` — the struct, its signing-input producer, `verify_attestation/2`, the compact format. Same shape as grants/proofs/anchors. Until BAP specifies it, BARA has nothing to call. |
| **BA** (`bounded_authority`) | the authority / attestation service | Issue role-attestations at key provisioning (sign `{key_id, public_key, role, valid_window}` with a BA authority key). This is core to BA's "attestation service" product direction, not a side feature. Includes revocation when a key's role changes. |
| **BARA** (this repo) | the shipped SDK / signer | Consume it: `sign_grant/3` accepts the BA-signed attestation compact as an input (the same input class as `grant_compact`), calls `BAP.verify_attestation/2`, checks the attested role is `:issuer` and the attested `public_key` matches the handle's, then signs. |

BARA's piece is the smallest. The first move is a BAP-side `RoleAttestation` design; BARA's
change follows once BAP lands the verify.

### Why the split is forced (not a choice)

- **The dep wall (charter §6 / RA3).** BARA depends only on BAP; it cannot call into BA.
  So whatever produces the attestation signature sits across the wall — it's an *input* to
  BARA, the way `grant_compact` is already an input to `sign_report/3` (issuer-signed out of
  band, passed in). The attestation compact crosses the wall as data; BARA never imports BA.
- **"BARA does not verify" (charter §3).** Verification lives in BAP. So BARA doesn't
  *implement* attestation verification — it *calls* `BAP.verify_attestation/2`.
- **BARA is a signer, not a CA.** It holds one key (the signing key) behind the handle. It
  has no separate authority key to counter-sign with — a self-signed attestation is the
  declaration gate with extra steps (the same key vouching for its own role).

### Charter sharpening (the "BARA does not verify" line)

BARA already softens charter §3 once: it does a sign-time `:crypto.verify` for the wrong-key
guard (`verify_signature`, lib `sign_and_assemble/3`). Adding `BAP.verify_attestation/2` is
a second **sign-time gating verify** (is this key role-attested as `:issuer`?), not a content
verification (which stays the verifier's job). This sharpens charter §3 to: *"BARA does
sign-time gating verifies (wrong-key, role-attestation); it does not do content
verification (which is the verifier's job via BAP)."* Worth recording as a charter/ADR delta
when this lands.

## Consequences

- When landed, the C1 gate's residual (the consistent-lie) is closed by the BA authority key
  — forging a role requires compromising BA, not misconfiguring a handle.
- The key-handle contract gains an attestation input (a new shape alongside `key_identity/1`
  / `signing_identity/1`).
- BARA's dep wall holds (depends only on BAP; the attestation crosses as data).
- The strengthening is **gated on the trigger conditions** (§Context 1-3). For the current
  single-issuer model with the verifier-side `TrustedIssuer` check, the declaration gate
  (RA7, ADR-0007) is a complete authority binding; the attestation is defense-in-depth until
  the program adopts multi-issuer, an emit-correctness requirement, or a signed-role audit
  trail.
- Sequencing: **BAP first** (`RoleAttestation` + `verify_attestation`), **BA** (issuance +
  revocation), **BARA last** (the `sign_grant` input + the verify-call + the gate). ROADMAP
  row RA11 tracks BARA's piece with the cross-repo dependencies named.
