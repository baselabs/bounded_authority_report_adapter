# 9. Key-transition signing (the 4th companion-signer instantiation)

Date: 2026-08-12

## Status

Accepted. Implements — does not supersede — ADR-0006; the universal companion-signer scope
and the shared signing tail are ADR-0006's, unchanged. Records the concrete decision RA8
(ROADMAP `b2-ra-key-transition`) made: `sign_key_transition/3` is **role-agnostic, mirroring
`sign_anchor/3`** — NOT role-gated like `sign_grant/3`. This ADR records WHY the role-gated
alternative (the first design draft) was rejected, so the durable record does not bake in a
phantom authority generalization the design-adversarial pass caught.

## Context

ADR-0006 named the library as BAP's universal companion signer (proof, grant, boundary
anchor, key transition); ADR-0006 §Decision 2 says "the pattern generalizes; grant/key-
transition signing are named extensions" — where *the pattern* is the shared signing tail
(`sign_via_handle → verify_signature → assemble_compact`), NOT the C1 role gate (the
§grant-signing pre-commitment is grant-specific). ADR-0007 realized grant signing (the 3rd
instantiation) with a NEW optional callback `signing_identity/1` returning `{:role, key_id,
public_key}`, gated on `:issuer` (the C1 gate). ADR-0007 §Decision 4 explicitly scoped
`signing_identity/1` to **grant-only** and kept `sign_anchor/3` on the role-agnostic
`key_identity/1` — "each scoped to the operation that needs it." ADR-0007 line 92-94 framed
this slice: "key-transition signing (RA8) — the fourth instantiation, design-gated on its
own BAP-contract read (`key_transition_signing_input`)."

The BAP contract (read first-hand at the pinned ref): `KeyTransition` carries
`current_{key_id, public_key}` + `next_{key_id, public_key}` + `transition_id` + `chain_id`
+ `effective_at` — **no role field**. `verify_key_transition/4` takes two `%HistoricalPublicKey{}`
structs (role-neutral — the SAME input type `verify_historical_anchor/3` takes) plus an
`ExpectedKeyTransition`; the signature verifies against `current_key.public_key` (the retiring
current key signs its successor).

## Decision

1. **`sign_key_transition/3` is the 4th instantiation, mirroring `sign_anchor/3`** — role-
   agnostic. It takes the transition's content + a key-handle, resolves the current key's
   identity atomically via `key_identity/1` (the EXISTING anchor callback), and returns
   `%{key_transition: compact}`, reusing the shared `sign_and_assemble/3` tail unchanged.

2. **Role-agnostic, NOT issuer-gated.** The current key's `{current_key_id, current_public_key}`
   come from ONE atomic `key_identity/1` snapshot. There is NO role gate (no `signing_identity/1`
   call, no `:issuer` check). Four independent authorities converge here (the design §1.3):
   - **The verify contract.** `verify_key_transition/4` takes `HistoricalPublicKey` ×2
     (role-neutral); `verify_grant/3` takes `TrustedIssuer` (an issuer-role concept). The
     signing-side callback mirrors the verify-side contract: anchor-shaped → `key_identity/1`.
   - **ADR-0007 §Decision 4.** `signing_identity/1` is grant-only; the anchor keeps
     `key_identity/1`. Reusing `signing_identity/1` for the transition would extend a callback
     beyond the grant-only boundary that decision drew.
   - **ADR-0006's universal posture.** The library signs for "whichever party holds the right
     key"; the right key for a transition is the current key. Role-gating would re-impose the
     narrow issuer-only framing ADR-0006 rejected.
   - **Charter §5 (the anchor posture).** "any holder of the right key"; authenticity is the
     signature against `current_key.public_key`, not a role binding.

3. **Key-identifier sourcing (ADR-0006 decision 3).** `current_{key_id, public_key}` come from
   the atomic `key_identity/1` snapshot (the signing key IS the retiring current key; same as
   `sign_anchor/3`'s kid+pub). A caller-supplied `:current_key_id` / `:current_public_key` is
   ignored. `next_{key_id, public_key}` are caller-supplied (the successor — the retiring key's
   owner knows it at mint time, parallel to grant's caller-supplied `holder_thumbprint`).

4. **`next_public_key` is pre-checked for 32 bytes** in `build_key_transition/3` (fail-fast
   `:invalid_transition`). Principle: the adapter pre-checks PUBLIC KEYS for 32 bytes
   (`resolve_public_key/1`, `resolve_key_identity/1`, `resolve_signing_identity/1`); caller-
   supplied 32-byte public keys get the same pre-check; caller-supplied DIGESTS (grant's
   `holder_thumbprint`) defer to BAP. A self-transition (`next_public_key == current_public_key`)
   is NOT pre-checked — BAP's `distinct_fingerprints` rejects it at produce-time as
   `{:producer_error, :invalid}`.

## The rejected alternative (recorded in full — the design-adversarial reversal)

The first design draft gated `sign_key_transition/3` on `:issuer` (reusing `signing_identity/1`,
mirroring `sign_grant/3`). Its rationale was "ADR-0006 §grant-signing pre-commitment generalized
to any issuer-key operation." A fresh-context design-adversarial pass (pre-registered against the
authority chain BEFORE reading the design) caught that this is a **phantom generalization**:
ADR-0006's pre-commitment is grant-specific (names "grant" four times, grounds in ADR-0002's
grant C1 correction); "the pattern generalizes" (ADR-0006 §Decision 2) is the signing *tail*,
not the role gate. The pass further noted the verify contract is anchor-shaped
(`HistoricalPublicKey`, not `TrustedIssuer`), ADR-0007 §Decision 4 scopes `signing_identity/1`
to grant-only, and ADR-0007:92-94 frames RA8 as contract-gated (the role-neutral BAP contract),
not role-gated.

The strongest case FOR the rejected alternative (stated fully, not as a strawman): in the BA
deployment reality the retiring key IS an issuer key (the authority's key chain rolls; holders
don't transition, they get a new grant bound to a new thumbprint), so a role gate would be
defense-in-depth against a holder handle misconfigured to sign a transition; and an issuer handle
already implements `signing_identity/1` for grants, so reusing it imposes no new callback on issuers.

The alternative was **rejected on mechanism**: (a) it extends `signing_identity/1` beyond the
grant-only boundary ADR-0007 §Decision 4 drew, with no authority generalizing the C1
pre-commitment; (b) the verify contract is `HistoricalPublicKey` (role-neutral), so the signing-
side callback must mirror the verify-side contract; (c) the transition's authenticity is the
signature, not a role binding — identical to the anchor ADR-0007 deliberately kept role-agnostic;
(d) a holder-signed transition is already rejected at verify time (the signature verifies against
`current_key.public_key`, which the verifier pins via `HistoricalPublicKey`) unless the verifier
MISpublished a holder key as a historical issuer key — a deployment error the signer cannot
prevent.

## The declaration-rejection residual (and why no signing-side role gate is owed)

The C1 declaration-rejection property (ADR-0007 §Decision 5) is **grant-only**: a handle that
declares `:holder` cannot sign a GRANT through `sign_grant/3`. `sign_key_transition/3` carries
no role gate by design — it signs for any handle implementing `key_identity/1`. This is NOT an
open forge: the verify-side `HistoricalPublicKey` check is the authority binding. A transition
signed by a "wrong" key (whatever its role) verifies ONLY against a verifier-published
`HistoricalPublicKey` whose `public_key` matches the signing key — i.e. only if the verifier
published that key as a historical key in the chain. The signing adapter cannot prevent a
deployment from publishing the wrong historical key; that is a verifier-side / custody concern.

If the program later wants a signing-side role assertion for transitions as additional
defense-in-depth, that would be a NEW slice (a transition role-attestation). Note RA11
(role-attestation consumption) is grant-scoped in the ROADMAP (`sign_grant/3` + the C1 gate,
verifier-side `TrustedIssuer`); a transition role-attestation is not "RA8 = RA11's job."

## Consequences

- The key-handle contract is unchanged: `key_identity/1` (optional) is now used by `sign_anchor/3`
  AND `sign_key_transition/3`; `signing_identity/1` (optional) remains grant-only. `@optional_callbacks`
  unchanged. `RawKey` (the test reference handle) already implements `key_identity/1` →
  `{"test-anchor-key-001", pub}`, so it signs transitions (the role-agnostic path needs no
  `signing_identity/1`).
- The tripwires (ROADMAP RA8 acceptance): wrong-key + atomic-snapshot drift (the
  `verify_signature` guard — `TransitionWrongKeyHandle`, `TransitionRacingKeyIdentityHandle`),
  no canonical-bytes fork (`TransitionCapturingKeyHandle`), defect injection (a tampered
  transition byte rejected by `verify_key_transition/4`), self-transition (BAP's
  `distinct_fingerprints`). The wrong-key + racing tripwires are mutation-proven (disabling
  `verify_signature` drives them RED).
- The universal companion-signer's four named instantiations are complete: proof (RA1),
  boundary-anchor (RA4), grant (RA7), key-transition (RA8) — all through the shared tail. The
  C1 issuer-role gate stays grant-only, exactly as ADR-0007 §Decision 4 scoped it.
