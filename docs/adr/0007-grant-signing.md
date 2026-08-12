# 7. Grant signing (the issuer-role companion-signer instantiation)

Date: 2026-08-11

## Status

Accepted. Records the RA7 realization of ADR-0006's grant-signing pre-commitment (the
C1 gate). Implements — does not supersede — ADR-0006; the universal companion-signer
scope and the pre-commitment are ADR-0006's, unchanged. This ADR records the concrete
mechanism RA7 chose (the atomic `signing_identity/1` callback) + the C1 tripwire now in
force.

## Context

ADR-0006 §"The grant-signing pre-commitment" named grant signing as a design-gated
future extension: issuer-role-only, with a tripwire that gates holder-key grant-signing
**red**. RA7 (ROADMAP row `b2-ra-grant-signing`) realizes it. The library already had
two instantiations of the universal companion-signer tail — proof signing (`sign_report/3`,
RA1) and boundary-anchor signing (`sign_anchor/3`, RA4) — both reusing the shared
`sign_and_assemble/3` primitive. Grant signing is the third.

The open design question ADR-0006 left to this slice was the **role mechanism**: how does
`sign_grant/3` know the key it is handed is an issuer key, not a holder key? The
key-handle contract (ADR-0006) carried no role notion — a handle is `{module(), term()}`
with `sign/2`, `public_key/1`, `thumbprint/1` required and `key_identity/1` optional.

## Decision

1. **`sign_grant/3` is the issuer-role instantiation.** It takes a grant's content + an
   issuer key-handle and returns `%{grant: grant_compact}`, reusing the shared
   `sign_and_assemble/3` tail unchanged. The grant's `key_id` (signed-header `kid`) and
   the `verify_signature` guard's `public_key` both come from the handle — never from
   caller input (ADR-0006 decision 3, same as `sign_anchor/3`). `holder_thumbprint` is
   caller-supplied (the grant's subject).

2. **The role mechanism is a new optional callback, `signing_identity/1`, returning
   `{:issuer | :holder, key_id, public_key}` as ONE atomic snapshot.** `sign_grant/3`
   resolves it in a single call and gates on `role == :issuer`. The role AND the key
   identity come from ONE observation, so a stateful handle cannot return `:issuer` then
   rotate to a holder key between role resolution and signing — the rotation-race
   defense ADR-0006 §Consequences established for `key_identity/1` → `sign/2` is extended
   here to cover `role`. The inherited `verify_signature` guard catches any
   `sign/2`-vs-snapshot `public_key` drift.

3. **The first draft's separate `role/1` + `key_identity/1` callbacks were rejected** by
   the RA7 design-adversarial pass (Challenge 1): two sequential callbacks opened a
   `role` → `key_identity` TOCTOU — a stateful handle returns `:issuer`, rotates, returns
   the holder key, signs with it; `verify_signature` passes (kid+pub consistent
   post-rotation) → a holder-key-signed grant as `{:ok, _}`. That is the same drift class
   `RacingKeyIdentityHandle` closes elsewhere, so the separate-callback design applied
   the "by construction, not by assumption" philosophy inconsistently. The atomic
   `signing_identity/1` closes it.

4. **`sign_anchor/3` keeps `key_identity/1`** — the combined callback is grant-only. The
   anchor path is role-agnostic (charter §5: "any holder of the right key"); retrofitting
   a richer return shape onto `key_identity/1` would churn the shipped, reviewed anchor
   surface for no gain. The contract gains two coexisting optional identity callbacks,
   each scoped to the operation that needs it.

5. **The C1 gate is a declaration-rejection property, not cryptographic key-role
   separation.** The `sign_grant/3` `@doc` states this precisely: a handle that declares
   `:holder` (or implements no `signing_identity/1`) cannot sign a grant through this
   API; but a handle that *consistently* mis-declares its role — whose `signing_identity/1`
   returns `{:issuer, holder_key_id, holder_public_key}` while `sign/2` holds the matching
   holder private key — signs successfully (every value is internally consistent). The
   adapter resolves only the handle's `public_key` and signs against it; it cannot prove
   key identity. Key-role separation (an issuer key and a holder key are cryptographically
   distinct custodied entities) is the key-custody boundary's job — the runtime / HSM /
   key server behind the handle (charter §4). The library's C1 obligation is narrower:
   the library's own API does not provide a path for a handle that declares the holder
   role to sign a grant. The strengthening path — a BA-signed role-attestation that closes
   this residual by binding the role to a BA authority key (not a handle self-declaration) —
   is evaluated in [ADR-0008](0008-role-attestation-direction.md); note that residual is
   defense-in-depth, not an open forge (BAP's verifier-side `TrustedIssuer` key check
   already rejects a holder-key-signed grant).

## Consequences

- The key-handle contract gains a second optional callback (`signing_identity/1`). A
  production issuer handle implements it, returning `:issuer` + its registry kid + public
  key from one consistent snapshot. A proof-only or anchor-only handle need not implement
  it (and is then rejected by `sign_grant/3` as `:invalid_key_handle`). The test-only
  reference handle (`Keys.RawKey`) declares `:holder` — it signs proofs + anchors, not
  grants.
- The C1 tripwire is in force: `sign_grant` on a `:holder`-declaring handle returns
  `{:error, :invalid_key_handle}` and `sign_call_count == 0` (the `GrantHolderCountingHandle`
  tripwire, the mirror of `sign_report`'s `sign_call_count == 1` pointed the other way);
  a roleless handle is rejected likewise; a post-snapshot `sign/2` key swap is caught by
  `verify_signature` (`GrantRacingIdentityHandle`). The tripwires are mutation-proven
  (removing the role guard / disabling `verify_signature` drives them red).
- The universal companion-signer pattern is now three-for-three: proof (RA1), anchor
  (RA4), grant (RA7), all through the shared tail. The one remaining named extension is
  key-transition signing (RA8) — the fourth instantiation, design-gated on its own
  BAP-contract read (`key_transition_signing_input`).
