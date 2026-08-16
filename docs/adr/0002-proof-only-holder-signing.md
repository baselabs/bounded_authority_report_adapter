# 2. Proof-only holder signing (the authority-model inversion correction)

Date: 2026-08-10

## Status

Accepted. Records the RA1 design-adversarial correction (C1 finding); in force
since `sign_report/3` shipped (2026-08-09). Authored retroactively when the ADR
gap was flagged by the 2026-08-10 alignment audit.

**Scope sharpened 2026-08-10 (ADR-0006):** "proof-only" is an *envelope-flow*
property — in the grant+proof envelope, the holder signs the proof, not the grant.
It is NOT a library-wide prohibition: the library also signs boundary anchors
(`sign_anchor/3`, RA4). The C1 correction below is unchanged; it governs the
envelope flow specifically.

## Context

A naive "signing adapter" might sign both the grant and the proof. But the
authority model assigns grant-signing to the **issuer** (the runtime) — the
grant is the authority's statement that a capability *exists* and was issued to
this holder. If the holder signs the grant, the envelope asserts "the holder
issued this capability to themselves," which **inverts the authority model**: the
party proving possession becomes the party granting it.

This is not a theoretical concern. `BoundedAuthorityProtocol.V1.check_envelope/2`
checks the grant signature against the issuer's public key
(`trusted_issuer.public_key`) and the proof signature against the holder's public
key (embedded in the proof header). A holder-signed grant therefore fails
verification at *every* correctly-configured verifier — the adapter would produce
envelopes nothing accepts.

The original scaffold draft of `docs/charter.md` §2 described a flow that built
the grant's signing input via `grant_signing_input/2` and "signed each" (grant +
proof). The RA1 design-adversarial review caught this as the C1 authority-model
inversion; the code never implemented it. (The 2026-08-10 audit found §2 still
carried the stale description; it was reconciled to the proof-only model the code
implements.)

## Decision

The adapter signs **only the holder proof**. Concretely, `sign_report/3`:

1. Receives the issuer-signed `grant_compact` as an **input**.
2. Builds the holder proof struct binding the grant to the report's request
   fields.
3. Produces the proof signing input via `BoundedAuthorityProtocol.V1.proof_signing_input/2`.
4. Signs the input's `message` with the holder key (via the `{module(), term()}`
   key-handle callback — never the key bytes in-process).
5. Verifies the signature against the resolved holder public key (wrong-key
   guard).
6. Assembles the compact proof via `assemble_compact/2`.
7. Returns `{grant: grant_compact, proof: proof_compact}` — the grant untouched.

The adapter **never** calls `grant_signing_input` in the envelope flow. *(Amended
2026-08-15: since RA7 the issuer-role instantiation `sign_grant/3` calls it —
`produce_grant_signing_input/2`, lib — with the C1 gate (`signing_identity/1`
resolving `:issuer`, ADR-0007) holding the holder key out of that path. The
envelope-flow prohibition this ADR governs is unchanged.)* `lib/` contains no
`:crypto.sign` call (the only `:crypto` calls are `:crypto.verify` for the
wrong-key guard and `:crypto.strong_rand_bytes` for the proof's `jti`).

## Consequences

- Grant integrity is the issuer's responsibility (signed out of band); proof
  integrity is the holder's. The two signatures are checked against different
  keys by the verifier.
- The correction is enforced **structurally** (no grant-signing code path
  exists) and by tripwire tests (`sign_report_test.exs`: grant pass-through,
  wrong-key verify, exit/throw containment).
- The holder key never enters the adapter (ADR 0001's edge-custody invariant);
  the key-handle callback is the only signing surface.
