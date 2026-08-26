# Security model

This library is a holder-side signer. It produces proofs, grants, boundary anchors, and
key transitions over the protocol's deterministic signing inputs; it never verifies,
never transports, never persists, and never holds a private key. Everything it guarantees
flows from that narrowness.

## Trust boundaries

- **The library never solicits, processes, or retains private key material.** All
  custody lives behind the `{module, term}` key-handle behaviour; the adapter sees
  messages, signatures, and public material only. The guarantee is the CONTRACT — the
  callbacks are its only channel to key operations — not an inspection of your handle
  term (a handle that embeds key bytes in its term, like the repo's test-only reference,
  has chosen that posture itself; production handles front an HSM/KMS/key server).
- **Handle-sourced identity.** `key_id` and `public_key` on anchors and transitions come
  from ONE atomic `key_identity/1` (or `signing_identity/1`) snapshot — caller-supplied
  key ids are ignored. A caller cannot make an anchor assert a kid it was not signed
  under.
- **Wrong-key rejection.** Every signature is verified against the handle-resolved
  public key before success. A handle that signs with a different key than it reports is
  `:signing_failed`, never a false success.
- **Closed-atom errors; value-free telemetry.** Errors are atoms; telemetry metadata is
  two closed atoms. Neither channel can carry key material, message bytes, or report
  content — see [telemetry.md](telemetry.md) for the handler-side posture.
- **Verification is the consumer's authority decision.** A signed envelope proves
  possession and binding; authorization (identity binding, replay, revocation) happens
  in the consuming runtime — [consumer-integration.md](consumer-integration.md) §8/§9.

## Named misuses

**Misuse: signing with a caller-supplied key id.** The kid is signed into the anchor and
transition headers; a caller-chosen kid over a differently-signed key is the forgery that
shape enables. Consequence if forced: a verifier's historical-key binding vouches for the
wrong key. The adapter ignores caller key ids for exactly this reason — do not fork the
handle contract to accept them.

**Misuse: skipping consumer identity binding.** An envelope that verifies is an envelope
SOMEONE validly signed — not proof of who is presenting it. Consequence: a captured
envelope replays under a different reporter identity until expiry
(consumer-integration.md §8). Bind the verified holder to the authenticated reporter at
the consumer; the adapter cannot do it for you.

**Misuse: running without a nonce ledger.** Within the proof's freshness window, the same
valid envelope verifies repeatedly. Consequence: a same-identity replay window as wide as
`proof_max_age` (§9). The nonce the proof carries exists precisely so the consumer can
close it; not spending it is choosing the window.

**Misuse: trusting `signing_identity/1`'s declaration as role separation.** The C1 gate
on `sign_grant/3` rejects handles that do not DECLARE `:issuer` — it cannot verify which
key the holder actually holds. Consequence if you rely on it for separation: a handle
that mis-declares (or a holder key labelled issuer) signs grants the gate happily passes;
the verifier's `TrustedIssuer` key check is the real boundary. Custody must keep issuer
keys in issuer custody — the gate is declaration-rejection, not cryptography.

**Misuse: extending telemetry metadata with values.** A key id in an event label is key
material in every sink downstream (logs, metric labels, dashboards). Consequence: the
value-free invariant — the property that makes the event stream safe to ship anywhere —
is broken for every consumer at once. The emitters are shape-validated precisely so this
"extension" is not expressible; treat the refusal as the feature it is.

**Misuse: shipping the test-support reference handle.** The `{pub, priv}` tuple handle in
the source repo's `test/support/` puts a private key in process memory as a recoverable
binary. Consequence if it reaches production: key custody reduced to heap scraping — the
exact failure mode the separate-handle contract exists to prevent (design C5, ADR-0014).
It is deliberately excluded from the package.
