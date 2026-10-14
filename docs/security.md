# Security model

This library signs. It produces holder proofs, local-loopback proofs, grants, boundary
anchors, key transitions and content assertions over the protocol package's deterministic
signing inputs. It does not verify credentials, transport or persist anything, or hold a
private key. What it guarantees follows from that narrow job.

## Trust boundaries

- **The library never asks for, processes or keeps private key material.** Custody lives
  behind the `{module, term}` key-handle behavior; the adapter sees messages, signatures
  and public keys only. The guarantee is the contract (the callbacks are its only way to
  reach a key), not an inspection of your handle term: a handle that puts key bytes in
  its term, like the repository's test-only reference handles, has chosen that itself.
  Production handles call an HSM, a KMS or a key server.
- **Key identity comes from the handle.** The key id and public key of anchors, key
  transitions and content assertions come from one `key_identity/1` call, and those of
  grants from one `signing_identity/1` call. Key ids in the input are ignored, so a
  caller cannot make a signed object name a key it was not signed with.
- **Wrong-key rejection.** Every signature is verified against the handle's public key
  before it is returned. A handle that signs with a different key than it reports gets
  `:signing_failed`, never a bad signature.
- **Closed errors and value-free telemetry.** Errors are atoms; telemetry metadata is two
  closed atoms. Neither can carry key material, message bytes or report content. See
  [telemetry.md](telemetry.md) for the handler side.
- **Authorization is the verifier's decision.** A signed envelope proves possession and
  binding. Identity binding, replay protection and revocation happen in the verifying
  service; see [consumer-integration.md](consumer-integration.md) §8 and §9.

## Named misuses

**Misuse: signing with a caller-supplied key id.** The key id is signed into the object's
header. A caller-chosen key id over a signature by a different key is the forgery that
shape enables: a verifier's historical-key check would vouch for the wrong key. The
adapter ignores caller key ids for this reason; do not fork the handle contract to
accept them.

**Misuse: skipping identity binding at the verifier.** An envelope that verifies was
validly signed by someone; it does not prove who is presenting it. Without the binding, a
captured envelope replays under a different authenticated identity until it expires
(consumer-integration.md §8). The verifier must bind the verified holder to the
authenticated identity; the adapter cannot do it.

**Misuse: running without a nonce ledger.** Within the proof's freshness window the same
valid envelope verifies again. Without a ledger, a same-identity replay window is as wide
as `proof_max_age` (§9). The proof carries a nonce so the verifier can close that window.

**Misuse: treating the declared role as role separation.** `sign_grant/3` refuses a handle
that does not declare `:issuer`, but it cannot check which key the handle actually holds.
A handle that declares `:issuer` for a holder's key signs grants. The verifier's trusted
issuer key is the real boundary, and custody must keep issuer keys with the issuer. The
optional `:role_attestation` input adds a cryptographic check: the issuer role must be
attested, for the handle's own key, by an attestor the caller trusts.

**Misuse: putting values in telemetry metadata.** A key id in an event label is key
material in every downstream sink (logs, metric labels, dashboards), and the stream is no
longer safe to ship anywhere. The emitters validate their shape so this cannot be
expressed; treat the refusal as the feature.

**Misuse: shipping a test-support reference handle.** The handles in the source
repository's `test/support/` keep a private key in process memory as a plain binary. In
production that reduces key custody to reading the heap, the failure the separate handle
contract exists to prevent. They are excluded from the package.
