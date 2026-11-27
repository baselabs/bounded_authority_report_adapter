# Security model

This library signs. It produces holder proofs, local-loopback proofs, grants, boundary
anchors, key transitions and content assertions over the protocol package's deterministic
signing inputs. It self-verifies signatures and can verify an optional Ed25519 role
attestation; it is not a general credential verifier. It does not transport or persist
objects or manage private keys. What it guarantees follows from that narrow job.

## Trust boundaries

- **Private-key custody belongs to the caller.** Keep private bytes behind the
  `{module, term}` callbacks, never in the opaque handle term. The adapter does not
  inspect or sanitize that term: the repository's test-only reference handles can
  therefore pass private bytes through it, which is unsuitable for production.
  Callback results must expose only signatures, public keys and identity metadata.
  Production handles call an HSM, a KMS or a key server; the provider and host enforce
  any non-exportability or isolation requirement.
- **Key identity comes from the handle.** The key id and public key of anchors, key
  transitions and content assertions come from one `key_identity/1` call, and those of
  grants from one `signing_identity/1` call. Key ids in the input are ignored, so a
  caller cannot make a signed object name a key it was not signed with.
- **Wrong-key rejection.** Every signature is verified against the handle's public key
  before it is returned. A handle that signs with a different key than it reports gets
  `:signing_failed`, never a bad signature.
- **Closed errors and value-free telemetry.** Signing errors use closed atoms or the
  fixed tuple `{:producer_error, :invalid}`; telemetry metadata uses closed atoms. Neither
  carries key material, message bytes or report content. See
  [telemetry.md](telemetry.md) for the handler side.
- **Callbacks run in your process, without a timeout.** The adapter calls the handle's
  callbacks in the process that called the entry point, one after another, and sets no
  timeout of its own. A custodian that never answers blocks that call for as long as
  your client waits: bound every remote call inside the handle. A callback that raises,
  throws or exits (a `GenServer.call/3` timeout is an exit) is contained and returns a
  closed error.
- **Verification is never authorization.** Pure verification returns facts about
  signatures and request binding against caller-supplied trust and expected context.
  Execution depends on the verifying service's authorization policy, including trusted
  keys, identity binding, replay reservation and live revocation; see [framework-integration.md](framework-integration.md) §8 and §9.

## Named misuses

**Misuse: signing with a caller-supplied key id.** The key id is signed into the object's
header. A caller-chosen key id over a signature by a different key is the forgery that
shape enables: a verifier's historical-key check would vouch for the wrong key. The
adapter ignores caller key ids for this reason; do not fork the handle contract to
accept them.

**Misuse: skipping identity binding at the verifier.** An envelope that verifies was
validly signed by someone; it does not prove who is presenting it. Without the binding, a
captured envelope replays under a different authenticated identity until it expires
(framework-integration.md §8). The verifier must bind the verified holder to the
authenticated identity; the adapter cannot do it.

**Misuse: accepting requests without reserving replay identities.** The same valid envelope
can verify again during its acceptance window. Reserve the nonce through that window plus
clock skew and the invocation identity through grant expiry plus skew. See
[replay reservation](framework-integration.md#9-reserve-replay-identities).

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

**Misuse: treating a telemetry event as evidence.** The events are an operational signal.
Any code in the VM can call `:telemetry.execute/3` with the adapter's event names, so an
event proves neither that a signing call happened nor which code emitted it. Audit what
was signed from the signed objects themselves.

**Misuse: shipping a test-support reference handle.** The handles in the source
repository's `test/support/` keep a private key in process memory as a plain binary. In
production that reduces key custody to reading the heap, the failure the separate handle
contract exists to prevent. They are excluded from the package.

## Replay and first arrival

A single-use challenge permits at most one consumption. It cannot authenticate the first
arrival: an interceptor may submit a captured valid request first and deny its sender.
The host must use authenticated confidential transport where interception matters, bind
the authenticated identity, apply policy and live revocation, and reserve both challenge
and invocation identities in durable shared storage. Retain invocation claims through
grant expiry plus maximum skew or in a longer-lived execution record. Refuse uncertain
admission outcomes. Rotation, proof freshness and nonce equality do not replace this store.
