# Charter — Bounded Authority Report Adapter

**Status:** Governing · **Authority:** the public
`bounded_authority_protocol` API, protocol corpus, and verifier contract.

## 1. The problem

An untrusted caller presents a request to a verifier. The verifier must answer two
distinct questions:

1. **Is the caller who the transport says it is?** Transport authentication answers this.
2. **Is that caller authorized for these exact request bytes?** A capability grant,
   bound to the request by a holder proof, answers this.

The request carries a **grant + proof envelope** proving that the caller holds a
capability the authority issued, bound to the specific request bytes. A captured
transport credential alone cannot forge authority or re-purpose a proof.

## 2. What this adapter does

This library is BAP's universal companion signer (ADR-0006): it signs BAP
protocol objects via a local key-handle: proof signing (`sign_report/3`, this
section), boundary-anchor signing (`sign_anchor/3`, §5), grant signing
(`sign_grant/3`, the issuer-role instantiation, ADR-0007), key-transition signing
(`sign_key_transition/3`, ADR-0009), local-loopback proof signing
(`sign_local_loopback_report/3`, the byte-distinct development-listener profile,
ADR-0018) and content-assertion signing (below). `BoundedAuthorityReportAdapter.V3`
signs the four standard objects under ES256 (ADR-0021). This section describes the
proof/envelope flow; each extension carries its own ADR.

The content-assertion extension (`sign_content_assertion/3`, ADR-0022, since 0.9.0)
adds a role-agnostic, digest-bound assertion through the same signing tail. It
uses BAP's explicit standalone profile and atomic key identity; it does not add
content interpretation, schema validation, trust resolution, or authorization.

**In the envelope, the adapter signs the holder proof — and only the holder
proof.** Concretely, a holder calls this adapter with an issuer-signed grant and
an application request, and the adapter returns the grant + proof envelope:

1. Receive the issuer-signed `grant_compact` as an INPUT. The grant was signed
   out of band by the authority runtime (the issuer) — in THIS flow
   the adapter never signs the grant (grant signing is the separate
   issuer-role instantiation `sign_grant/3`, gated on the handle's
   `signing_identity/1` resolving `:issuer` — ADR-0007).
2. Build the holder proof struct binding that grant to the report's request
   fields (`method`, `target_uri`, `invocation_id`, `operation`,
   `cast_arguments`).
3. Produce the deterministic proof signing input via
   `BoundedAuthorityProtocol.V1.proof_signing_input/2`.
4. Sign the input's message with the holder's private key — Ed25519 on the major-1
   surface, EC P-256 (`ES256`) on the `V3` surface (held locally
   on the edge — never in the verifier; the adapter holds a
   `{module(), term()}` key-handle callback, never the key bytes).
5. Assemble the compact proof via
   `BoundedAuthorityProtocol.V1.assemble_compact/3`, using the same caller bounds
   as the signing-input producer.
6. Return `{grant: grant_compact, proof: proof_compact}` — the grant passes
   through untouched.

The verifier then verifies the envelope with
`BoundedAuthorityProtocol.V1.check_envelope/2`, which checks the grant signature
against the issuer's public key and the proof signature against the holder's
public key. The adapter produces what the verifier checks.

Signing the grant with the holder key would produce an envelope no
correctly-configured verifier accepts — `sign_report/3`'s one signing artifact
is the proof, which is why grant signing lives in its own issuer-role-gated
instantiation (see §4 for the three-role split).

## 3. What this adapter does NOT do

These negatives are load-bearing — each maps to a different repo's job:

- **It does not verify (content).** Verification is embedded in every party via the
  protocol package. The verifier verifies; this adapter signs. Conflating
  the two puts the signer in the verifier's trust boundary. *(Nuance — the
  adapter DOES run sign-time gating verifies: the wrong-key guard on every sign
  path, and the optional role-attestation gate on grants (ADR-0008); those gate
  the SIGNING so a mis-signed artifact fails loudly at the signing boundary;
  they never verify the artifact's content, which stays the verifier's job via
  BAP.)*
- **It is not the runtime.** Grant *issuance*, key custody/rotation, and live
  revocation are the authority runtime's job (ADR 0001). This
  adapter uses a caller-owned holder key and signs on invocation; it does not
  mint capabilities.
- **It is not a transport.** Transport remains outside the library. This adapter
  envelopes a request before it is sent; how the envelope crosses a process or
  network boundary is the caller's concern.
- **Publication does not widen its role.** The package is public on Hex,
  and its source is public. It is still only a signer and gains no verifier,
  runtime, transport, persistence, or custody authority from publication.

## 4. The authority model

| Role | Repo | Keys it holds | Signs? | Verifies? |
|---|---|---|---|---|
| **Authority / issuer** | the authority runtime (a separate service) | issuer key | grants at issuance | revocation-sensitive decisions |
| **Holder / prover** (the edge agent) | **this adapter** | holder (private key: Ed25519 major-1, P-256 `ES256` via `.V3`) | every BAP object kind — proofs (holder role, plus the local-loopback profile sibling), anchors + key transitions (role-agnostic), grants (issuer-role instantiation, gated per ADR-0007), content assertions | — |
| **Verifier** (the verifier + any third party) | `bounded_authority_protocol` (public package) | none (verifies against published keys) | — | grants, proofs, envelopes, boundary anchors, key transitions |

This is the DPoP-shaped split (RFC 9449): the holder proves possession of a key
bound to the request, without exposing the key. The adapter is the holder-side
glue — and, for issuer-side callers, the grant-signing SDK (ADR-0007); the
protocol package is the shared verifier; the runtime is the issuer.

## 5. Boundary anchors (`sign_anchor/3`)

A durable confirmation MAY be a signed **boundary anchor**
(`BoundedAuthorityProtocol.V1.BoundaryAnchor`) that a holder verifies before
advancing local state. The library provides `sign_anchor/3`; the protocol package
provides `boundary_anchor_signing_input` and `verify_historical_anchor`. Whether a
deployment uses anchors is a consumer decision, not this library's scope.

## 6. Invariants this adapter must preserve

- **The holder key never leaves the edge.** The verifier, the transport,
  and the protocol package never see the private key. The adapter signs locally;
  only the public key + the signatures cross the boundary.
- **The envelope is byte-compatible with the protocol package's verifiers +
  conformance vectors.** The adapter does not invent envelope shapes; it calls
  BAP's signing-input producers and assembles with BAP's `assemble_compact`.
  Round-trip against the published vectors is the acceptance bar.
- **The adapter depends only on the public protocol package.** No runtime-service
  dependency (the dependency-direction wall). A test proves this.
- **Transports stay protocol-free.** This adapter is called BY the edge agent; it
  is not embedded in the transport libraries.
