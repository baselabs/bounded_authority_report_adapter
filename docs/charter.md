# Charter — Bounded Authority Report Adapter

**Status:** Governing — reconciled 2026-08-24 to the shipped four-instantiation
API and public-source boundary · **Authority:** the public
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
protocol objects via a local key-handle. Four instantiations have landed —
proof signing (`sign_report/3`, RA1, this section), boundary-anchor signing
(`sign_anchor/3`, RA4, §5), grant signing (`sign_grant/3`, RA7 — the
issuer-role instantiation, ADR-0007), and key-transition signing
(`sign_key_transition/3`, RA8 — ADR-0009). This section describes the
proof/envelope flow; each extension carries its own ADR.

**In the envelope, the adapter signs the holder proof — and only the holder
proof.** Concretely, a holder calls this adapter with an issuer-signed grant and
an application request, and the adapter returns the grant + proof envelope:

1. Receive the issuer-signed `grant_compact` as an INPUT. The grant was signed
   out of band by the `bounded_authority` runtime (the issuer) — in THIS flow
   the adapter never signs the grant (grant signing is the separate
   issuer-role instantiation `sign_grant/3`, gated on the handle's
   `signing_identity/1` resolving `:issuer` — RA7/ADR-0007).
2. Build the holder proof struct binding that grant to the report's request
   fields (`method`, `target_uri`, `invocation_id`, `operation`,
   `cast_arguments`).
3. Produce the deterministic proof signing input via
   `BoundedAuthorityProtocol.V1.proof_signing_input/2`.
4. Sign the input's message with the holder's private Ed25519 key (held locally
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
is the proof, which is why grant signing lives in its own issuer-role,
C1-gated instantiation (see §4 for the three-role split).

## 3. What this adapter does NOT do

These negatives are load-bearing — each maps to a different repo's job:

- **It does not verify (content).** Verification is embedded in every party via the
  protocol package. The verifier verifies; this adapter signs. Conflating
  the two puts the signer in the verifier's trust boundary. *(Nuance — the
  adapter DOES run sign-time gating verifies: the wrong-key guard on every sign
  path, and a role-attestation gate if RA11 lands — per ADR-0008, those gate
  the SIGNING so a mis-signed artifact fails loudly at the signing boundary;
  they never verify the artifact's content, which stays the verifier's job via
  BAP.)*
- **It is not the runtime.** Grant *issuance*, key custody/rotation, and live
  revocation are the `bounded_authority` runtime service's job (ADR 0001). This
  adapter uses a caller-owned holder key and signs on invocation; it does not
  mint capabilities.
- **It is not a transport.** Transport remains outside the library. This adapter
  envelopes a request before it is sent; how the envelope crosses a process or
  network boundary is the caller's concern.
- **Publication does not widen its role.** The package is public on Hex at 0.5.0,
  and its source is public. It is still only a signer and gains no verifier,
  runtime, transport, persistence, or custody authority from publication. The
  separate BA runtime remains a private commercial application and is not
  distributed from Hex because no paid private-package subscription exists. Any
  future private Hex release requires the subscription and fresh approval for that
  exact release and destination (see `docs/strategy.md`).

## 4. The authority model

| Role | Repo | Keys it holds | Signs? | Verifies? |
|---|---|---|---|---|
| **Authority / issuer** | `bounded_authority` (runtime service) | issuer key | grants at issuance | revocation-sensitive decisions |
| **Holder / prover** (the edge agent) | **this adapter** | holder (private Ed25519) | all four BAP object kinds — proofs (holder role), anchors + key transitions (role-agnostic), grants (issuer-role instantiation, C1-gated per ADR-0007) | — |
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
- **The adapter depends only on the public protocol package.** No private runtime
  dependency (the dependency-direction wall). A test proves this.
- **Transports stay protocol-free.** This adapter is called BY the edge agent; it
  is not embedded in the transport libraries.
