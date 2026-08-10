# Charter — Bounded Authority Report Adapter

**Status:** Draft (2026-08-09 scaffold) · **Roadmap row:** verifier application ROADMAP B2
(`b2-report-path-adapter`) · **Authority:** `bounded_authority_protocol`
`docs/design/consumer-seams-application-report-path.md` (first-hand, the application-report-path
seam note) + `bounded_authority_protocol`'s `docs/adr/0001` (the public-verifier / private-runtime topology) + verifier application
ADR 0002/0007.

## 1. The problem

An external data plane (the "edge agent") reports materializations into the
verifier application verifier. The verifier must answer two distinct questions
about each report:

1. **Is the reporter who they claim to be?** (transport identity — an api_key
   answers this; S1's `eddsa-boundary-s1` boundary signature answers it for the
   report body).
2. **Is the reporter *authorized* to perform this report?** (capability — a
   grant from the authority, bound to the report by a holder proof).

S1 closed question 1. B2 closes question 2: the report carries a **grant + proof
envelope** proving the reporter holds a capability the authority issued, bound to
the specific report bytes. A captured api_key alone cannot forge a report;
a captured transport cannot re-purpose one.

## 2. What this adapter does

This library is BAP's universal companion signer (ADR-0006): it signs BAP
protocol objects via a local key-handle. Two instantiations have landed — proof
signing (`sign_report/3`, this section) and boundary-anchor signing
(`sign_anchor/3`, RA4). This section describes the proof/envelope flow.

**In the envelope, the adapter signs the holder proof — and only the holder
proof.** Concretely, the edge agent calls this adapter with an issuer-signed
grant + a application report, and the adapter returns the grant + proof envelope:

1. Receive the issuer-signed `grant_compact` as an INPUT. The grant was signed
   out of band by the `bounded_authority` runtime (the issuer) — this adapter
   never signs the grant.
2. Build the holder proof struct binding that grant to the report's request
   fields (`method`, `target_uri`, `invocation_id`, `operation`,
   `cast_arguments`).
3. Produce the deterministic proof signing input via
   `BoundedAuthorityProtocol.V1.proof_signing_input/2`.
4. Sign the input's message with the holder's private Ed25519 key (held locally
   on the edge — never in the verifier; the adapter holds a
   `{module(), term()}` key-handle callback, never the key bytes).
5. Assemble the compact proof via
   `BoundedAuthorityProtocol.V1.assemble_compact/2`.
6. Return `{grant: grant_compact, proof: proof_compact}` — the grant passes
   through untouched.

The verifier then verifies the envelope with
`BoundedAuthorityProtocol.V1.check_envelope/2`, which checks the grant signature
against the issuer's public key and the proof signature against the holder's
public key (verifier application already calls it at `deny_stack.ex:178` for the layer-1
verify). The adapter produces what the verifier checks.

Signing the grant with the holder key would produce an envelope no
correctly-configured verifier accepts — the adapter's one signing artifact is
the proof (see §4 for the three-role split).

## 3. What this adapter does NOT do

These negatives are load-bearing — each maps to a different repo's job:

- **It does not verify.** Verification is embedded in every party via the
  protocol package. The verifier verifies; this adapter signs. Conflating
  the two puts the signer in the verifier's trust boundary.
- **It is not the runtime.** Grant *issuance*, key custody/rotation, and live
  revocation are the `bounded_authority` runtime service's job (ADR 0001). This
  adapter holds a holder key it was issued and signs on invocation; it does not
  mint capabilities.
- **It is not a transport.** The application transport libraries (`replicant`,
  `capstan`) stay protocol-free (the dependency-direction invariant). This
  adapter is a composable lib the edge agent calls *to envelope a report before
  sending it*; how the envelope crosses the wire is a transport concern.
- **It is not hex-published.** Private BaseLabs library until consumed + exercised
  + tuned across the projects that use it (see `docs/strategy.md`).

## 4. The authority model (three roles, three repos)

| Role | Repo | Keys it holds | Signs? | Verifies? |
|---|---|---|---|---|
| **Authority / issuer** | `bounded_authority` (runtime service) | issuer key | grants at issuance | revocation-sensitive decisions |
| **Holder / prover** (the edge agent) | **this adapter** | holder (private Ed25519) | holder proofs on reports | — |
| **Verifier** (the verifier + any third party) | `bounded_authority_protocol` (public package) | none (verifies against published keys) | — | grants, proofs, envelopes |

This is the DPoP-shaped split (RFC 9449): the holder proves possession of a key
bound to the request, without exposing the key. The adapter is the holder-side
glue; the protocol package is the shared verifier; the runtime is the issuer.

## 5. The checkpoint-ack boundary anchor (exploratory — ROADMAP B2 acceptance)

The verifier's durable-commit confirmation back to the edge (the
checkpoint-after-persist ack) MAY be a signed **boundary anchor**
(`BoundedAuthorityProtocol.V1.BoundaryAnchor`) the agent verifies before
advancing its transport checkpoint — authenticating the effect-once loop
end-to-end. The library provides the signing capability for this — `sign_anchor/3`
(RA4) signs a boundary anchor any holder of the right key can use, including a
platform-side ack producer. The protocol package already expresses the ack
(`boundary_anchor_signing_input` + `verify_historical_anchor`); no consumer-side
fork of protocol semantics is needed (per BAP's consumer-seam note). Whether a
given deployment produces checkpoint-ack anchors is a consumer decision, not this
library's scope.

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
