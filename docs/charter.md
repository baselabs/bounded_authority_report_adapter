# Charter — Bounded Authority Report Adapter

**Status:** Governing — reconciled 2026-08-15 to the shipped four-instantiation
API (RA1–RA9; original 2026-08-09 scaffold) · **Roadmap row:** verifier application ROADMAP B2
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
protocol objects via a local key-handle. Four instantiations have landed —
proof signing (`sign_report/3`, RA1, this section), boundary-anchor signing
(`sign_anchor/3`, RA4, §5), grant signing (`sign_grant/3`, RA7 — the
issuer-role instantiation, ADR-0007), and key-transition signing
(`sign_key_transition/3`, RA8 — ADR-0009). This section describes the
proof/envelope flow; each extension carries its own ADR.

**In the envelope, the adapter signs the holder proof — and only the holder
proof.** Concretely, the edge agent calls this adapter with an issuer-signed
grant + a application report, and the adapter returns the grant + proof envelope:

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
public key (verifier application already calls it at `deny_stack.ex:178` for the layer-1
verify). The adapter produces what the verifier checks.

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
  adapter holds a holder key it was issued and signs on invocation; it does not
  mint capabilities.
- **It is not a transport.** The application transport libraries (`replicant`,
  `capstan`) stay protocol-free (the dependency-direction invariant). This
  adapter is a composable lib the edge agent calls *to envelope a report before
  sending it*; how the envelope crosses the wire is a transport concern.
- **Publication does not widen its role.** The package is public on Hex at 0.2.1,
  while its source repository remains private pending explicit source/registry
  alignment. It is still only a signer and gains no verifier, runtime, transport,
  persistence, or custody authority from publication (see `docs/strategy.md`).

## 4. The authority model (three roles, three repos)

| Role | Repo | Keys it holds | Signs? | Verifies? |
|---|---|---|---|---|
| **Authority / issuer** | `bounded_authority` (runtime service) | issuer key | grants at issuance | revocation-sensitive decisions |
| **Holder / prover** (the edge agent) | **this adapter** | holder (private Ed25519) | all four BAP object kinds — proofs (holder role), anchors + key transitions (role-agnostic), grants (issuer-role instantiation, C1-gated per ADR-0007) | — |
| **Verifier** (the verifier + any third party) | `bounded_authority_protocol` (public package) | none (verifies against published keys) | — | grants, proofs, envelopes, boundary anchors, key transitions |

This is the DPoP-shaped split (RFC 9449): the holder proves possession of a key
bound to the request, without exposing the key. The adapter is the holder-side
glue — and, for issuer-side callers, the grant-signing SDK (ADR-0007); the
protocol package is the shared verifier; the runtime is the issuer.

## 5. The checkpoint-ack boundary anchor (`sign_anchor/3` shipped at RA4; the consumer use case is exploratory)

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
