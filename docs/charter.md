# Charter: Bounded Authority Report Adapter

The public `bounded_authority_protocol` API, specifications and conformance corpus define
the wire contract. This adapter supplies signing through caller-owned key handles.

## 1. The problem

A verifying service receives a grant and holder proof bound to a request. The pure
protocol verifier checks signatures, signed scope and exact request binding against
caller-supplied trusted keys and expected context. It returns facts, not permission.
Verification is never authorization.

The verifying service's authorization policy decides whether those facts permit execution.
That policy also requires authenticated identity binding, trusted-key selection, live
revocation checks and atomic replay reservation. Transport authentication identifies the
presenter; it does not supply those policy decisions.

A captured transport credential alone cannot create a valid holder signature or bind an
existing proof to different request bytes. A captured complete envelope still requires
the service's replay protection.

## 2. What this adapter does

The root module signs holder proofs, local-loopback proofs, grants, boundary anchors,
key transitions and content assertions with Ed25519 keys. `BoundedAuthorityReportAdapter.V3`
signs the four standard objects with P-256 keys and ES256. Each function documents its
fields, options, key-handle callbacks, result and closed errors.

For a request envelope, `sign_report/3`:

1. Receives an issuer-signed grant and request fields from the caller.
2. Builds the holder proof binding the grant, method, target URI, invocation id,
   operation, tagged arguments and nonce.
3. Calls the protocol's signing-input producer for the exact bytes to sign.
4. Signs through the holder's key handle, then checks the signature against that
   handle's public key.
5. Assembles the compact proof through the protocol package with the same bounds.
6. Returns the unchanged grant and the new proof.

Grant signing is a separate issuer-side operation, `sign_grant/3`, whose handle must
declare the `:issuer` role through `signing_identity/1`. It can additionally require an
Ed25519 role attestation. Content assertions bind content digests and context without
granting authority or interpreting the content.

## 3. Component boundaries

The adapter signs; the pure protocol package verifies. The adapter's signature self-check
and optional role-attestation gate protect signing output. They do not implement the
verifying service's authorization policy.

Grant issuance, trusted-key discovery, live revocation, replay reservation and execution
belong to stateful applications. Key custody and rotation belong to the caller's
custodian. The adapter does not contact an authority service, transport requests or
persist results.

## 4. The authority model

| Role | Component | Key access | Responsibility |
|---|---|---|---|
| Issuer | Authority service | Issuer custody | Issues and revokes grants; can call this adapter to sign them. |
| Holder | Calling agent and this signer | Holder custody through a key handle | Signs request proofs without exposing its private key. |
| Pure verifier | Public protocol package | Caller-supplied trusted public keys | Returns cryptographic and contextual facts about signed objects. |
| Verifying service | Consuming application | Trusted public keys and live policy state | Binds identity, reserves replay, checks revocation and applies authorization policy. |

The holder proof follows the proof-of-possession model of
[RFC 9449](https://www.rfc-editor.org/rfc/rfc9449). The protocol supplies canonical bytes
and verification; this adapter supplies signing; services supply operational authority.

## 5. Boundary anchors (`sign_anchor/3`)

A boundary anchor is a signed checkpoint naming a chain, sequence and hash. A holder
may verify it before advancing local state. The adapter signs it through `sign_anchor/3`;
the protocol provides the signing-input producer and `verify_historical_anchor/3`.
Choosing whether to use anchors and trusting a historical key are application decisions.

## 6. Invariants

- Private keys remain in caller custody. The adapter receives public keys and signatures
  through callbacks; production handle terms identify keys rather than containing them.
- Canonical bytes come from the protocol's producers and assembler. Independent
  conformance vectors, including exact-byte comparisons, qualify the output.
- Required runtime dependencies are the public protocol package and telemetry. Igniter
  is optional installer support. The dependency-direction test rejects authority-runtime
  and transport dependencies in the library.
- Transport remains a separate application concern. The edge-agent example has its own
  Mix project and transport dependencies.
- The [stability contract](guides/upgrading.md#stability-contract) has applied since 1.0.0.
