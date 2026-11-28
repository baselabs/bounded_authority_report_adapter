# Strategy: Bounded Authority Report Adapter

This guide explains the released package's stability, dependencies and signing boundary.
The [charter](charter.md) describes the authority model; the [capability map](ROADMAP.md)
and [CHANGELOG](../CHANGELOG.md) record the shipped surface.

## 1. Release posture

See the [package on Hex](https://hex.pm/packages/bounded_authority_report_adapter) for
released versions. The [stability contract](guides/upgrading.md#stability-contract) has
applied since 1.0.0.
Breaking changes to its public API require a major release. Additions and soundness
repairs follow the contract's documented minor-release rules.

The authority service is a separate application. The adapter has no dependency on it
and does not contact it at signing time.

## 2. Public API stability

Public distribution and API stability are separate properties; this package has both.
The stable surface includes the signing functions, the thumbprint helper, key-handle
callbacks, result and error shapes, telemetry contract and doctor preflight described
in the upgrading guide. Protocol wire compatibility follows the protocol package's
contract-major rules, independently of this adapter's package version.

## 3. Dependencies and direction

The direct dependency graph declared by `mix.exs` is:

```text
bounded_authority_report_adapter
  + bounded_authority_protocol ~> 1.5   required runtime dependency
  + telemetry ~> 1.3                    required runtime dependency
  + igniter ~> 0.8                      optional installer dependency
  + credo, dialyxir, ex_doc, mix_audit,
    sbom                               dev/test only; runtime: false
```

The protocol owns canonical bytes, producers, assembly and pure verification. Telemetry
provides value-free signing events. Igniter enables the install task when present; it
is optional and is not called by signing entry points. Its transitive dependencies
belong to that optional installer graph.

The dependency-direction test rejects authority-runtime dependencies, transport libraries
and HTTP clients or servers in the library. The separate example app declares its own
Req, Bandit and Plug dependencies. Those never enter the library's required runtime graph.

## 4. Why a separate signer

The pure protocol package accepts public keys and produces deterministic signing inputs;
it never holds private keys or signs. This adapter signs through caller-owned handles.
A verifying service can use the protocol package without installing a signer or gaining
access to holder keys. Issuers can use the same adapter through issuer-role handles.

Verification is never authorization. Operational decisions belong to the verifying
service's authorization policy, with its own trust configuration, identity binding,
replay reservation and revocation state.

## 5. Cryptographic posture

The root module signs contract-major 1 using Ed25519. `BoundedAuthorityReportAdapter.V3`
signs contract-major 3 using P-256 and ES256. Content assertions and action approvals
have explicit profiles for both suites. The local-loopback proof profile uses Ed25519.

For each object, the protocol package produces the exact signing input. The adapter
signs through the handle, checks the signature against the handle-resolved public key,
and calls the protocol assembler with the same bounds. It does not implement another
canonical serializer. Holder-proof signing passes the issuer-signed grant through
unchanged; grant signing is a separate issuer-side call.

Key custody belongs to the caller. Public keys and signatures cross the handle boundary;
private keys remain in the custodian.

## 6. Release compatibility

Version 1.0.0 established the current stability contract and the protocol `~> 1.0`
requirement. The [release runbook](release.md) describes compatibility, conformance,
provenance, archive reproducibility and registry read-back checks for subsequent releases.
Historical 0.x behavior is recorded under its own version in the upgrading guide.

## 7. Protocol conformance

The adapter qualifies its output against the protocol's published vectors and certified
corpora, including exact-byte comparisons where signatures are deterministic.
A successful self-round-trip alone is not independent interoperability evidence.
Each package runs its own release checks; a protocol release does not qualify an adapter
release automatically.

## 8. Following protocol releases

`mix.exs` declares the supported protocol range. The library and example app each lock
the same Hex release. Qualification checks the installed protocol version and archive
checksum in both projects. Moving the floor or crossing a compatibility
boundary also updates the range checks, both locks, examples and migration notes.
Consumers choose when to adopt compatible releases.
