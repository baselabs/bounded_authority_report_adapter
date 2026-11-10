# ROADMAP — Bounded Authority Report Adapter

The build arc, by capability. Each row is an authored definition: what the capability is,
how it was accepted, what it built on, and the governing document. Rows carry no live
state; the CHANGELOG records what each release shipped, and the test suite is the evidence.
The row id (`RA1` … `RA15`) is a stable name for the capability.

## Shipped

| ID | What | Acceptance | Depends | Why |
|---|---|---|---|---|
| RA1 | **Envelope signing** — `sign_report/3`: a report and a holder key handle in, a grant + proof envelope out, through the protocol's signing-input producer and `assemble_compact`. | The envelope verifies with `BoundedAuthorityProtocol.V1.check_envelope/2` and round-trips byte-compatibly with the protocol's grant-holder-proof conformance vector. | — | [charter §2](charter.md) · [strategy §5](strategy.md) |
| RA2 | **Conformance round-trip** — the protocol's published vectors and certified corpora as the oracle. | Every published envelope case verifies through `check_envelope/2` and every grant-time case through `verify_grant/3`; the certified corpora for contract-majors 1, 2 and 3 agree through the protocol's verifier CLI. | RA1 | [charter §6](charter.md) · [strategy §7](strategy.md) |
| RA3 | **Dependency-direction wall** — the library depends only on the public protocol package (plus `:telemetry`). | A test reads `mix.exs` and `mix.lock` and fails on the private runtime, a transport library, or a range outside the declared floor and ceiling; planted forbidden dependencies fail it. | — | [charter §6](charter.md) · [strategy §3](strategy.md) |
| RA4 | **Boundary-anchor signing** — `sign_anchor/3`, through the shared signing tail. | Both key identifiers come from the handle's `key_identity/1`; wrong-key, exit/throw and defect-injection tests pass; the anchor verifies with `verify_historical_anchor/3`. | RA1 | [charter §2](charter.md) |
| RA5 | **Consumer contract guide** — how any verifier receives an envelope, binds it to the authenticated identity and the exact request bytes, and rejects replay. | The guide is implementation-neutral; its verifier examples call the protocol package directly and run in the test suite. | RA1, RA2 | [consumer integration](consumer-integration.md) |
| RA6 | **Closeout of the first arc** — topology, signing, dependency wall and publication records agree. | RA1–RA5 shipped; the full suite and the conformance round-trip are green. | RA1–RA5 | [charter](charter.md) · [strategy](strategy.md) |
| RA7 | **Grant signing** — `sign_grant/3`, the issuer-side instantiation. | Signs only for a handle whose `signing_identity/1` declares `:issuer`; a holder handle is refused before `sign/2`; the grant verifies with `verify_grant/3`. | RA1 | [charter §2](charter.md) |
| RA8 | **Key-transition signing** — `sign_key_transition/3`, role-agnostic like anchors. | The transition verifies with `verify_key_transition/4`; wrong-key and defect-injection tests pass. | RA1 | [charter §2](charter.md) |
| RA9 | **Edge-agent example** — `examples/edge_agent/`, a runnable app: the agent signs and POSTs over HTTP, the receiver verifies with the protocol package only. | The round trip returns `200 accepted`; a tampered proof, a stranger's proof, a wrong identity and a replayed nonce each return `401`; the README's two-terminal commands run. | RA1, RA2 | [consumer integration](consumer-integration.md) |
| RA10 | **Second-language verifier** — not this library's deliverable. Cross-language verifiers belong to the protocol, which publishes them. | — | RA2 | [strategy §7](strategy.md) |
| RA11 | **Role-attestation gate** — `sign_grant/3`'s optional `:role_attestation`: the issuer role must be attested, for the handle's own key, by an attestor the caller trusts. | A holder-role, foreign-subject, wrong-attestor, expired or tampered attestation never signs (no `sign/2` call); the protocol's role-attestation corpus agrees. | RA7 | [charter §4](charter.md) · [security model](security.md) |
| RA12 | **Local-loopback proof signing** — `sign_local_loopback_report/3` for the protocol's development-listener profile. | Literal-loopback targets sign and verify; `localhost` and other spellings fail closed; the profile corpus agrees; the example app runs it over real IPv4 and IPv6 listeners. | RA1 | [recipes](recipes.md#recipe-the-local-loopback-development-listener) |
| RA13 | **ES256 surface** — `BoundedAuthorityReportAdapter.V3`: the four standard objects under contract-major 3 with P-256 keys. | Key-type discrimination, point validation, low-S normalization, DER refusal, wrong-key and mixed-major refusals all fail closed; the v3 corpus agrees. | RA1, RA4, RA7, RA8 | [charter §2](charter.md) |
| RA14 | **Content-assertion signing** — `sign_content_assertion/3` for the protocol's content-assertion profile. | The handle's `key_identity/1` names the key; the protocol's producer and assembler build the bytes; an independent verifier agrees on the content digest. | RA1, RA8 | [charter §2](charter.md) |

## 1.0

| ID | What | Acceptance | Depends | Why |
|---|---|---|---|---|
| RA15 | **The 1.0 release** — the [stability contract](upgrading.md#stability-contract) becomes the public surface, on the protocol's 1.0 line. | The shipped surface equals the contract; the package requires the protocol at `~> 1.0` from Hex; every gate in the [release runbook](release.md) passes, including the registry read-back. | RA1–RA14 | [strategy §6](strategy.md) |
