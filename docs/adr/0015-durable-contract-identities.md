# ADR 0015: Durable contract identities

Status: accepted 2026-08-24.

## Context

This adapter must name the public Bounded Authority Protocol major that it
consumes and the immutable package tag that its documentation links to. A broad
ban on every version token made those required contract identities fail the
same scanner as lifecycle-derived implementation names.

## Decision

Project versioning is enabled at the kimosabe policy boundary, then narrowed by
the tracked architecture gate to three enumerated identities:

- `source_ref: "v#{@version}"` at the `mix.exs` package metadata boundary;
- the externally owned `BoundedAuthorityProtocol.V1` wire namespace used by the
  adapter; and
- `ba_protocol_v1`, the documented persisted scheme label for that wire major.
- *(Amended 2026-09-22, ADR-0021:)* `lib/bounded_authority_report_adapter/v3.ex` —
  the adapter-owned `BoundedAuthorityReportAdapter.V3` signing surface (path and
  module), mirroring the externally owned wire major it serves; and the v3 suite's
  exact test paths (`v3_sign_test.exs`, `v3_test_handles.exs`, module
  `BoundedAuthorityReportAdapter.V3SignTest` / `.V3TestHandles`).
- *(Amended 2026-09-22, ADR-0021:)* `BoundedAuthorityProtocol.V3` joins
  `BoundedAuthorityProtocol.V1` as an enumerated external wire namespace, accepted
  only at the exact adapter and test-support paths that consume it
  (`v3.ex`, `test_keys.ex`, `v3_sign_test.exs`); `BoundedAuthorityProtocol.V2`
  is enumerated likewise (its single consuming path: the v3 suite's
  payload-major discriminator leg); the V1 namespace's accepted path
  set gains the three files that now reference the shared producer structs
  (`v3.ex`, `standard_byte_identity_test.exs`, `v3_sign_test.exs`); the doctor
  task (`lib/mix/tasks/...doctor.ex`) joins both sets — it derives both suites'
  expected thumbprints.

Path, identifier kind, and spelling are part of every allowlist key. The
externally owned namespace is accepted only at the exact enumerated adapter,
test-support, and runnable-example paths that consume it, and only at its exact
current-major spelling. A lookalike namespace or any contract token at another
path is rejected.
Release-, task-, or implementation-derived names
remain forbidden for adapter modules, functions, paths, configuration, queues,
events, or storage objects.

## Decision protocol

Initial recommendation: enable project versioning and rely on the universal
lifecycle-name scanner. The strongest counterargument was that this would also
admit internal names such as `SignerV2` and `sign_report_v2`. The initial choice
was revised: enable the binary project policy only to remove its false-positive
version sweep, while a repository-owned exact allowlist retains the narrower
rule and proves both allowed and rejected fixtures.

## Consequences

The canonical kimosabe tree sweep continues to reject phase, task, slice,
sprint, step, and work-order identifiers. The adapter test suite separately
rejects project-owned version genealogy and fails if the owned library tree
acquires one.
