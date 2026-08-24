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
