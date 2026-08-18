# 3. Edge-path dependency wall

Date: 2026-08-10

## Status

Accepted. Records charter §6 invariant 3; in force since RA3 shipped the
structural test (2026-08-10). Authored retroactively when the ADR gap was flagged
by the 2026-08-10 alignment audit.

## Context

verifier application's dependency-direction wall forbids the verifier from depending
on anything that signs — so a compromised app cannot forge authority by calling a
signing path it links against. This adapter **is** the thing that signs, so it
must live outside verifier application (ADR 0005). For the same invariant to hold on *this*
adapter's edge path, the adapter must depend only on the public protocol package:
not on the private runtime, not on transport libraries.

Two failure modes the wall prevents:

1. **A private runtime dependency** (`:bounded_authority`) would couple the edge
   signer to the issuer service — re-introducing a path the verifier wall
   was built to sever, and dragging the runtime's operational surface onto the
   edge.
2. **A runtime-internal namespace reference** (`BoundedAuthority.*` /
   `BoundedAuthorityWeb.*`) would bind the adapter to the runtime's private
   internals even without a declared dep — an `alias`/`import` is a compile-time
   coupling whether or not the referenced module has public defs.

## Decision

The adapter's only dependency is `bounded_authority_protocol` (private git dep,
pinned by ref in `mix.exs`). No `:bounded_authority` (runtime); no `:replicant` /
`:capstan` (transports). The adapter consumes **only** the public
`BoundedAuthorityProtocol.*` surface — never the `BoundedAuthority.*` /
`BoundedAuthorityWeb.*` runtime internals.

A two-clause structural test (`test/bounded_authority_report_adapter/dependency_direction_test.exs`)
proves this, scanning both compile-bearing source surfaces (`lib/` and
`test/support/`):

- **Positive clause** — the protocol dep is declared, pinned, and locked.
- **Negative clauses** — no forbidden dep tuple/lock entry (in bare + quoted atom
  forms); no runtime-internal namespace reference in any scanned source file.

The test is mutation-proven in every scanned directory + the real adapter module,
with dep-removal and form-precise regex RED proofs.

## Consequences

- The wall is **machine-checked, not prose-only**. Adding a private coupling or
  bumping/deleting the protocol dep reds the test.
- The BAP pin in `mix.exs` is the explicit ref that gates when an adapter bump
  is required (if BAP's vectors change, this adapter's conformance test goes red
  — the coupling is intentional). *(Amended 2026-08-17: the pin's
  alignment-with-BA posture — default alignment, a verifiability-gated
  BARA-ahead exception — is governed by [ADR-0010](0010-pin-bump-policy.md),
  which extends this ADR.)*
- Transports stay protocol-free: this adapter is called *by* the edge agent, not
  embedded in the transport libraries.
