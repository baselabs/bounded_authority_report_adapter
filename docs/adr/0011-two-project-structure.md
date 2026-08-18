# 11. Two-project structure (the `examples/` carve-out + two-job CI)

Date: 2026-08-17

## Status

Accepted. Records the structure the RA9 example app forced (2026-08-12) and CI
has enforced since — CI itself landed at `45a8bc2` (2026-08-11) as a SINGLE
`gate` job; the two-job bar this ADR records arrived with the example job in
`79fe668` (2026-08-12). The dependency-direction carve-out it rests on has
governed since RA3 (ADR-0003) without its own record. Authored when the
2026-08-17 alignment audit listed it an ADR-gap candidate.

## Context

The RA9 deliverable — a runnable edge-agent reference app (`examples/edge_agent/`)
— needs exactly what the library must never take: HTTP client + server deps. The
dependency-direction wall (ADR-0003) forbids transport deps in the LIBRARY's
`mix.exs`, yet an example that proves real-deployment behavior has to POST an
envelope over HTTP and serve a verifying receiver.

Three shapes: (a) no example — loses the real-deployment proof and the consumer
contract's runnable reference; (b) the example inside the library's mix project
with dev-only transport deps — pollutes the wall's scan surface, mixes library
and demo contexts, and lets demo deps ride the library's dependency graph;
(c) a separate mix project under `examples/` consuming the adapter as a path dep.

## Decision

1. **`examples/edge_agent/` is its own mix project** — its own `mix.exs`,
   `mix.lock`, and `deps/`; the adapter is a `path: "../.."` dependency, so the
   example always tracks this repo's working tree, and
   `bounded_authority_protocol` resolves transitively. Transport deps
   (`req`, `plug`, `bandit`) live ONLY here.
2. **The dep-wall scan deliberately excludes `examples/`** — the carve-out is
   the wall's design, not a hole. The wall
   (`dependency_direction_test.exs`) scans `lib/`, `test/support/`, and the
   library's `mix.exs`/`mix.lock`; a transport dep added to the LIBRARY still
   trips it red. The example holds transport deps LEGITIMATELY (they are its
   purpose), so there is no dep-direction scan to run there — and nothing in
   `examples/` can leak into the library's artifact (the path dep points the
   example AT the library, never the reverse). The example's CI job proves the
   app builds + tests green with exactly its declared deps; it is not a
   namespace/dep scan.
3. **CI is two jobs, both green is the bar** (`.github/workflows/ci.yml`):
   `gate` (root: format · compile warnings-as-errors · credo --strict · test,
   including the conformance round-trip) and the `examples/edge_agent` job (the
   same four steps, `working-directory: examples/edge_agent`). A broken example
   reds the gate, not a provision attempt.
4. The Livebook (`examples/report_envelope_roundtrip.livemd`) is NOT run in CI —
   its round-trip is covered by the library's `sign_report_test.exs`.

## Consequences

- The wall keeps its single-subject clarity (library deps only) while the repo
  still ships runnable transport proof.
- The example compiles without an `elixirc_paths` override, so its TEST-file
  warnings surface at `mix test` time, not `mix compile` time — watched in CI
  and recorded in AGENTS.md.
- Adding a second example later follows the same shape: own mix project, own CI
  job or a widened `working-directory` matrix, never the library's dep graph.
