# 4. Private release posture (not hex-published)

Date: 2026-08-10

## Status

**Superseded 2026-08-20** by the owner decision to publish. The package is released to Hex as
`bounded_authority_report_adapter` (0.2.0) once its sibling protocol package published; consumption
uses the Hex release. The unlock condition this ADR itself named — an external re-implementation
against the documented protocol format — was met by the protocol's public release. This record is
retained as history; the private-posture directive below is no longer in force.

Accepted (historical). Records the owner directive of 2026-08-09 (strategy §1); in force
since the scaffold until superseded above.

## Context

The adapter began as a new library whose API was still tuning against its first
consumers. Publishing to Hex signals a
stability contract — a public semver surface, a deprecation cadence, an
expectation of backwards compatibility — that does not yet hold. The rationale
matched the original portfolio posture. That posture changed when the public
protocol and conformance corpus established an external contract. The separate
runtime remains private because it is a commercial application, not a library.

## Decision

The adapter was a **private source repository**, consumed through a source dependency,
**not published to hex**. `package/0` metadata (`maintainers`, `licenses`,
`links`, `files`) is carried in `mix.exs` — it documents the package shape and
keeps a future flip cheap — but `mix hex.publish` is not the posture. "Public" in
the inter-repo docs means the API contract between BaseLabs repos, not the hex
registry (strategy §2).

## Consequences

- Hex publication is **deferred** until (a) the adapter has been consumed across
  the BaseLabs projects that need it, (b) the conformance round-trip is stable,
  and (c) the API has survived at least one external (non-Elixir) consumer's
  re-implementation against the documented format.
- Flipping private → public later costs nothing structurally (the dependency stays
  valid); publishing-then-revoking costs reputation + semver.
- `package/0` metadata is not a contradiction with this posture — carrying it is
  normal and documents intent; it is the publication *act* that is deferred.
