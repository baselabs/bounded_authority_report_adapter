# 4. Private release posture (not hex-published)

Date: 2026-08-10

## Status

Accepted. Records the owner directive of 2026-08-09 (strategy §1); in force
since the scaffold. Authored retroactively when the ADR gap was flagged by the
2026-08-10 alignment audit.

## Context

The adapter is a new library whose API is still tuning against its first
consumers (verifier application's report path first). Publishing to hex signals a
stability contract — a public semver surface, a deprecation cadence, an
expectation of backwards compatibility — that does not yet hold. The rationale
matches the sibling repos: BAP is private because its API is still tuning against
the first real consumers; the runtime is private because it is a service, not a
library.

## Decision

The adapter is a **private BaseLabs GitHub repo**, consumed via private git dep,
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
- Flipping private → public later costs nothing structurally (the git dep stays
  valid); publishing-then-revoking costs reputation + semver.
- `package/0` metadata is not a contradiction with this posture — carrying it is
  normal and documents intent; it is the publication *act* that is deferred.
