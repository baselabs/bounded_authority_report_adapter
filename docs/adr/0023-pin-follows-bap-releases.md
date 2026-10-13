# 23. The BAP pin follows published BAP releases

Date: September 28, 2026

## Status

Accepted (owner decision, September 28, 2026). Supersedes
[ADR-0010](0010-pin-bump-policy.md) and retires the alignment exception recorded in
[ADR-0018](0018-local-loopback-profile-pin.md).

## Context

ADR-0010 made BARA's protocol pin track the pin of the private authority runtime (BA):
a BARA release could move to a BAP release whose library code changed only after BA had
adopted and validated it, unless the owner superseded the policy for that span. The
owner did so for BAP 0.3.0 (ADR-0018) and 0.6.0 (the 2026-09-23 supersession note).

That ordering is backwards. BAP is the public protocol and BARA its public companion
signer; BA is one consumer of both. A consumer never gates the release of the packages
it depends on. BAP qualifies each release with its own normative contract, certified
corpora, independent SDK agreement, and package gates; BARA qualifies each adoption with
its own suite against the exact published package.

## Decision

1. **BARA follows published BAP releases directly.** BARA may move its protocol pin to
   any published BAP release. No other repository's pin, validation, or schedule is a
   precondition. BA adopts BAP and BARA releases on its own schedule.
2. **The pin stays exact and deliberate.** *(Amended October 6, 2026: the requirement is now
   a range with a security floor; see the amendment below.)* The pin is the pair: the exact requirement in
   `mix.exs` and the locked version in `mix.lock`. A bump moves the requirement, both
   dependency-wall attributes, and both project locks (library and example app) in one
   commit. The pin is read from those files, never restated in prose.
3. **Every bump carries its evidence.** The bump commit quotes, from the protocol
   repository over the release-tag span `v<locked>..v<candidate>`: the full
   `git diff --stat`; the `-- lib/` delta; and the `-- priv/conformance test/conformance`
   corpus sweep. Library changes that touch surfaces BARA consumes are classified in the
   bump commit (additive, behavior change, or wire change) and exercised by BARA's
   suite. The consumed standard vector's round-trip (RA2, ADR-0013) is quoted green at
   the new pin on every bump, and `MIX_ENV=test mix ci` passes on the bump tree.
4. **Corpus scope is unchanged.** RA2 discharges exactly the consumed vector
   (ADR-0013 Decision 1). Corpus changes outside it are surfaced by the sweep in
   Decision 3 and consumed by BARA only through a deliberate decision recorded in the
   bump commit.
5. **Tooling reads no private repository.** `scripts/check-bap-drift.sh` reports BARA's
   lock, the published Hex releases, and protocol `main`, with the `lib/` delta of each
   span. It does not read or report any consumer's pin.

## Consequences

- BARA can release protocol-dependent features as soon as the BAP release that carries
  them is published and BARA's own gates pass.
- BA's pin may trail BARA's. That is a BA adoption task, owned in that repository.
- ADR-0010 remains in the repository as the historical record of the retired policy and
  of the surface-enumeration discipline that Decision 3 keeps.

## Amendment, October 6, 2026: a range with a security floor

Owner ruling, October 6, 2026: libraries declare dependency ranges with a security floor,
and only applications lock exact versions in `mix.lock`. This amends Decision 2 only; every
other decision above stands.

- **Decision 2 amended.** The requirement in `mix.exs` is a range, not an exact pin:
  `~> 0.8.0`. The floor (0.8.0) is the first protocol release that carries the strict
  Ed25519 verification rule BARA calls, so no 0.7.x release may resolve. The ceiling is the
  next protocol minor, exclusive. The pin is now the pair: the requirement range in
  `mix.exs` and the exact locked version in `mix.lock`, which this repository still holds
  at one reviewed version because it is also the tree the suite runs against.
- **What moves a requirement.** Raising the floor (a new security fix BARA depends on) or
  the ceiling (adopting the next protocol minor) edits `mix.exs`, the dependency wall's
  `@protocol_requirement`, `@protocol_floor` and `@protocol_ceiling`, and both locks in one
  commit. Adopting a newer release inside the range moves only the locks and the wall's
  `@protocol_locked_version`.
- **The wall.** `test/bounded_authority_report_adapter/dependency_direction_test.exs`
  asserts the range shape instead of an exact string: the declared requirement admits the
  floor and later releases below the ceiling, admits nothing below the floor or at the
  ceiling, and admits the locked version. A requirement that admits 0.7.x (for example
  `~> 0.7`) or is an exact pin fails it, and the wall reads the declaration from `mix.exs`
  itself.
- **Decision 3 unchanged.** Every adoption of a newer release, inside or beyond the range,
  still carries its span evidence in the commit that moves the locks.
- **Consequence for the currency gate.** [ADR-0020](0020-dependency-currency-gate.md)
  listed the protocol's exact requirement as a deliberate pin that the gate never floats. It
  is now an ordinary range: the gate reports drift when a release inside the range is
  published and the lock is behind it, and the lock moves under Decision 3.
- **Consequence for consumers.** An application can resolve BARA together with any protocol
  release in the range, instead of only the one BARA was built against.
