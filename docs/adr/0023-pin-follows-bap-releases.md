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
2. **The pin stays exact and deliberate.** The pin is the pair: the exact requirement in
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
