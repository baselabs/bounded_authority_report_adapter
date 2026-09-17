# ADR 0020: The dependency-currency gate (latest-first)

- Status: Accepted
- Date: 2026-09-16
- Relates to: [ADR-0010](0010-pin-bump-policy.md) (the one deliberate pin
  this gate deliberately does NOT float), [ADR-0011](0011-two-project-structure.md)
  (the gate runs per mix project)

## Context

Nothing in CI or the local battery noticed resolver-updatable dependency
drift. Real drift existed at audit time: the library lock held `dialyxir`
1.4.7 (latest 1.4.8) and `ex_doc` 0.40.3 (latest 0.40.4); the example app's
lock held `req` 0.7.2 while the library's own lock had already moved to
0.7.4 in the 0.6.0 advisory sweep — the two locks drifted apart with no gate
the wiser. "We never bumped it" is not a state a repository should be able
to sit in silently.

Two prior traps shape the design. `mix hex.outdated` exits nonzero BOTH on
drift and on lookup failure, so an exit-code gate classifies nothing. And
its rendered table pads rows with trailing whitespace, so a status match
anchored on a hard `$` silently fails open on padded rows.

## Decision

1. **Latest-first policy**: every resolver-updatable dependency sits at the
   latest version its declared requirement admits. Anything not at latest is
   a deliberate pin with an inline reason in `mix.exs` (identity contract,
   major jump pending, or resolver conflict). The one deliberate pin in this
   repo is `bounded_authority_protocol == 0.4.0` — ADR-0010's bump policy
   owns it; the currency gate never floats it.
2. **`scripts/check_deps_currency.exs`** (run via `mix run --no-start` — an
   `.exs`, not the original `.sh`, so the gate runs on every OS lane;
   `feedback_cross_platform_capability_is_required`) enforces
   the policy under a
   caller-cwd contract: the script never cds — CI invokes it once per
   project job from that job's working directory, and `mix ci` invokes it
   for both projects. It classifies the RENDERED tables (direct AND `--all`):
   "Update possible" rows (anchored `[[:space:]]*$` against the padding) are
   resolvable drift and fail the gate with the packages named;
   "Update not possible" rows are resolver-rejected pins and are REPORTED
   with each package's requirement chain (`mix hex.outdated <pkg>`), not
   failed; a run where no table renders is an UNVERIFIED currency state and
   exits nonzero — an unverified state must never pass.
3. The gate runs in both CI jobs (after dependency install) and in both
   project sections of `mix ci`, so the local parity alias and the workflow
   fail together on the same drift.

## Rejected alternatives

- **Exit-code classification of `mix hex.outdated`**: the nonzero-on-lookup-
  failure collision makes every network hiccup indistinguishable from drift
  — the exact ambiguity that made the old un-gated state invisible.
- **Renovate/Dependabot-style bot PRs**: they move the decision to a queue
  of PRs; the policy here is that the tree is never behind in the first
  place, and deliberate pins (BAP) would generate perpetual noise.
- **Gating only direct dependencies**: a resolvable transitive drift
  (`--all` table) is drift too; only resolver-REJECTED transitives are
  reported rather than failed.

## Failure modes and proofs

- The trailing-whitespace anchor is load-bearing: with a hard `$` the padded
  "Update possible␠␠" rows stop matching and the gate passes real drift.
- Proofs recorded 2026-09-16: green on the post-sweep locks (exit 0, both
  projects, via the exact `mix cmd` invocations `mix ci` uses); RED on a
  fabricated drift (a scratch copy with the pre-sweep lock reverted:
  `mix deps.get`, then the script exits 1 naming `dialyxir` and `ex_doc`);
  RED on the no-table path (run outside a mix project: exit 1, "currency
  state unverified").
- Resolver-rejected chains at acceptance time: `hex_core` 0.19.0, `protobuf`
  0.17.0, `purl` 0.5.0 — all held by `sbom ~>` requirements; reported, not
  failed, and visible in every gate run.
