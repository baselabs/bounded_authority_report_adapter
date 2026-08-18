# 14. test/support compiles only in :test — the reference key-handle does not ship

Date: 2026-08-18

## Status

Accepted. Records the packaging decision in force since RA1 (2026-08-09,
`7190453`/`f21dfef`) — until now it lived only in the `mix.exs` `elixirc_paths`
comment ("design C5"), `Keys.RawKey`'s moduledoc, and AGENTS.md. Authored when
the 2026-08-17/18 alignment audits listed the missing ADR (carried three
audit rounds).

## Context

The adapter's whole contract is "caller supplies a `{module(), term()}` key
handle; the adapter signs via it" (ADR-0002/0006). The test suites need at
least one working handle, and the convenient one is a `{public_key,
private_key}` tuple of raw Ed25519 keys in process memory (`Keys.RawKey`). The
obvious placement — `lib/`, shipped in the artifact — would distribute exactly
the custody posture strategy §4 says the separate repo exists to prevent
("once the signing key is in the app, extracting it is a re-architecture, not
a refactor"): a raw-key handle in `lib/` makes key-in-process-memory every
consumer's cheapest option.

## Decision

1. **`test/support/` compiles ONLY in `:test`** (`elixirc_paths(:test)`);
   every other environment compiles `lib/` alone, so no support module can
   load in `:dev`/`:prod` or ship in the artifact (the `package: files:`
   list in mix.exs carries `lib/` + docs, never `test/`).
2. **`Keys.RawKey` stays TEST-ONLY** — the reference handle for the suites and
   local `MIX_ENV=test` development. Its moduledoc names the production
   alternative (real custody: HSM, OS keychain, a key server) and forbids
   this module's use there.
3. **Nothing outside `:test` consumes `test/support/`.** The Livebook
   (`examples/report_envelope_roundtrip.livemd`) is deliberately
   self-contained — it inlines its own throwaway seeded keypairs + a minimal
   handle instead of importing the reference impl. A future notebook that
   wants `Keys.RawKey` must run under `:test`, not pull support code into a
   shipped env.
4. **The dependency-direction wall still SCANS `test/support/`** (ADR-0003):
   the directory carries signing-path code, so a forbidden dep or
   runtime-internal reference planted there matters even though the code
   never ships. Test-only is a packaging boundary, not a scan exemption.

## Consequences

- The artifact physically cannot grow a private-key-in-memory implementation
  by accident; compiling support code into a shipped env is a visible
  `elixirc_paths` change that must supersede this ADR, not erode it.
- Cost: consumers writing their first handle have no shipped reference
  implementation to copy — the behaviour contract (the
  `BoundedAuthorityReportAdapter` moduledoc), `docs/consumer-integration.md`,
  and the test suites carry that weight deliberately.
- Bare `mix compile` runs in `:dev` and never sees support-module warnings —
  the per-file floor's `MIX_ENV=test mix compile --warnings-as-errors`
  requirement (AGENTS.md) exists partly because of this.
