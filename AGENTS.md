# AGENTS.md — working in this repo as an AI coding agent

How to work here. Read by area: `docs/charter.md` (authority model), `docs/strategy.md`
(dependency and release posture), `docs/ROADMAP.md` (build arc), `docs/adr/` (decisions),
`docs/consumer-integration.md` (consumer contract). Dated lessons, the former track calibration
and the full earlier text of this file: [`docs/reference/agent-history.md`](docs/reference/agent-history.md).

## What this is

`bounded_authority_report_adapter` (BARA) is BAP's universal companion-signer glue (ADR-0006;
holder-side by default, issuer-side for grants). It takes a `{module(), term()}` key-handle and a
BAP signing input, signs via the handle's local key, and assembles the compact via the public
`bounded_authority_protocol` (BAP) package. It signs proofs, grants, boundary anchors and key
transitions; it does NOT verify, transport, persist, or act as the runtime. The package and this
source repository are public. The separate `bounded_authority` runtime is a private commercial
application: not a public Hex package, not published to private Hex (no paid private-package
subscription exists), and never a dependency of this library. Any future private Hex release
requires an active subscription and fresh approval for that exact release and destination.

## Read BAP first-hand

- The contract is the **resolved BAP dependency** locked from Hex: the version in `mix.lock` and
  `deps/bounded_authority_protocol/` are the compiled truth, not this repo's docs, a handoff or
  the Livebook. Build calls from the struct definitions and function `@spec`s (for example
  `v1/runtime.ex` `check_envelope/2` and `verify_grant/3`, `jwk.ex` `encode_public/2` and
  `thumbprint/2`).
- Call only documented protocol functions:
  `test/bounded_authority_report_adapter/protocol_private_api_test.exs` fails on any call to a
  `@doc false` function or `@moduledoc false` module of the protocol package.
- Two layers drift: BARA's locked release (what it compiles against) and BAP main (what BAP has
  decided). A BAP ADR may be accepted on main and absent from the locked release. Before citing a
  BAP ADR or claiming something is blocked on BAP or BA, check the sibling checkout's main branch
  (`../bounded_authority_protocol/`, `../bounded_authority/`) with `git log`, `ls docs/adr/` or
  `grep`.

## The dependency-direction wall (RA3 — non-negotiable)

The LIBRARY depends ONLY on `bounded_authority_protocol`: never on the `:bounded_authority`
runtime, a transport library (`:replicant`/`:capstan`), or an HTTP client or server.
`test/bounded_authority_report_adapter/dependency_direction_test.exs` scans `lib/`,
`test/support/`, `mix.exs` and `mix.lock` for forbidden deps and runtime-internal namespace refs.
It does NOT cover `examples/`: the example app (`examples/edge_agent/`) is a separate Mix project
that may declare transport deps (req/bandit/plug) in its own `mix.exs`; adding them to the
library's `mix.exs` trips the wall.

## Protocol version discipline

- BAP comes from **Hex**. `mix.exs` declares a range with a security floor (owner ruling
  October 6, 2026, ADR-0023 amendment: libraries declare ranges, only applications lock exact
  versions); `mix.lock` records the exact version; the wall test pins both
  (`@protocol_requirement`, `@protocol_floor`, `@protocol_ceiling`, `@protocol_locked_version`).
  The values live in those files, never in prose (ADR-0023 decision 2).
- A bare `mix deps.update bounded_authority_protocol` reconciles lock and deps quietly; the
  wall's `@protocol_locked_version` reds the gate until the move is reviewed.
- Raising the floor or ceiling moves the `mix.exs` requirement, the wall's range attributes and
  BOTH locks in one commit; adopting a newer release inside the range moves
  `@protocol_locked_version` and BOTH locks. Either way enumerate the span and classify its
  `lib/` delta per ADR-0023. The example app's lock is held to parity by its own test. BARA
  follows published BAP releases directly; no consumer's pin gates a bump.
- `scripts/check-bap-drift.sh` compares the lock, hex.pm and BAP main (read-only). Run it before
  citing sibling state or planning a version move. A probe, not a gate; not part of `mix ci`.

## The build: two Mix projects

1. **The library** (repo root): `bounded_authority_protocol` plus dev/test-only `credo` and
   `ex_doc`. `test/support/` compiles only under `:test`; the reference key-handle and fixtures
   never ship (design C5, ADR-0014).
2. **The example app** (`examples/edge_agent/`, ROADMAP RA9): its own `mix.exs`, `mix.lock` and
   `deps/`; the adapter is a `path: "../.."` dep. Runnable end-to-end
   (`EdgeAgent.run` → `EdgeAgent.Receiver`).

CI (`.github/workflows/ci.yml`) runs two jobs, `gate` (library) and `example` (example app),
one Linux lane per supported OTP major 27–29 (ADR-0019). CI never adds macOS or Windows lanes;
Windows developers use WSL2 (clone inside the WSL filesystem, not under `/mnt/c`), and no
native-Windows path is maintained (owner direction, October 4, 2026).

The Livebook (`examples/report_envelope_roundtrip.livemd`) is run by
`test/bounded_authority_report_adapter/livebook_walkthrough_test.exs`: every fenced `elixir`
cell except the `Mix.install/1` setup cell is evaluated and compared with the output pinned
under it, so editing a cell means re-pinning its output. It also reds when a `lib/` module
exports a `sign_*/3` the notebook never calls, or when the notebook's source version, protocol
requirement or release state drifts from `mix.exs` and the CHANGELOG (update it in the same
commit as a version or range move).

**`mix ci`** reproduces the workflow step-for-step for both jobs (the example job through
`scripts/ci_example.exs`). Its first step, `scripts/ci_env_guard.exs`, refuses any boot other
than `MIX_ENV=test`. It exits non-zero if any step failed, but it does not stop at the first
failure: some steps end the run at once while others (`mix test`, `mix hex.audit`) record a
non-zero status and let later steps run, so read the whole output. Not reproduced locally:
checkout and setup-beam.

## Focused checks

- Library: `mix format`, `MIX_ENV=test mix compile --warnings-as-errors` (bare `mix compile`
  runs `:dev`, skips `test/support/` and misses its warnings), `mix credo --strict`, and
  `mix test` on the changed tests. Run them from the project that owns the file.
- Example app: no `elixirc_paths` override, so test-file warnings surface only at `mix test`.

## Example-app conventions

- HTTP client **Req**; HTTP server **Bandit + Plug** (a bare `@behaviour Plug` receiver). Chosen
  on merit for RA9, not mandated by any rule.
- Bandit listener options (`:ip`, `:port`, `:scheme`) go at the **top level** of the child spec,
  never nested under `:options` (raises `Unsupported key(s) in top level config: [:options]` at
  server start; compile does not catch it). Pin Bandit `~> 1.0`.
- A consumer must retain the request body's RAW bytes. The example receiver has no competing
  parser, so it reads the body via `Plug.Conn.read_body/1` (three clauses; thread the returned
  `conn`; `{:error, _}` carries no conn). A pipeline with `Plug.Parsers` must use the
  `body_reader:` approach (`docs/consumer-integration.md` §2).
- `BoundedAuthorityProtocol.V1.Json` is decode-only. Both sides call
  `V1.Json.decode(raw_body_bytes)` for the tagged `cast_arguments`; never reach for an `encode`.

## Workflow

Make the change, run the tests that cover it, commit with named paths, and push to `master`. CI
runs once on `master`; if it goes red, fix forward.

- CI runs the `gate` and `example` jobs; `mix ci` reproduces both. Run the focused checks that
  cover your change.
- Publishing, deploying and pushes to mirrors need the owner's approval for that action.
- A test that fails on every run is a defect: fix it, or quarantine it with a reason, in the
  change that finds it.
- Update the CHANGELOG when behavior, a dependency or a contract changes; other docs only when
  a contract changes.
- Stage exact paths, never `git add -A` (the ignored local-harness tree and `.zcode/` would
  ride). Single tree on `master`.

## Environment

Elixir 1.20.2 / OTP 29 (`.tool-versions`, asdf). The supported set is Elixir 1.18/1.19/1.20 on
Erlang/OTP 27–29 (25/26 excluded: BAP's codecs decode through `:json`, OTP 27+ stdlib),
enforced at config load by `config/config.exs` in both projects and carried one lane per major
by CI (ADR-0019; the Mix range, the set, `.tool-versions` and the lanes move in ONE commit). Run
`mix` from inside the repo directory (asdf shim quirk).
