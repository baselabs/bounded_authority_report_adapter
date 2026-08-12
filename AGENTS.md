# AGENTS.md — working in this repo as an AI coding agent

Operational instructions for any agent (forge track or otherwise) editing this
repository. This is the *how to work here* doc; `docs/charter.md` is the authority
model, `docs/strategy.md` is the dependency/release posture, `docs/ROADMAP.md` is
the build arc. Read this FIRST, then the charter/strategy for the *why*.

## What this is

`bounded_authority_report_adapter` (BARA) — the HOLDER-side signing glue for the
Bounded Authority protocol. It takes a `{module(), term()}` key-handle + a BAP
signing input, signs via the handle's local key, assembles the compact via the
public `bounded_authority_protocol` (BAP) package. It signs proofs, grants, and
boundary anchors; it does NOT verify, does NOT transport, does NOT persist, is NOT
the runtime, is NOT hex-published.

## Read BAP first-hand — never trust a summary (handoff, doc, or your own memory)

The contract surfaces live in the **BAP dependency** at a pinned git ref. Before
building anything that calls BAP, **read the BAP source first-hand** — the pinned
ref is the truth, not this repo's docs, not a prior session's handoff, not the
Livebook's account. The handoff that pointed at this work named the exact files:
`deps/bounded_authority_protocol/lib/bounded_authority_protocol/v1/runtime.ex`
(`check_envelope/2`, `verify_grant/3`), the struct files (`expected_request.ex`,
`trusted_issuer.ex`, `envelope_facts.ex`, `credentials.ex`), `jwk.ex`
(`public_key_thumbprint_raw/2`). Build verifier/consumer calls from the struct
defs + the function `@spec`s, not from prose.

**Verify before you cite.** ADR numbers, ROADMAP rows, and "the standard says X"
claims are all UNVERIFIED until you check the actual file. Two phantom citations
bit a prior slice: a "Req per repo-root AGENTS.md" rule (no such rule existed)
and "BAP ADR-0014/0015" (only ADRs 0001–0008 exist at the pinned ref). `ls
deps/bounded_authority_protocol/docs/adr/` before you cite a BAP ADR number.

## The dependency-direction wall (RA3 — non-negotiable)

The LIBRARY depends ONLY on `bounded_authority_protocol` — never on the
`:bounded_authority` runtime, never on a transport lib (`:replicant`/`:capstan`),
never on an HTTP client/server. Enforced by
`test/bounded_authority_report_adapter/dependency_direction_test.exs`, which scans
**`lib/`, `test/support/`, `mix.exs`, `mix.lock`** for forbidden deps + runtime-
internal namespace refs.

That scan does **NOT cover `examples/`** — so the example app
(`examples/edge_agent/`) is a SEPARATE mix project that may declare transport deps
(req/bandit/plug) in its OWN `mix.exs`. Adding transport deps THERE is fine;
adding them to the library's `mix.exs` trips the wall red.

## The build: TWO mix projects, each with its own CI

1. **The library** (repo root) — `mix.exs` with `bounded_authority_protocol` +
   dev/test-only `credo`/`ex_doc`. `lib/bounded_authority_report_adapter.ex` is the
   one signing module. `test/support/` compiles only under `:test` (the reference
   key-handle + fixtures do NOT ship — design C5).
2. **The example app** (`examples/edge_agent/`, ROADMAP RA9) — its own `mix.exs`,
   its own `mix.lock`, its own `deps/`. The adapter is a `path: "../.."` dep; it
   pulls req/bandit/plug. Runnable end-to-end (`EdgeAgent.run` → `EdgeAgent.Receiver`).

CI (`.github/workflows/ci.yml`) runs **two jobs**: `gate` (the library: format ·
compile · credo · test) and `example` (the example app, same four steps, run from
`examples/edge_agent/`). Both must stay green. The Livebook
(`examples/report_envelope_roundtrip.livemd`) is NOT run in CI — its round-trip is
covered by the library's `sign_report_test.exs`.

## Per-file floor on EVERY touched file (the RA7 lesson)

Before calling anything done, run **on every file you touched**:

```
mix format
MIX_ENV=test mix compile --warnings-as-errors   # NOT bare `mix compile`
mix credo --strict
mix test
```

The `MIX_ENV=test` matters for the LIBRARY: bare `mix compile` runs in `:dev`,
which skips `test/support/` and misses warnings there (a real RA7 closeout miss).
Run BOTH from the repo that owns the file (library floor at the root, example-app
floor inside `examples/edge_agent/`).

**Example-app nuance:** the example app has no `elixirc_paths` override, so
`mix compile` compiles only `lib/` — **test-file warnings surface only at `mix
test` time**, not at `mix compile`. So watch the `mix test` output for warnings;
the compile step alone does not cover test files there.

## Transport posture (chosen, not mandated by a rule that doesn't exist)

There is **no repo-root or user-level rule** mandating a specific HTTP client or
server. The choices below were made on technical merit for RA9 and are the
current convention:

- **HTTP client: Req** (modern Elixir standard, Finch-backed). Used by the edge
  agent to POST the envelope + raw report body.
- **HTTP server: Bandit + Plug** (pure-Elixir Plug adapter). The receiver is a
  bare `@behaviour Plug` served by Bandit.

**Bandit ≥ 1.12 option gotcha:** listener options (`:ip`, `:port`, `:scheme`) go at
the **top level** of the Bandit child spec, NOT nested under `:options:`. The
pre-1.12 `options: [ip: ..., port: ...]` shape raises
`Unsupported key(s) in top level config: [:options]` at server start — it passes
`mix compile` (no spec) and fails at `mix test` / runtime. Pin Bandit `~> 1.0` and
use top-level options.

## Raw-body retention: `Plug.Conn.read_body/1` vs `body_reader`

A consumer must retain the request body's RAW bytes (parsing loses both the bytes
and BAP's tagged structure). `docs/consumer-integration.md` §2 discusses
`Plug.Parsers`' `body_reader:` — that's for a pipeline that ALSO parses other
routes. The example receiver has NO competing parser, so it reads the raw body
directly via `Plug.Conn.read_body/1` (3-clause: `{:ok,_,conn}` / `{:more,_,conn}` /
`{:error,_}`). Thread the returned `conn` — `{:error, _}` is a 2-tuple with no conn.
A receiver with `Plug.Parsers` in the pipeline must switch to the `body_reader:`
approach instead.

## BAP's `Json` is decode-only

`BoundedAuthorityProtocol.V1.Json` has `decode/2` but **no `encode`**. The
edge↔verifier contract is symmetric on the RAW bytes: both sides call
`V1.Json.decode(raw_body_bytes)` to get the tagged `cast_arguments` — byte-agreement
by construction. Do not reach for an `encode`; the body is bytes that already exist
(report source), and the agent decodes them the same way the receiver does.

## Commit discipline

- Surgical pathspecs: `git commit -o <files>` (or explicit paths). **Never
  `git add -A`** — `.forge/` (process state, gitignored) and `.zcode/` would ride.
- `.forge/` is gitignored EXCEPT `.forge/critical-surfaces`, `.forge/conformance*`
  (tracked-when-present). The commit MESSAGE is the audit trail for forge work
  (`.forge/` artifacts don't ship).
- Single tree on `master`, no feature branches unless the user says otherwise.
- Never `git stash`.

## Forge track calibration

- **T2** for the crypto signing surfaces (`lib/bounded_authority_report_adapter.ex`,
  any `sign_*/3`, the key-handle contract, conformance) — manifest-declared
  critical; the full design-adversarial + plan + 4-lens + cross-vendor loop.
- **T1** for additive work that calls existing tested surfaces without new crypto
  (the example app, docs, tests over existing behavior) — intent-first, one
  diff-review, closeout-lite.
- A slice that introduces NEW verify/crypto in a consumer escalates to T2 even if
  it's "just a consumer" — the receiver in the example app stayed T1 because it
  calls BAP's *existing* `check_envelope`, introducing none.

## Environment

Elixir 1.20.2 / OTP 29 (`.tool-versions`, asdf). Run `mix` from inside the repo
dir (the asdf shim quirk). The BAP dep is a private git remote — `mix deps.get`
needs GitHub access to `baselabs/bounded_authority_protocol`.
