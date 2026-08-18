# 12. Example-app transport choices (Req client; Bandit + Plug server)

Date: 2026-08-17

## Status

Accepted. Records the RA9 transport selections (2026-08-12) — until now carried
only by the example's `mix.exs`, `receiver.ex`, and an AGENTS.md section that
concedes they were "chosen, not mandated," recorded nowhere else. These choices
bind the EXAMPLE APP only, never the library and never a consumer.

## Context

The edge-agent example needs an HTTP client (POST the envelope + raw report
body) and an HTTP server (the verifying receiver). No repo-root or user-level
rule mandates any specific client or server — the choice was made on technical
merit, and the selection's sharpest consequence (a Bandit option-shape gotcha
that passes compile and fails at runtime) is exactly the kind of decision an ADR
exists for.

## Decision

1. **HTTP client: Req** (`~> 0.5` — the modern Elixir standard, Finch-backed).
   Used by the agent to POST `{grant, proof}` headers + the RAW report body.
2. **HTTP server: Bandit** (`~> 1.0`) **+ Plug** (`~> 1.15`). The receiver
   (`EdgeAgent.Receiver`) is a bare `@behaviour Plug` served by Bandit's
   `plug:` child-spec form — no Phoenix, no router.
3. **The Bandit option-shape gotcha is part of this decision's record:**
   listener options (`:ip`, `:port`, `:scheme`) go at the TOP level of the
   Bandit child spec (`{Bandit, plug: __MODULE__, scheme: :http, ip: ip,
   port: port}` — `receiver.ex`) — and have since **0.7.6** (Apr 2023), which
   renamed the nested top-level `options` field to `thousand_island_options`
   and added `ip`/`port` top-level support. Under the example's `~> 1.0`
   constraint NO resolvable version accepts the nested `options:` shape: it
   raises `Unsupported key(s) in top level config: [:options]` at server START
   — it passes `mix compile` (no dialyzer spec on the child spec) and fails
   first at `mix test`/runtime, the quiet class. *(Corrected 2026-08-17: this
   repo's record — and the RA9 session that met the error on a 1.12 install —
   attributed the break to "Bandit ≥ 1.12"; the changelog shows the option
   shape has been top-level-only since 0.7.6.)*
4. **Raw-body retention follows from the receiver's shape:** with no competing
   parser in the pipeline, the receiver reads the raw body directly via
   `Plug.Conn.read_body/1` (3-clause, threading the returned `conn`). A
   consumer whose pipeline DOES run `Plug.Parsers` must switch to the
   `body_reader:` approach instead (consumer-integration.md §2) — the
   edge↔verifier contract is symmetric on the raw bytes (`V1.Json.decode` on
   both sides).

## Consequences

- Convention, not mandate: these bind `examples/edge_agent/` only. The library
  stays transport-free (ADR-0003/0011), and `docs/consumer-integration.md`
  remains transport-agnostic — verifier application's report path (instance #1) and any
  consumer pick their own stack.
- The option-shape gotcha is recorded here once, in the receiver's comment, and
  in AGENTS.md — three places, one truth.
- Req/Bandit/Plug version bumps are the example project's own concern (its CI
  job), never the library's.
