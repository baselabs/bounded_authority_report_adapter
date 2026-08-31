# edge_agent — a runnable end-to-end reference (ROADMAP RA9)

A minimal but real Elixir app that proves the adapter works in a deployment: an
**edge agent** signs a application report with `BoundedAuthorityReportAdapter.sign_report/3`
and POSTs it over HTTP to a **receiver** that verifies the envelope via
`BoundedAuthorityProtocol.V1.check_envelope/2`. No database, no Docker, no other
project running — the whole capability loop runs in one app.

The Livebook (`../report_envelope_roundtrip.livemd`) plays all three roles
in-process; THIS app adds the piece the Livebook does not — **real HTTP
transport** between an edge signer and a consumer.

## What's here

```
edge_agent/
  lib/
    edge_agent.ex               # the agent: mint → sign_report/3 → POST (Req)
    edge_agent/handle.ex        # DEMO proof-only key-handle (prod = HSM/KMS)
    edge_agent/demo_issuer.ex   # DEMO grant minter (prod = the BA runtime)
    edge_agent/receiver.ex      # the consumer: a Plug (Bandit) that verifies
    edge_agent/receiver/
      nonce_ledger.ex           # the §9 replay ledger (an ETS table)
  config/config.exs             # shared config (agent + receiver in sync)
  test/edge_agent_test.exs      # the round-trip + the four rejection classes
```

## Run it

From `examples/edge_agent/`:

```bash
# 0. fetch deps (bounded_authority_protocol resolves from Hex)
mix deps.get

# 1. terminal one — start the receiver (listens on 127.0.0.1:4001 by default)
mix run --no-halt -e EdgeAgent.Receiver.start

# 2. terminal two — run the agent once against it
mix run -e 'EdgeAgent.run() |> IO.inspect(label: "result")'

# The local-loopback profile flow (development listeners): the same loop over
# the byte-distinct ba+loopback-proof profile with a mandatory nonce and a
# canonical http://127.0.0.1 / http://[::1] target (see
# EdgeAgent.run_local_loopback/1 + the receiver's profile: :local_loopback
# mode; tests/local_loopback_test.exs runs it over real IPv4 AND IPv6
# listeners). Loopback HTTP is plain HTTP — not equivalent to HTTPS.
```

You should see:

```
result: {:ok, 200, "accepted"}
```

`200 accepted` means the receiver decoded the raw report body, ran
`check_envelope/2` against the published demo issuer key, bound the verified
holder to the configured identity, claimed the nonce — and every step passed.

## What the receiver actually checks (the complete safe path)

The receiver (`EdgeAgent.Receiver`) runs ONE `with` that fails closed to a uniform
`401 invalid`, following `docs/consumer-integration.md`:

1. **`V1.Json.decode(raw_body)`** — the request's RAW bytes → BAP's tagged
   `cast_arguments`. A BAP-strict decode failure (a Jason-valid-but-BAP-invalid
   body) collapses to `:invalid`.
2. **`V1.check_envelope/2`** — the grant + proof verified cryptographically
   against the published issuer key + the reconstructed expected request.
3. **Identity binding (§8)** — the verified envelope's `holder_thumbprint` must
   equal the configured identity key's thumbprint. Without this, a captured
   envelope is replayable under a different identity.
4. **Nonce dedup (§9)** — the nonce is claimed on a replay ledger. Without this,
   a byte-identical request is re-accepted within `proof_max_age`.

The envelope rides as two headers (`X-BA-Grant`, `X-BA-Proof`); the raw report
body rides as the request body. Both sides decode the SAME bytes with the SAME
function, so `cast_arguments` agrees by construction.

## Run the tests

```bash
mix test
```

Six tests: the happy path (via `EdgeAgent.run/1` and a hand-built envelope) plus
the four rejection classes that prove the defenses are real, not vacuous — a
tampered proof, a stranger's proof, a wrong identity (the §8 binding catches an
envelope `check_envelope` would otherwise accept), and a replayed nonce (the §9
ledger catches a second identical request).

## Development notes (gotchas specific to this app)

This is its **own mix project** (`examples/edge_agent/mix.exs`), separate from the
library at the repo root. Its deps (req/bandit/plug) live HERE — they never touch
the library's `mix.exs`, so the library's dependency-direction wall (RA3, which
scans `lib`/`test/support`/`mix.exs`/`mix.lock` — **not `examples/`**) stays green.
See the repo-root [`AGENTS.md`](../../AGENTS.md) for the full operational picture.

- **Bandit ≥ 1.12:** `:ip`/`:port`/`:scheme` go at the TOP LEVEL of the Bandit
  child spec, not nested under `:options:`. The old shape raises
  `Unsupported key(s) in top level config: [:options]` at server start (it passes
  `mix compile` and fails at runtime).
- **Test-file warnings surface only at `mix test` time**, not `mix compile` — this
  app has no `elixirc_paths` override, so the compile step covers `lib/` only.
  Watch the `mix test` output.
- **`V1.Json` is decode-only** (no `encode`): both the agent and the receiver
  `V1.Json.decode` the SAME raw body bytes. Don't reach for an encode; the body is
  bytes both sides decode identically.


## What this is, and is not

- **Not a production issuer.** `DemoIssuer` mints the grant from a demo issuer key
  so the loop is self-contained. A real grant is minted by the `bounded_authority`
  authority runtime and arrives at the edge out-of-band.
- **Not production key custody.** `EdgeAgent.Handle` holds a `{pub, priv}` tuple in
  memory. A production edge agent implements the handle callbacks against an HSM,
  the OS keychain, or a key server — that swap is the ONE place custody enters.
- **Not a production replay ledger.** `NonceLedger` is an in-memory ETS table. A
  production consumer keys a durable unique constraint on `(identity, nonce)`.
- **The receiver depends ONLY on `bounded_authority_protocol`** — never on this
  adapter. That is the dependency-direction wall: the verifier consumes the public
  protocol package; the adapter is the holder-side signing glue the agent uses.

See [`docs/consumer-integration.md`](../../docs/consumer-integration.md) for the
full universal consumer contract this app implements.
