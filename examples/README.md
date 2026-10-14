# Examples

Self-contained, runnable demos of the adapter — **no database, no Docker, no other project
running.** The adapter is pure crypto (it signs; it does not persist), so neither demo needs a
backing store.

## `edge_agent/` — a runnable end-to-end app

A minimal mix app that adds the piece the Livebook does not — **real HTTP transport** between
an edge signer and a consumer. An **edge agent** calls `sign_report/3` and POSTs the envelope
via Req to a **receiver** (a Plug on Bandit) that verifies via `check_envelope/2`, binds the
holder to the configured identity (`docs/consumer-integration.md` §8), and dedupes nonces on a
replay ledger (§9). A demo grant minter + an in-memory key-handle make the loop runnable with
zero external services. CI-covered (`test/edge_agent_test.exs`).

See [`edge_agent/README.md`](edge_agent/README.md) for how to run both sides.

## `report_envelope_roundtrip.livemd` — a Livebook

Runs every signing entry point the adapter exposes, in-process, and verifies each result with the
public `bounded_authority_protocol` package. It plays all three roles so you can see exactly what
the adapter does and does not do:

1. **Issuer** — `sign_grant/3` signs a grant through an issuer-role handle, with and without the
   role-attestation gate. Grant issuance normally belongs to the authority runtime; the adapter
   signs one only for an issuer that keeps its key behind a handle.
2. **Holder** — `sign_report/3` signs the proof that binds the grant to one request. **This is the
   adapter's one job.** Development listeners on literal loopback use
   `sign_local_loopback_report/3`, the byte-distinct `ba+loopback-proof` profile (also exercised
   over real HTTP by `EdgeAgent.run_local_loopback/1`).
3. **Verifier** — the public `check_envelope/2`, `verify_grant/3` and the other verify functions
   accept what the adapter signed.

It also signs a boundary anchor, a key transition and a content assertion
(`sign_content_assertion/3`), and repeats the grant, proof, anchor and key-transition flow under
ES256 with P-256 keys (`BoundedAuthorityReportAdapter.V3`), showing that the adapter emits low-S
signatures even when the key handle returns the high-S spelling. Every signer is shown failing
closed, mostly in a cell right after its success: a changed byte, a wrong key, a wrong audience
or a wrong context, each returning the real error value. A final section shows the adapter's own
wrong-key guard (`:signing_failed`) for a handle that signs with a different key than it reports
and for a P-256 handle that returns DER.

### Run it

Open it in Livebook (the desktop app: *File → Open* → this file; or `livebook server` from the
repo root and open the URL), then **Run All**. The setup cell installs this repository as a path
dependency and resolves `bounded_authority_protocol` from Hex. Every key is generated when the
notebook runs. The value under each cell is the result that cell returns.

### CI

The notebook is executed by the library's test suite:
`test/bounded_authority_report_adapter/livebook_walkthrough_test.exs` reads every fenced `elixir`
cell (with or without attributes), skips the `Mix.install/1` setup cell, evaluates every other
cell in order against the repository source, and requires each cell's returned value to equal the
output pinned under it; the number of evaluated cells must equal the number of pinned outputs. It
also fails when a `sign_*/3` exported by a `lib/` module is never called in the notebook's code
(read from the parsed code, so a comment does not count), when a cell is not formatted, and when
the notebook's statement of the source version, the protocol requirement and whether that
requirement is released disagrees with `mix.exs` and the CHANGELOG. It runs in `mix test`, so in
`mix ci` and in CI.

### What this is not

- **Not a consumer.** The adapter signs; a real consumer additionally binds the envelope to the
  authenticated sender (`docs/consumer-integration.md` §8) and dedupes nonces against a replay
  ledger (§9). Those are the consumer's job (that is where a database would enter), not the
  adapter's.
- **Not an issuer runtime.** The adapter can sign a grant for an issuer's key handle, but issuing,
  revoking and keeping track of grants belongs to the authority runtime.
