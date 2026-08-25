# Examples

Self-contained, runnable demos of the adapter — **no database, no Docker, no other project
running.** The adapter is pure crypto (it signs; it does not persist), so neither demo needs a
backing store.

## `edge_agent/` — a runnable end-to-end app (RA9)

A minimal mix app that adds the piece the Livebook does not — **real HTTP transport** between
an edge signer and a consumer. An **edge agent** calls `sign_report/3` and POSTs the envelope
via Req to a **receiver** (a Plug on Bandit) that verifies via `check_envelope/2`, binds the
holder to the configured identity (`docs/consumer-integration.md` §8), and dedupes nonces on a
replay ledger (§9). A demo grant minter + an in-memory key-handle make the loop runnable with
zero external services. CI-covered (`test/edge_agent_test.exs`).

See [`edge_agent/README.md`](edge_agent/README.md) for how to run both sides.

## `report_envelope_roundtrip.livemd` — a Livebook

Runs the full capability round-trip in-process and plays all three roles so you can see exactly
what the adapter does and doesn't do:

1. **Issuer** mints a grant (played here only so the demo has a real grant — *not* the adapter's job).
2. **Holder** — `BoundedAuthorityReportAdapter.sign_report/3` signs the proof over a report. **This is the adapter's one job.**
3. **Verifier** — the public `BoundedAuthorityProtocol.V1.check_envelope/2` accepts the envelope.
4. **Tamper** + **wrong-key** — both rejected (the bindings are real, not vacuous).

### Run it

Open it in Livebook (the desktop app: *File → Open* → this file; or `livebook server` from the
repo root and open the URL), then **Run All**. The setup cell pulls this repo + the
`bounded_authority_protocol` dependency from Hex, then each cell prints a plain `✅` / `❌` line.

### What you'll see (verified output)

```
🎟️ issuer-signed grant minted (529 bytes). It authorizes holder-thumbprint TrI1g9he… to perform operation "report_demo".
✍️ adapter signed the PROOF (678 bytes), binding the grant to this report. The grant passed through untouched.
✅ VERIFIED — the grant is genuine, the proof matches this report, the holder is the one the grant was issued to.
✅ tampered proof REJECTED — one flipped byte breaks the signature
✅ stranger's proof REJECTED — the proof must come from the holder the grant was issued to
```

### CI

The **notebook itself is not run in CI** — driving a Livebook headlessly is awkward (runtime +
`Mix.install` re-fetch + the CLI runner isn't in every build), and a notebook is the wrong shape
for a gate anyway. The same round-trip (sign → `check_envelope` → tamper/wrong-key reject) **is**
CI-covered, by `test/bounded_authority_report_adapter/sign_report_test.exs` (RA1's contract tests).
The notebook is the human-readable view of that contract; the test is the gate.

### What this is not

- **Not a consumer.** The adapter signs; a real consumer (consumer's report path) additionally
  binds the envelope to the authenticated reporter (`docs/consumer-integration.md` §8) and dedupes
  nonces against a replay ledger (§9). Those are the consumer's job — that's where a database
  would enter — not the adapter's.
- **Not an issuer.** The grant is an *input* to the adapter. The runtime issues it.
