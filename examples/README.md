# Examples

A self-contained, runnable demo of the adapter — **no database, no Docker, no other project
running.** The adapter is pure crypto (it signs; it does not persist), so the demo needs no
backing store.

## `report_envelope_roundtrip.livemd` — a Livebook

Runs the full capability round-trip in-process and plays all three roles so you can see exactly
what the adapter does and doesn't do:

1. **Issuer** mints a grant (played here only so the demo has a real grant — *not* the adapter's job).
2. **Holder** — `BoundedAuthorityReportAdapter.sign_report/3` signs the proof over a report. **This is the adapter's one job.**
3. **Verifier** — the public `BoundedAuthorityProtocol.V1.check_envelope/2` accepts the envelope.
4. **Tamper** + **wrong-key** — both rejected (the bindings are real, not vacuous).

### Run it

```bash
# from the repo root
mix deps.get                       # fetch bounded_authority_protocol (private git; needs access)
livebook server examples/report_envelope_roundtrip.livemd
```

(No Livebook? The notebook's setup cell uses `Mix.install` on this repo, so it also runs from
[livebook.dev](https://livebook.dev) after a `git clone` — it pulls the adapter + BAP itself.)

### What this is not

- **Not a consumer.** The adapter signs; a real consumer (verifier application's report path) additionally
  binds the envelope to the authenticated reporter (`docs/consumer-integration.md` §8) and dedupes
  nonces against a replay ledger (§9). Those are the consumer's job — that's where a database
  would enter — not the adapter's.
- **Not an issuer.** The grant is an *input* to the adapter. The runtime issues it.
