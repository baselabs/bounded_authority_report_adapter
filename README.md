# Bounded Authority Report Adapter

> holder-side signing adapter for application reports — wraps the public
> [`bounded_authority_protocol`](https://github.com/baselabs/bounded_authority_protocol)
> package's grant/proof envelopes with local private-key signing.

**Private BaseLabs library.** Not published to hex. Consumed by BaseLabs projects
(verifier application's report path, and future edge agents) as a private git dep.

## What this is

An external data plane (the "edge agent") reports materializations into a
verifier. To prove a report is authorized — *not* just transport-authenticated
— the report carries a **grant + proof envelope**: a capability grant signed by
the authority, plus a holder proof signed by the edge agent's private key.
This adapter is the glue the edge agent calls to **produce** that envelope.

The split of responsibility across the three BA repos:

| Repo | Role | Does it sign? | Does it verify? |
|---|---|---|---|
| `bounded_authority_protocol` | the public verifier + signing-input producer | No (produces inputs only) | **Yes** (pure verifier) |
| `bounded_authority` (runtime) | issuance, key custody/rotation, live revocation | At issuance | — |
| **`bounded_authority_report_adapter`** (this repo) | holder-side signing glue | **Yes** (holder proof, local key) | No |

The verifier (verifier application) verifies the envelope using the protocol package;
it never depends on this adapter (the dependency-direction wall). See
`docs/charter.md` for the authority model and `docs/strategy.md` for the
dependency + release posture.

## Status

**RA1/RA2/RA3 shipped** (2026-08-09 → 2026-08-10):

- **RA1 — envelope signing.** `sign_report/3` binds an issuer-signed grant to a
  application report by producing a holder proof, returning the grant + proof envelope
  the verifier verifies via `BoundedAuthorityProtocol.V1.check_envelope/2`.
  The adapter signs ONLY the proof (the grant arrives issuer-signed and passes
  through untouched). The holder key never enters the adapter (callers supply a
  `{module(), term()}` key-handle callback). Wrong-key verify + exit/throw
  containment make a misconfigured signer fail loudly, not silently.
- **RA2 — conformance round-trip.** Every published-vector case verifies via
  `check_envelope/2` (envelopes) / `verify_grant/3` (grant-time), and an
  adapter-coherent round-trip (`sign_report/3` → `check_envelope/2`) is green
  against a freshly issuer-signed grant. Defect-injection RED proofs guard
  non-vacuity.
- **RA3 — dependency-direction wall.** A two-clause structural test proves the
  adapter depends only on `bounded_authority_protocol`, scanning `lib/` +
  `test/support/`.

Remaining: RA4 (checkpoint-ack probe), RA5 (verifier application consumer), RA6 (topology
ADR + closeout). See `docs/ROADMAP.md`.

## Installation (private git dep)

```elixir
def deps do
  [
    {:bounded_authority_report_adapter,
     git: "https://github.com/baselabs/bounded_authority_report_adapter.git",
     ref: "<pinned-ref>"}
  ]
end
```

This adapter pulls in `bounded_authority_protocol` transitively (also a private
git dep). Both repos must be reachable from the consumer's build environment.

## Development

```bash
mix deps.get          # fetches bounded_authority_protocol
mix test              # 55 tests (sign_report + conformance + dep-direction)
mix compile --warnings-as-errors
mix credo
```

Requires Elixir 1.18+ (developed on 1.20.2 / OTP 29; see `.tool-versions`).

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
