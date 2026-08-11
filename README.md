# Bounded Authority Report Adapter

> Universal companion signer to the public
> [`bounded_authority_protocol`](https://github.com/baselabs/bounded_authority_protocol)
> package — BAP produces the signing input for each protocol object (proof, boundary anchor, …)
> and refuses to sign; this library takes a local key-handle + a BAP signing input and signs it.
> See [ADR-0006](docs/adr/0006-universal-companion-signer.md). **Consuming an envelope** (a
> verifier's side of the contract, no adapter dependency) is documented in
> [docs/consumer-integration.md](docs/consumer-integration.md).
>
> **Where this fits:** this is the holder-side signer SDK in BaseLabs's commercial agent-authority
> platform. For the one-page product picture, see
> [`bounded_authority` → overview](https://github.com/baselabs/bounded_authority/blob/master/docs/strategy/overview.html)
> (HTML) or [overview.md](https://github.com/baselabs/bounded_authority/blob/master/docs/strategy/overview.md).

**Looking for a specific doc?** [`doc-map.md`](https://github.com/baselabs/bounded_authority/blob/master/docs/doc-map.md) — every doc across all four repos.

**Private BaseLabs library.** Not published to hex. Consumed by BaseLabs projects
(verifier application's report path, and future edge agents / any signing party) as a private git dep.

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

**See it run, self-contained (no DB / no Docker / no other project):** the
[Livebook demo](examples/report_envelope_roundtrip.livemd) plays all three roles (issuer →
holder/sign → verifier) in one notebook and proves a tampered or wrong-key proof is rejected.

## Status

**RA1–RA7 shipped** (2026-08-09 → 2026-08-11):

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
- **RA4 — boundary-anchor signing.** `sign_anchor/3` signs a `BoundaryAnchor`
  (a durable chain checkpoint) via the shared companion-signer tail, round-tripping
  through `verify_historical_anchor/3`. Both key identifiers come from the
  key-handle; wrong-key + defect-injection tripwires guard it.
- **RA5 — verifier application consumer + the universal contract.** The consumer-integration
  guide (the verifier's side of the envelope, no adapter dependency), the
  self-contained Livebook demo, and the CI workflow. (The verifier application-side report-plug
  wiring lands in `verifier application`.)
- **RA6 — closeout.** ADRs `0001`–`0006` landed; the full suite + conformance
  round-trip green.
- **RA7 — grant signing.** `sign_grant/3` signs a grant (the issuer-role
  instantiation of the shared companion-signer tail), round-tripping through
  `verify_grant/3` and the full `check_envelope/2` loop. The handle's
  `signing_identity/1` must resolve to the `:issuer` role — the C1 gate
  (ADR-0006's grant-signing pre-commitment; a `:holder` or roleless handle is
  rejected before signing). Recorded in ADR-0007.

Remaining: RA8 (key-transition signing), RA9 (edge-agent reference), RA10
(cross-language verifier). See `docs/ROADMAP.md`.

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
mix test              # 83 tests (sign_report + sign_anchor + sign_grant + conformance + dep-direction)
mix compile --warnings-as-errors
mix credo
```

Requires Elixir 1.18+ (developed on 1.20.2 / OTP 29; see `.tool-versions`).

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
