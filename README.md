# Bounded Authority Report Adapter

Holder-side companion signer for the [Bounded Authority
Protocol](https://hex.pm/packages/bounded_authority_protocol). The protocol package produces the
deterministic signing input for each protocol object (holder proof, boundary anchor, grant, key
transition) and **refuses to sign**; this library takes a local key handle and a signing input and
produces the signed compact form. **The private key never enters the library** — callers supply a
`{module(), term()}` handle whose module implements the signing callbacks against their own custody
(an HSM, a KMS, or an in-process key in test).

Verifiers depend only on the protocol package, never on this adapter. Consuming an envelope (the
verifier's side of the contract) is documented in
[docs/consumer-integration.md](docs/consumer-integration.md).

## Installation

```elixir
def deps do
  [
    {:bounded_authority_report_adapter, "~> 0.2"}
  ]
end
```

## What it is

An edge agent proves a request is authorized — not merely transport-authenticated — by presenting a
**grant + proof envelope**: an issuer-signed capability grant plus a holder proof signed by the
agent's own key. This adapter is what the agent calls to *produce* that envelope. It signs the
proof; the grant arrives issuer-signed and passes through untouched. The receiver verifies the
envelope with the protocol package's `check_envelope/2` and gets back cryptographic facts.

The signer is universal across the four protocol objects, each through one shared signing tail:

| Function | Object | Role |
|---|---|---|
| `sign_report/3` | holder proof (the grant passes through) | holder |
| `sign_anchor/3` | boundary anchor | role-agnostic |
| `sign_key_transition/3` | key transition | role-agnostic |
| `sign_grant/3` | grant | issuer-only, structurally gated |

The role gate is load-bearing: a holder handle **cannot** sign a grant. Only a handle that resolves
the issuer role may, so an agent can never mint its own capability.

**See it run, self-contained (no database, no Docker):** the repository's `examples/` directory
carries a Livebook demo that plays issuer → holder → verifier in one notebook, and an `edge_agent`
app that runs the full loop over real HTTP (agent signs and POSTs; receiver verifies via
`check_envelope`). Both prove a tampered or wrong-key proof is rejected.

## Key custody

The library never holds a key. A caller passes a `{module, ref}` handle; the module implements
`sign/2`, `public_key/1`, and `thumbprint/1` (plus optional identity callbacks) against its own key
store. Every sign path ends in a verify-against-the-public-key guard, so a misconfigured signer
fails loudly rather than emitting an unverifiable signature. A production holder points the handle
at an HSM or KMS; the in-memory reference handle used in tests compiles only in the test
environment and never ships.

## Development

```bash
mix deps.get
mix ci
```

`mix ci` reproduces the CI pipeline locally: format, warnings-as-errors compilation, Credo, and the
full test suite (including the conformance round-trip against the protocol package's published
oracle vectors and the dependency-direction wall), for both the library and the example app.

Requires Elixir 1.18+ (developed on 1.20 / OTP 29). The runnable `examples/edge_agent` app is a
separate mix project with its own deps and CI job — develop it from inside that directory.

## Security

See [`SECURITY.md`](SECURITY.md) for the vulnerability-reporting process.

## License

Apache-2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
