# Bounded Authority Report Adapter

[![Hex](https://img.shields.io/hexpm/v/bounded_authority_report_adapter.svg)](https://hex.pm/packages/bounded_authority_report_adapter)
[![Docs](https://img.shields.io/badge/hexdocs-reference-blue.svg)](https://hexdocs.pm/bounded_authority_report_adapter)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

The Elixir signer for the [Bounded Authority Protocol](https://hex.pm/packages/bounded_authority_protocol).

The protocol package builds the exact bytes to sign for every protocol object, verifies
them, and never signs. This library does the signing: you give it a key handle that
reaches your own key custody (an HSM, a KMS, or an in-process key for development) and it
returns the signed compact form. **The private key never enters the library.**

Verifiers depend only on the protocol package, never on this one.

## Installation

```elixir
def deps do
  [
    {:bounded_authority_report_adapter, "~> 0.9.0"}
  ]
end
```

Requires Elixir 1.18, 1.19 or 1.20 on Erlang/OTP 27 through 29.

## Quick start

A key handle is a `{module, term}` pair. The module implements the
`BoundedAuthorityReportAdapter` callbacks against your key store:

```elixir
defmodule MyApp.HolderKey do
  @behaviour BoundedAuthorityReportAdapter

  @impl true
  def sign(message, ref), do: {:ok, MyApp.Custody.sign_ed25519(ref, message)}

  @impl true
  def public_key(ref), do: {:ok, MyApp.Custody.public_key(ref)}

  @impl true
  def thumbprint(ref),
    do: BoundedAuthorityProtocol.V1.Jwk.public_key_thumbprint_raw(MyApp.Custody.public_key(ref), %{})

  @impl true
  def key_identity(ref), do: {:ok, {"holder-key-1", MyApp.Custody.public_key(ref)}}

  @impl true
  def signing_identity(ref), do: {:ok, {:holder, "holder-key-1", MyApp.Custody.public_key(ref)}}
end
```

An agent proves one request by signing a holder proof over an issuer-signed grant:

```elixir
{:ok, %{grant: grant, proof: proof}} =
  BoundedAuthorityReportAdapter.sign_report(
    %{
      grant_compact: grant_from_issuer,
      operation: "transfer",
      method: "POST",
      target_uri: "https://api.example.test/invoke",
      invocation_id: "123e4567-e89b-42d3-a456-426614174000",
      cast_arguments: {:object, [{"amount", {:integer, 5000}}]},
      nonce: "challenge-001"
    },
    {MyApp.HolderKey, :holder},
    %{}
  )
```

The resource verifies `grant` and `proof` with the protocol package's
`BoundedAuthorityProtocol.V1.check_envelope/2` and gets cryptographic facts back, never an
authorization decision. [Getting started](docs/getting-started.md) walks the whole loop,
including the verifier side.

## What it signs

| Function | Object | Role |
|---|---|---|
| `sign_report/3` | holder proof (the grant passes through unchanged) | holder |
| `sign_local_loopback_report/3` | local-loopback development proof (`ba+loopback-proof`) | holder |
| `sign_grant/3` | capability grant | issuer only |
| `sign_anchor/3` | consumption-chain boundary anchor | any |
| `sign_key_transition/3` | historical-key transition | any |
| `sign_content_assertion/3` | content assertion (`ba+content-assertion`) | any |

`BoundedAuthorityReportAdapter.V3` provides `sign_report/3`, `sign_grant/3`,
`sign_anchor/3` and `sign_key_transition/3` for the ES256 suite (contract-major 3). The
key's shape selects the suite: 32-byte Ed25519 keys for the functions above, 65-byte
P-256 keys for `V3`.

Every function returns `{:ok, map}` or `{:error, reason}` with a closed set of reasons and
no values in errors. See [Errors](docs/errors.md).

## Safety properties

- **Key custody stays with you.** Every handle callback may reach a remote custodian.
- **Wrong-key guard.** Every signature is verified against the handle's public key before
  it is returned; a custodian that signs with the wrong key fails as `:signing_failed`.
- **Role gate.** `sign_grant/3` signs only when the handle resolves the issuer role, so a
  holder can never mint its own capability. It can additionally require an
  authority-signed role attestation.
- **Explicit profiles.** The local-loopback and content-assertion profiles are selected by
  calling their functions; nothing is inferred from URIs, headers or the environment.
- **Signing is not authorization.** The verifier decides what a signature proves;
  trusted keys, replay protection and policy stay with the verifying host.

## Content assertions

`sign_content_assertion/3` signs a standalone assertion that binds the SHA-256 digest of
exact content bytes to an issuer, audience, lineage subject, semantic profile, validity
window and predecessor:

```elixir
{:ok, digest} = BoundedAuthorityProtocol.ContentAssertion.V1.content_digest(content_bytes, %{})

{:ok, %{content_assertion: compact}} =
  BoundedAuthorityReportAdapter.sign_content_assertion(
    %{
      jti: "urn:example:assertion:1",
      iss: "urn:example:issuer",
      aud: "urn:example:audience",
      sub: "urn:example:lineage:document-1",
      profile: "urn:example:profile:document/1",
      profile_digest: profile_digest,
      content_digest: digest,
      gen: 1,
      prev: <<0::256>>,
      iat: now,
      nbf: now,
      exp: now + 3600
    },
    {MyApp.HolderKey, :holder},
    %{}
  )
```

The signer does not read or interpret the content. The consumer verifies with
`BoundedAuthorityProtocol.ContentAssertion.V1.verify_assertion/2`, supplying the trusted
key, the expected context and the digest of the bytes it holds.

## Telemetry

Each signing call emits `[:bounded_authority_report_adapter, :sign, :start | :stop]` with
atom-only metadata: the object kind and a result class. No key material, message bytes or
content appears. A sustained `:signing_failed` rate means custody is misconfigured. See
[Telemetry](docs/telemetry.md).

## Documentation

- [Getting started](docs/getting-started.md): first sign, then a production key handle.
- [Usage rules](usage-rules.md): the integration contract as a checklist.
- [Errors](docs/errors.md): every error reason and what to check.
- [Recipes](docs/recipes.md): HSM and KMS handles, a Plug consumer, the loopback listener.
- [Security model](docs/security.md): trust boundaries and named misuses.
- [Telemetry](docs/telemetry.md): events, result classes and alerting.
- [Consumer integration](docs/consumer-integration.md): the verifier side of the contract.
- [Upgrading](docs/upgrading.md): per-version migration notes.
- [Changelog](CHANGELOG.md): release notes.
- [Contributing](CONTRIBUTING.md) and the [code of conduct](CODE_OF_CONDUCT.md).

Runnable examples live in the repository's `examples/` directory: a Livebook that plays
issuer, holder and verifier, and an `edge_agent` app that runs the full loop over HTTP.

## Development

```bash
mix deps.get
MIX_ENV=test mix ci
```

`mix ci` runs the same checks as CI: formatting, compilation with warnings as errors,
Credo, the test suite (including a conformance round-trip against the protocol's
published vectors), coverage, Dialyzer, documentation, advisory audits, and the package
and reproducibility checks, for the library and the example app.

## Security

Report vulnerabilities as described in [SECURITY.md](SECURITY.md).

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
