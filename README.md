# Bounded Authority Report Adapter

[![Hex](https://img.shields.io/hexpm/v/bounded_authority_report_adapter.svg)](https://hex.pm/packages/bounded_authority_report_adapter)
[![Docs](https://img.shields.io/badge/hexdocs-reference-blue.svg)](https://hexdocs.pm/bounded_authority_report_adapter)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

The Elixir signer for the [Bounded Authority Protocol](https://hex.pm/packages/bounded_authority_protocol).

The protocol package builds the exact bytes to sign for every protocol object, verifies
them, and never signs. This library does the signing: you give it a key handle that
reaches your own key custody (an HSM, a KMS, or an in-process key for development) and it
returns the signed compact form. **The private key never enters the library.**

Use it when an agent or service must prove, per request, that it holds the key an issuer
granted authority to: the holder signs a proof over the issuer's grant and the exact
request, and any verifier checks both offline with public keys. The same signing path
signs the issuer's grants, chain checkpoints, key rotations and content assertions.

Verifiers depend only on the protocol package, never on this one.

## Installation

Add the package to `deps/0` in `mix.exs`:

<!-- doc-sample: fragment -->
```elixir
def deps do
  [
    {:bounded_authority_report_adapter, "~> 0.10.0"}
  ]
end
```

Requires Elixir 1.18, 1.19 or 1.20 on Erlang/OTP 27 through 29. The protocol package
resolves with it.

## Quick start

A key handle is a `{module, term}` pair. The module implements the
`BoundedAuthorityReportAdapter` callbacks against your key store, and the term is a key
reference only that module understands. This development handle derives each Ed25519 key
from its name, in process. Never use it in production; a production handle forwards the
same calls to your HSM or KMS.

```elixir
defmodule MyApp.DevKey do
  @moduledoc "Development only: derives an Ed25519 key from its name. Never use in production."
  @behaviour BoundedAuthorityReportAdapter

  # The handle term is {role, name}. The role matters only to sign_grant/3.
  @impl true
  def sign(message, {_role, name}),
    do: {:ok, :crypto.sign(:eddsa, :none, message, [private_key(name), :ed25519])}

  @impl true
  def public_key({_role, name}), do: {:ok, public_key_of(name)}

  # The raw RFC 7638 thumbprint, from the protocol package's documented JWK functions.
  @impl true
  def thumbprint({_role, name}) do
    with {:ok, jwk} <- BoundedAuthorityProtocol.V1.Jwk.encode_public(public_key_of(name), %{}),
         {:ok, thumbprint} <- BoundedAuthorityProtocol.V1.Jwk.thumbprint(jwk, %{}) do
      {:ok, Base.url_decode64!(thumbprint, padding: false)}
    end
  end

  # Key id and public key in one call, so a rotating key store cannot split them.
  @impl true
  def key_identity({_role, name}), do: {:ok, {name, public_key_of(name)}}

  # Role, key id and public key in one call. sign_grant/3 requires the :issuer role.
  @impl true
  def signing_identity({role, name}), do: {:ok, {role, name, public_key_of(name)}}

  defp private_key(name), do: :crypto.hash(:sha256, "development only: " <> name)

  defp public_key_of(name) do
    {public_key, _private_key} = :crypto.generate_key(:eddsa, :ed25519, private_key(name))
    public_key
  end
end
```

The whole loop: an issuer grants one holder key one operation, the holder signs a proof for
one request, and a verifier checks the pair with public keys only.

```elixir
alias BoundedAuthorityProtocol.V1

issuer = {MyApp.DevKey, {:issuer, "issuer-key-1"}}
holder = {MyApp.DevKey, {:holder, "holder-key-1"}}
now = System.system_time(:second)

# 1. Issuer: grant the holder's key the "archive_document" operation for one hour.
{:ok, holder_thumbprint} = MyApp.DevKey.thumbprint({:holder, "holder-key-1"})

{:ok, %{grant: grant}} =
  BoundedAuthorityReportAdapter.sign_grant(
    %{
      issuer: "https://issuer.example",
      grant_id: "urn:example:grant:archive-1",
      audiences: ["https://records.example"],
      issued_at: now,
      not_before: now,
      expires_at: now + 3600,
      holder_thumbprint: holder_thumbprint,
      operations: [%V1.Operation{name: "archive_document", selectors: [:all]}]
    },
    issuer
  )

# 2. Holder: sign a proof that binds the grant to this exact request. The request body
#    is passed in the protocol's tagged form, decoded from the raw bytes sent.
raw_body = ~s({"document":"minutes-2026-10-01.pdf"})
{:ok, cast_arguments} = V1.Json.decode(raw_body)

{:ok, %{grant: grant, proof: proof}} =
  BoundedAuthorityReportAdapter.sign_report(
    %{
      grant_compact: grant,
      operation: "archive_document",
      method: "POST",
      target_uri: "https://records.example/archive",
      invocation_id: "7d3f1c2e-8a4b-4c5d-9e6f-0a1b2c3d4e5f",
      cast_arguments: cast_arguments,
      nonce: "nonce-archive-1"
    },
    holder
  )

# 3. Verifier: rebuild the expected request and check grant and proof together.
{:ok, issuer_public_key} = MyApp.DevKey.public_key({:issuer, "issuer-key-1"})

{:ok, facts} =
  V1.check_envelope(
    %V1.Credentials{grant: grant, proof: proof},
    %V1.ExpectedRequest{
      trusted_issuer: %V1.TrustedIssuer{key_id: "issuer-key-1", public_key: issuer_public_key},
      issuer: "https://issuer.example",
      audience: "https://records.example",
      method: "POST",
      target_uri: "https://records.example/archive",
      invocation_id: "7d3f1c2e-8a4b-4c5d-9e6f-0a1b2c3d4e5f",
      operation: "archive_document",
      cast_arguments: cast_arguments,
      evaluation_time: now,
      clock_skew: 60,
      proof_max_age: 300,
      nonce: {:required, "nonce-archive-1"},
      bounds: V1.Bounds.maximum()
    }
  )

{facts.operation, facts.authorization}
#=> {"archive_document", :not_evaluated}
```

`check_envelope/2` returns cryptographic facts, never an authorization decision
(`authorization: :not_evaluated`): whether to act on a verified request is the
verifier's policy. A real verifier also binds the holder to the identity it authenticated
and keeps a nonce ledger; see [Consumer integration](docs/consumer-integration.md).
[Getting started](docs/getting-started.md) walks this loop step by step.

## What it signs

| Function | Object | Callbacks it uses | Verify with |
|---|---|---|---|
| `sign_report/3` | holder proof (the grant passes through unchanged) | `sign/2`, `public_key/1` | `V1.check_envelope/2` |
| `sign_local_loopback_report/3` | local-loopback development proof (`ba+loopback-proof`) | `sign/2`, `public_key/1` | `LocalLoopbackHttp.V1.check_envelope/2` |
| `sign_grant/3` | capability grant (issuer role only) | `sign/2`, `signing_identity/1` | `V1.verify_grant/3` |
| `sign_anchor/3` | consumption-chain boundary anchor | `sign/2`, `key_identity/1` | `V1.verify_historical_anchor/3` |
| `sign_key_transition/3` | historical-key transition | `sign/2`, `key_identity/1` | `V1.verify_key_transition/4` |
| `sign_content_assertion/3` | content assertion (`ba+content-assertion`) | `sign/2`, `key_identity/1` | `ContentAssertion.V1.verify_assertion/2` |

These take Ed25519 keys (contract-major 1). `BoundedAuthorityReportAdapter.V3` provides
`sign_report/3`, `sign_grant/3`, `sign_anchor/3` and `sign_key_transition/3` for the ES256
suite (contract-major 3) with P-256 keys. The key's shape selects the suite: a 32-byte
Ed25519 public key for the functions above, a 65-byte uncompressed P-256 point for `V3`.
Verify functions are in the protocol package (`BoundedAuthorityProtocol.*`).

Every function returns `{:ok, map}` or `{:error, reason}` with a closed set of reasons and
no values in errors. See [Errors](docs/errors.md).

## Safety properties

- **Key custody stays with you.** Every handle callback may reach a remote custodian.
- **Wrong-key guard.** Every signature is verified against the handle's public key before
  it is returned; a custodian that signs with the wrong key fails as `:signing_failed`.
- **Role gate.** `sign_grant/3` signs only when the handle declares the issuer role, so a
  holder handle cannot mint its own capability. It can additionally require a role
  attestation signed by the authority.
- **Explicit profiles.** The local-loopback and content-assertion profiles are selected by
  calling their functions; nothing is inferred from URIs, headers or the environment.
- **Signing is not authorization.** The verifier decides what a signature proves;
  trusted keys, replay protection and policy stay with the verifying host.

## Content assertions

`sign_content_assertion/3` signs a standalone assertion that binds the SHA-256 digest of
exact content bytes to an issuer, audience, lineage subject, semantic profile, validity
window and predecessor. It grants nothing. Continuing the quick start:

```elixir
alias BoundedAuthorityProtocol.ContentAssertion

publisher = {MyApp.DevKey, {:holder, "publisher-key-1"}}
content = ~s({"station":"riverside","pm25":[8.1,7.9,8.4]})
{:ok, content_digest} = ContentAssertion.V1.content_digest(content, %{})
profile_digest = :crypto.hash(:sha256, "air-quality schema, version 1")

{:ok, %{content_assertion: assertion}} =
  BoundedAuthorityReportAdapter.sign_content_assertion(
    %{
      jti: "urn:example:assertion:riverside-1",
      iss: "urn:example:publisher",
      aud: "urn:example:archive",
      sub: "urn:example:dataset:riverside-air-quality",
      profile: "urn:example:profile:air-quality/1",
      profile_digest: profile_digest,
      content_digest: content_digest,
      gen: 1,
      prev: <<0::256>>,
      iat: now,
      nbf: now,
      exp: now + 3600
    },
    publisher
  )

# The consumer hashes the bytes it holds and verifies against the publisher's key.
{:ok, publisher_public_key} = MyApp.DevKey.public_key({:holder, "publisher-key-1"})

{:ok, assertion_facts} =
  ContentAssertion.V1.verify_assertion(assertion, %ContentAssertion.V1.ExpectedContentAssertion{
    attestor: %V1.HistoricalPublicKey{
      key_id: "publisher-key-1",
      public_key: publisher_public_key,
      valid_from: now - 60,
      valid_before: now + 3600
    },
    issuer: "urn:example:publisher",
    audience: "urn:example:archive",
    subject: "urn:example:dataset:riverside-air-quality",
    profile: "urn:example:profile:air-quality/1",
    profile_digest: profile_digest,
    content_digest: content_digest,
    now: now,
    bounds: V1.Bounds.maximum()
  })

assertion_facts.verification
#=> :signature_and_window
```

The first assertion in a lineage has `gen: 1` and an all-zero `prev`. The signer does not
read or interpret the content.

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

Runnable examples live in the repository's `examples/` directory: a Livebook that runs every
signing entry point, including the ES256 surface, and plays issuer, holder and verifier (the
test suite executes it), and an `edge_agent` app that runs the full loop over HTTP.

## What this is not

- **Not a verifier.** Verification is the protocol package's job, in every party.
- **Not an issuer runtime.** It signs a grant for an issuer that keeps its key behind a
  handle; issuing, tracking and revoking grants belong to your authority service.
- **Not a transport or a store.** It returns compact strings; carrying and persisting them
  is yours.
- **Not key custody.** It calls your handle; it never generates, stores or receives a
  private key.

## Development

```bash
mix deps.get
MIX_ENV=test mix ci
```

`mix ci` runs the same checks as CI: formatting, compilation with warnings as errors,
Credo, the test suite (including a conformance round-trip against the protocol's
published vectors, the Livebook, and every runnable code sample in these docs), coverage,
Dialyzer, documentation, advisory audits, and the package and reproducibility checks, for
the library and the example app.

## Security

Report vulnerabilities as described in [SECURITY.md](SECURITY.md).

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
