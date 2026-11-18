# Bounded Authority Report Adapter

[![Hex](https://img.shields.io/hexpm/v/bounded_authority_report_adapter.svg)](https://hex.pm/packages/bounded_authority_report_adapter)
[![Docs](https://img.shields.io/badge/hexdocs-reference-blue.svg)](https://hexdocs.pm/bounded_authority_report_adapter)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

The Elixir signer for the [Bounded Authority Protocol](https://hex.pm/packages/bounded_authority_protocol).

The protocol package builds the exact bytes to sign for every protocol object, verifies
them, and never signs. This library does the signing: you give it a key handle that
reaches your own key custody (an HSM, a KMS, or an in-process key for development) and it
returns the signed compact form. The handle must contain only an opaque reference; never
put private key bytes in it.

Use it when an agent or service must prove, per request, that it holds the key an issuer
granted authority to: the holder signs a proof over the issuer's grant and the exact
request, and any verifier checks both offline with public keys. The same signing path
signs the issuer's grants, chain checkpoints, key rotations and content assertions.

Verifiers depend only on the protocol package, never on this one.

## What this is not

- **Not a general credential verifier.** The protocol package verifies envelopes and evidence.
  This adapter self-verifies its signatures and can verify an optional Ed25519 role attestation.
- **Not an issuer runtime.** It signs a grant for an issuer that keeps its key behind a
  handle; issuing, tracking and revoking grants belong to your authority service.
- **Not a transport or a store.** It returns compact strings; carrying and persisting them
  is yours.
- **Not key custody.** It calls your handle. Keep private keys behind that callback;
  the library cannot inspect or sanitize the opaque term you supply.

## Installation

Add the package to `deps/0` in `mix.exs`:

```elixir
def deps do
  [
    {:bounded_authority_report_adapter, "~> 1.0"}
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

  # The raw RFC 7638 thumbprint: the value a grant's holder_thumbprint carries.
  @impl true
  def thumbprint({_role, name}),
    do: BoundedAuthorityReportAdapter.public_key_thumbprint(public_key_of(name))

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
host's policy. Before any effect, the host binds the holder to its authenticated identity,
applies authorization, checks current revocation, and atomically admits nonce and invocation
replay identities through its durable execution record. See [Framework integration](docs/guides/framework-integration.md).
[Getting started](docs/guides/getting-started.md) walks this loop step by step.

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
suite (contract-major 3) with P-256 keys. Select the module explicitly: the main surface
requires a 32-byte Ed25519 public key; `V3` requires a 65-byte uncompressed P-256 point.
Verify functions are in the protocol package (`BoundedAuthorityProtocol.*`).

Every signing function returns `{:ok, map}` or `{:error, reason}` with a closed set of
reasons and no values in errors. The `public_key_thumbprint/1` helper returns
`{:ok, <<_::256>>}` or `{:error, :invalid}`. See [Errors](docs/guides/errors.md).

## Safety properties

- **Key custody stays with you.** Every handle callback may reach a remote custodian.
- **Wrong-key guard.** Every signature is verified against the handle's public key before
  it is returned; a custodian that signs with the wrong key fails as `:signing_failed`.
- **Role gate.** `sign_grant/3` requires `:issuer` from the caller-provided
  `signing_identity/1` callback. This is a local
  consistency gate, not independent issuer authorization. For Ed25519 it can additionally
  verify a role attestation against an explicitly trusted attestor.
- **Explicit profiles.** The local-loopback and content-assertion profiles are selected by
  calling their functions; nothing is inferred from URIs, headers or the environment.
- **Signing and verification are never authorization.** Pure verification returns facts.
  Execution depends on the verifying service's authorization policy, including trusted
  keys, identity binding, replay reservation and revocation.

## Documentation

Read the guides in this order:

- [Getting started](docs/guides/getting-started.md).
- [Holder requests](docs/guides/holder-requests.md).
- [Grants and roles](docs/guides/grants-and-roles.md).
- [Key custody](docs/guides/key-custody.md).
- [Anchors and rotation](docs/guides/anchors-and-rotation.md).
- [Content assertions](docs/guides/content-assertions.md).
- [Local loopback](docs/guides/local-loopback.md).
- [Framework integration](docs/guides/framework-integration.md).
- [Security](docs/guides/security.md).
- [Operations](docs/guides/operations.md).
- [Telemetry](docs/guides/telemetry.md).
- [Errors](docs/guides/errors.md).
- [Recipes](docs/guides/recipes.md).
- [Testing](docs/guides/testing.md).
- [Upgrading](docs/guides/upgrading.md).
- [FAQ](docs/guides/faq.md).
- [Glossary](docs/guides/glossary.md).
- [Cheatsheet](docs/guides/cheatsheet.md).

Runnable notebooks (each installs the exact public release):

- [Holder request](docs/notebooks/holder-request.livemd).
- [Issuer grants](docs/notebooks/issuer-grants.livemd).
- [ES256 custody](docs/notebooks/es256-custody.livemd).
- [Anchors and rotation](docs/notebooks/anchors-and-rotation.livemd).
- [Content assertions](docs/notebooks/content-assertions.livemd).
- [Local loopback](docs/notebooks/local-loopback.livemd).
- [Production preflight](docs/notebooks/production-preflight.livemd).

- [Usage rules](usage-rules.md), [Changelog](CHANGELOG.md), [Contributing](CONTRIBUTING.md),
  [Security reporting](SECURITY.md), and [Code of conduct](CODE_OF_CONDUCT.md).
- [Tested HTTP example](https://github.com/baselabs/bounded_authority_report_adapter/tree/master/examples/edge_agent).

## Development

```bash
mix deps.get
MIX_ENV=test mix ci
```

`mix ci` runs the same checks as CI: formatting, compilation with warnings as errors,
Credo, the test suite (including a conformance round-trip against the protocol's
published vectors, the notebook registry, and the recursively discovered code samples in these docs), coverage,
Dialyzer, documentation, rendered links, the notebooks against this checkout, advisory audits, and the package and reproducibility checks, for
the library and the example app. It runs the steps in order and exits non-zero if any step
failed. Not every failing step ends the run: a failing test suite, for one, lets the later
steps run, so read the whole output.

## Security

Report vulnerabilities as described in [SECURITY.md](SECURITY.md).

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
