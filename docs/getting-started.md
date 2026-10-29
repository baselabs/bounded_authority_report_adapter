# Getting started

This guide signs a grant, signs a proof over it, and verifies the pair, then shows what
changes for a production key handle. Every Elixir block after the install line runs as
written, in order, in one `iex -S mix` session of a project that depends on this package;
the test suite runs them the same way.

## Install

<!-- doc-sample: fragment -->
```elixir
{:bounded_authority_report_adapter, "~> 0.11.0"}
```

Add that line to `deps/0` in `mix.exs` and run `mix deps.get`. The package supports Elixir
1.18, 1.19 and 1.20 on Erlang/OTP 27 through 29; OTP 25 and 26 are not supported because
the protocol package decodes JSON through OTP 27's `:json` module.

To scaffold a starter key-handle module, add `{:igniter, "~> 0.8", only: [:dev, :test]}`
to your dependencies and run:

```sh
mix bounded_authority_report_adapter.install --module MyApp.HolderKey
```

The generated module compiles, and every callback raises until you wire it to your key
store, so it cannot sign anything by accident.

## The shape of the thing

The adapter never sees your private key. You pass a `{module, term}` key handle: the module
implements the `BoundedAuthorityReportAdapter` behavior, and the term is a key reference
only that module understands. The adapter asks the handle for its public key, asks it to
sign the exact bytes the protocol package produced, checks the signature against that
public key, and assembles the compact form.

Holders use it to sign proofs. Issuers can use it to sign grants. Any key holder can use it
to sign boundary anchors, key transitions and content assertions. Verifying is the protocol
package's job (`BoundedAuthorityProtocol.V1.check_envelope/2` and the other verify
functions); this adapter never verifies a credential.

## 1. A development key handle

A development handle needs five callbacks. This one derives each Ed25519 key from its name
in process, which is acceptable only for development. The repository's own test-only
handles live under `test/support/` and are not shipped in the package.

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

Which callbacks each entry point calls:

| Entry point | Callbacks |
|---|---|
| `sign_report/3`, `sign_local_loopback_report/3` | `sign/2`, `public_key/1` |
| `sign_grant/3` | `sign/2`, `signing_identity/1` (must declare `:issuer`) |
| `sign_anchor/3`, `sign_key_transition/3`, `sign_content_assertion/3` | `sign/2`, `key_identity/1` |

`thumbprint/1` is required by the behavior but the adapter does not call it; it exists so
you can check your handle against a grant's holder binding. `key_identity/1` and
`signing_identity/1` are optional callbacks: a handle that only signs proofs can omit them.

## 2. The issuer signs a grant

In production your authority service issues grants and the holder receives one out of
band. Here the same session plays the issuer. The grant names the holder's key by its
RFC 7638 thumbprint and lists the operations that key may perform.

```elixir
alias BoundedAuthorityProtocol.V1

issuer = {MyApp.DevKey, {:issuer, "issuer-key-1"}}
holder = {MyApp.DevKey, {:holder, "holder-key-1"}}
now = System.system_time(:second)
{:ok, holder_thumbprint} = MyApp.DevKey.thumbprint({:holder, "holder-key-1"})

{:ok, %{grant: grant}} =
  BoundedAuthorityReportAdapter.sign_grant(
    %{
      issuer: "https://issuer.example",
      grant_id: "urn:example:grant:rooms-1",
      audiences: ["https://calendar.example"],
      issued_at: now,
      not_before: now,
      expires_at: now + 3600,
      holder_thumbprint: holder_thumbprint,
      operations: [%V1.Operation{name: "book_room", selectors: [:all]}]
    },
    issuer
  )
```

A handle that declares `:holder` cannot sign a grant:

```elixir
BoundedAuthorityReportAdapter.sign_grant(%{}, holder)
#=> {:error, :invalid_key_handle}
```

## 3. The holder signs a proof

`cast_arguments` is the request body in the protocol's tagged form. Decode it from the raw
bytes you send, with `BoundedAuthorityProtocol.V1.Json.decode/2`; the verifier decodes the
same raw bytes it receives, so both sides agree by construction.

```elixir
raw_body = ~s({"room":"harbor-3","start":"2026-11-02T09:00:00Z","minutes":45})
{:ok, cast_arguments} = V1.Json.decode(raw_body)

report = %{
  grant_compact: grant,
  operation: "book_room",
  method: "POST",
  target_uri: "https://calendar.example/bookings",
  invocation_id: "2f6c9d1a-3b4e-4f5a-8b6c-7d8e9f0a1b2c",
  cast_arguments: cast_arguments,
  nonce: "nonce-booking-1"
}

{:ok, %{grant: grant, proof: proof}} = BoundedAuthorityReportAdapter.sign_report(report, holder)
```

The grant comes back unchanged; the proof is new. The adapter verified the proof's
signature against the holder's public key before returning it, so a handle that signs
with a different key than it reports gets `{:error, :signing_failed}`, never a bad proof.

## 4. The verifier checks the envelope

The verifier depends only on the protocol package. It rebuilds the request it expects and
checks the grant and proof together against the issuer's public key.

```elixir
{:ok, issuer_public_key} = MyApp.DevKey.public_key({:issuer, "issuer-key-1"})

expected = %V1.ExpectedRequest{
  trusted_issuer: %V1.TrustedIssuer{key_id: "issuer-key-1", public_key: issuer_public_key},
  issuer: "https://issuer.example",
  audience: "https://calendar.example",
  method: "POST",
  target_uri: "https://calendar.example/bookings",
  invocation_id: report.invocation_id,
  operation: "book_room",
  cast_arguments: cast_arguments,
  evaluation_time: now,
  clock_skew: 60,
  proof_max_age: 300,
  nonce: {:required, "nonce-booking-1"},
  bounds: V1.Bounds.maximum()
}

{:ok, facts} = V1.check_envelope(%V1.Credentials{grant: grant, proof: proof}, expected)
facts.operation
#=> "book_room"
```

Any difference between the request and what the verifier expects is a rejection:

```elixir
credentials = %V1.Credentials{grant: grant, proof: proof}
V1.check_envelope(credentials, %{expected | nonce: {:required, "nonce-booking-2"}})
#=> {:error, :invalid}
```

A verifier's `{:error, :invalid}` does not say which check failed. The adapter checked
only the proof it signed and passed the grant through untouched, so look at both: an
expected-request field that differs (times, nonce, audience, body, invocation id), or the
grant itself (issuer key, validity window, holder thumbprint). The adapter's own errors
are a different set; [Errors](errors.md) lists them.

## The invocation id

`invocation_id` is yours to supply, and the protocol requires a canonical lowercase,
dashed UUID with valid version and variant digits. Two consequences:

- A malformed id (uppercase, no dashes, wrong version digit) signs nothing:
  `sign_report/3` returns `{:error, {:producer_error, :invalid}}`. Generate ids with
  `Ecto.UUID.generate/0` or another UUID v4 generator.
- The proof binds it. The same grant and key with a different invocation id is a
  different request, so a signed envelope cannot be reused for a retry under a new id.

## The path to a production handle

Replace `MyApp.DevKey` with a module whose `sign/2` calls your HSM or KMS and whose
`key_identity/1` and `signing_identity/1` return your key registry's real key id. The
adapter's contract does not change. Two rules:

- `public_key/1` and the identity callbacks must describe the same key `sign/2` uses. The
  adapter verifies every signature against the resolved public key, and a mismatch is
  `:signing_failed`.
- Never pass key bytes to the adapter. If your integration does, it is wrong
  ([Usage rules](../usage-rules.md), rule 2).

For grants, `signing_identity/1` must return `{:issuer, key_id, public_key}`. The adapter
rejects any other declared role, but it cannot check that the declaration is true; keep
issuer keys in issuer custody, or require a role attestation
([Usage rules](../usage-rules.md), rule 3).

Check a handle module against the contract before you use it:

```sh
mix bounded_authority_report_adapter.doctor --handle MyApp.DevKey --ref '{:holder, "holder-key-1"}' --live
```

For an ES256 (P-256) handle, see `BoundedAuthorityReportAdapter.V3` and the P-256 notes in
[Recipes](recipes.md).

## Where to next

- [Usage rules](../usage-rules.md): the integration contract as a checklist.
- [Errors](errors.md): every error, what it means, what to check.
- [Recipes](recipes.md): HSM and KMS handles, a Plug consumer, the loopback listener.
- [Telemetry](telemetry.md): the value-free signing events and the custody alarm.
- [Consumer integration](consumer-integration.md): the verifier side, including identity
  binding and the nonce ledger.
- The repository's [edge-agent example app](https://github.com/baselabs/bounded_authority_report_adapter/tree/master/examples/edge_agent)
  runs sign, POST and verify over HTTP, and its
  [Livebook](https://github.com/baselabs/bounded_authority_report_adapter/blob/master/examples/report_envelope_roundtrip.livemd)
  runs every signing entry point.
