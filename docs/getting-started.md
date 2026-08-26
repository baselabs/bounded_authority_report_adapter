# Getting started

`bounded_authority_report_adapter` targets Elixir `~> 1.18` (tested on 1.20 / OTP 29, CI
runs 1.18/27, 1.19/28, 1.20/29). The package is published on
[Hex](https://hex.pm/packages/bounded_authority_report_adapter).

```elixir
{:bounded_authority_report_adapter, "~> 1.0"}
```

Or scaffold the starter key-handle with [Igniter](https://hexdocs.pm/igniter)
(add `{:igniter, "~> 0.8"}` to your dev deps first):

```sh
mix bounded_authority_report_adapter.install --module MyApp.HolderKey
```

The scaffold compiles clean and raises on every callback until you wire your
custody store — it signs nothing by accident.

## The shape of the thing

This library is a HOLDER-side signer. It never sees your private key: you hand it a
`{module, term}` key handle whose module implements the `BoundedAuthorityReportAdapter`
behaviour, and it signs protocol objects (holder proofs, boundary anchors, grants, key
transitions) through that handle. Verification is the protocol package's job
(`BoundedAuthorityProtocol.V1.check_envelope/2` and friends) — this adapter never
verifies.

## Your first sign, in minutes

A development handle is ~25 lines: a seeded Ed25519 pair behind the five callbacks. (The
source repository carries a reference implementation under `test/support/` — it is
TEST-ONLY and deliberately NOT shipped in the package; in production the handle fronts
an HSM, OS keychain, or key server.)

```elixir
defmodule MyApp.DevHandle do
  @behaviour BoundedAuthorityReportAdapter

  @seed <<2::256>>  # DEV ONLY — never a real key
  defp keypair, do: :crypto.generate_key(:eddsa, :ed25519, @seed)

  @impl true
  def sign(message, _handle) when is_binary(message) do
    {_pub, priv} = keypair()
    {:ok, :crypto.sign(:eddsa, :none, message, [priv, :ed25519])}
  end

  def sign(_message, _handle), do: {:error, :invalid_handle}

  @impl true
  def public_key(_handle), do: {:ok, elem(keypair(), 0)}

  @impl true
  def thumbprint(_handle) do
    {:ok, raw} =
      BoundedAuthorityProtocol.V1.Jwk.public_key_thumbprint_raw(elem(keypair(), 0), %{})

    {:ok, raw}
  end

  @impl true
  def key_identity(_handle), do: {:ok, {"my-dev-key-001", elem(keypair(), 0)}}

  @impl true
  def signing_identity(_handle), do: {:ok, {:holder, "my-dev-key-001", elem(keypair(), 0)}}
end
```

Sign a report against an issuer-signed grant (the grant arrives out-of-band from your
issuer — mint one for the dev loop the way the
[example app](https://github.com/baselabs/bounded_authority_report_adapter/tree/master/examples/edge_agent)
does):

```elixir
# cast_arguments MUST be BAP's tagged form — decode the SAME raw bytes both sides use:
{:ok, cast_arguments} = BoundedAuthorityProtocol.V1.Json.decode(raw_report_body, %{})

report = %{
  grant_compact: issuer_signed_grant_compact,   # binds YOUR thumbprint via cnf.jkt
  operation: "report_external_materialization",
  method: "POST",
  target_uri: "https://api.example.test/invoke",
  invocation_id: "123e4567-e89b-42d3-a456-426614174000",
  cast_arguments: cast_arguments,
  nonce: "challenge-001"
}

{:ok, %{grant: grant, proof: proof}} =
  BoundedAuthorityReportAdapter.sign_report(report, {MyApp.DevHandle, :dev}, %{})

# Verify through the protocol's own verifier (the CONSUMER's side of the contract):
alias BoundedAuthorityProtocol.V1

{:ok, _facts} =
  V1.check_envelope(
    %V1.Credentials{grant: grant, proof: proof},
    %V1.ExpectedRequest{
      trusted_issuer: %V1.TrustedIssuer{key_id: issuer_kid, public_key: issuer_pub},
      issuer: "https://issuer.example.test",
      audience: "https://verifier.example.test",
      method: "POST",
      target_uri: "https://api.example.test/invoke",
      invocation_id: report.invocation_id,
      operation: report.operation,
      cast_arguments: cast_arguments,
      evaluation_time: System.system_time(:second),
      clock_skew: 60,
      proof_max_age: 300,
      nonce: {:required, "challenge-001"},
      bounds: V1.Bounds.maximum()
    }
  )
```

If that comes back `{:ok, _}`, you have signed a proof the protocol's verifier accepts.
If it comes back `{:error, :invalid}`: the adapter verified only the PROOF it just
signed and passed your grant through untouched, so a rejection can be an
expected-request field mismatch (times, nonce, audience, arguments) OR the verifier
rejecting the GRANT itself (issuer signature, window, thumbprint binding). The
adapter-side signing errors are a different surface — [Errors](errors.md) covers those.

## The invocation-id trap (read this before your first 401)

`invocation_id` is caller-supplied and gated by the protocol's UUID grammar
(`valid_uuid?` — canonical dashed lowercase hex, version + variant nibbles). Two
consequences that bite in practice:

- A malformed id (uppercase, undashed, wrong version nibbles) is rejected far
  from the cause — your proof verifies fine byte-wise, but the verifier's
  expected-request comparison fails as a bare `{:error, :invalid}`. Use
  `Ecto.UUID.generate/0`, a UUIDv4 library, or the shape in the examples.
- It is part of what the proof BINDS: the verifier reconstructs it from the
  request line. Same grant, same key, different invocation id = rejected. That
  is the point (per-invocation binding); it just means you cannot reuse a
  signed envelope for a retried request with a fresh id.

## The path to a production handle

Swap `MyApp.DevHandle` for one whose `sign/2` calls your HSM/KMS and whose
`key_identity/1`/`signing_identity/1` return the registry's real `key_id` — the adapter's
contract is identical. Two non-negotiables:

- `public_key/1` (and the identity callbacks) must describe the SAME key `sign/2` uses —
  the adapter verifies every signature against the resolved public key and a mismatch is
  `:signing_failed` (the wrong-key guard).
- The private key never enters the library. If an integration passes key bytes to the
  adapter, it is wrong ([Usage rules](../usage-rules.md) #2).

For grants, the handle must resolve `{:issuer, _, _}` from `signing_identity/1` — that is
the C1 declaration gate, and it is declaration-rejection, not cryptographic role
separation (Usage rules #3).

## Where to next

- [Usage rules](../usage-rules.md) — the twelve-rule version of everything above.
- [Errors](errors.md) — every closed atom, what it means, what to check.
- [Telemetry](telemetry.md) — the value-free sign events and the custody alarm.
- [Consumer integration](consumer-integration.md) — the verifier side: raw bytes,
  identity binding, the nonce ledger.
- The runnable [edge-agent example app](https://github.com/baselabs/bounded_authority_report_adapter/tree/master/examples/edge_agent)
  — a full sign → POST → verify loop over HTTP.
