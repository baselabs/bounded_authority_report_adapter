# Grants, selectors, and issuer roles

Examples continue the [README quick start](../../README.md#quick-start) in the same IEx session.

## Operations and selectors

Requires: nothing beyond this package.

A grant names operations, and each operation can narrow the arguments it allows with
selectors over the request's `cast_arguments`. The issuer signs them;
`BoundedAuthorityProtocol.V1.check_envelope/2` (or `BoundedAuthorityProtocol.V3.check_envelope/2`)
enforces them at the verifier; the holder cannot widen them.

| Selector | Contract-major 1 (`BoundedAuthorityReportAdapter`) | Contract-major 3 (`.V3`) |
|---|---|---|
| `:all`: any arguments | yes | yes |
| `{:equals, path, value}`: the value at `path` equals `value` | yes | yes |
| `{:one_of, path, values}`: it equals one of `values` | yes | yes |
| `{:lte, path, bound}` / `{:gte, path, bound}`: inclusive numeric range | no | yes |

A `path` is a list of object member names; values use the protocol's tagged form
(`{:string, s}`, `{:integer, n}`, `{:float, f}`, `{:boolean, b}`, `{:array, list}`,
`{:object, members}`). Write whole numbers as `{:integer, n}`: with protocol 1.0 the grant
producer refuses a float-tagged whole number such as `{:float, 2.0}` in any selector value
or range bound, and `sign_grant/3` returns `{:error, {:producer_error, :invalid}}`
([errors](errors.md#selector-values-and-erratum-6)).

A contract-major-1 grant for a stock-reservation service: any quantity, but only from the
north warehouse and only in boxes or crates.

```elixir
alias BoundedAuthorityProtocol.V1
alias BoundedAuthorityProtocol.V3

now = System.system_time(:second)
issuer = {MyApp.DevKey, {:issuer, "issuer-key-1"}}
holder = {MyApp.DevKey, {:holder, "holder-key-1"}}
{:ok, holder_thumbprint} = MyApp.DevKey.thumbprint({:holder, "holder-key-1"})
{:ok, issuer_public_key} = MyApp.DevKey.public_key({:issuer, "issuer-key-1"})

reserve_stock = %V1.Operation{
  name: "reserve_stock",
  selectors: [
    {:equals, ["warehouse"], {:string, "north"}},
    {:one_of, ["unit"], [{:string, "box"}, {:string, "crate"}]}
  ]
}

{:ok, %{grant: stock_grant}} =
  BoundedAuthorityReportAdapter.sign_grant(
    %{
      issuer: "https://issuer.example",
      grant_id: "urn:example:grant:stock-1",
      audiences: ["https://inventory.example"],
      issued_at: now,
      not_before: now,
      expires_at: now + 3600,
      holder_thumbprint: holder_thumbprint,
      operations: [reserve_stock]
    },
    issuer
  )

# The holder signs a proof for each request body; the verifier checks it against the grant.
reserve = fn surface, verifier, grant, holder, trusted_issuer, raw_body ->
  {:ok, cast_arguments} = V1.Json.decode(raw_body)
  invocation_id = "4b0a6c2e-1f3d-4e5a-9b7c-8d6e5f4a3b2c"
  nonce = "nonce-#{System.unique_integer([:positive])}"

  {:ok, %{proof: proof}} =
    surface.sign_report(
      %{
        grant_compact: grant,
        operation: "reserve_stock",
        method: "POST",
        target_uri: "https://inventory.example/reservations",
        invocation_id: invocation_id,
        cast_arguments: cast_arguments,
        nonce: nonce
      },
      holder,
      issued_at: now
    )

  verifier.check_envelope(
    %V1.Credentials{grant: grant, proof: proof},
    %V1.ExpectedRequest{
      trusted_issuer: trusted_issuer,
      issuer: "https://issuer.example",
      audience: "https://inventory.example",
      method: "POST",
      target_uri: "https://inventory.example/reservations",
      invocation_id: invocation_id,
      operation: "reserve_stock",
      cast_arguments: cast_arguments,
      evaluation_time: now,
      clock_skew: 60,
      proof_max_age: 300,
      nonce: {:required, nonce},
      bounds: V1.Bounds.maximum()
    }
  )
end

trusted = %V1.TrustedIssuer{key_id: "issuer-key-1", public_key: issuer_public_key}
reserve_v1 = &reserve.(BoundedAuthorityReportAdapter, V1, stock_grant, holder, trusted, &1)

{
  match?({:ok, _facts}, reserve_v1.(~s({"warehouse":"north","unit":"box","quantity":12}))),
  reserve_v1.(~s({"warehouse":"south","unit":"box","quantity":12})),
  reserve_v1.(~s({"warehouse":"north","unit":"pallet","quantity":12}))
}
#=> {true, {:error, :invalid}, {:error, :invalid}}
```

Contract-major 3 adds inclusive ranges. Use the same development-only P-256 handle as
in the V3 API reference to run this example without a remote custodian. It uses real
local cryptography; never use these deterministically derived development keys in
production.

```elixir
defmodule MyApp.DevP256Key do
  @moduledoc "Development only: derives a P-256 key from its name. Never use in production."
  @behaviour BoundedAuthorityReportAdapter

  @impl true
  def sign(message, {_role, name}) do
    der = :crypto.sign(:ecdsa, :sha256, message, [private_key(name), :prime256v1])
    # DER: SEQUENCE { INTEGER r, INTEGER s }. Re-encode as two 32-byte integers.
    <<0x30, _length, 0x02, r_size, r::binary-size(r_size), 0x02, s_size,
      s::binary-size(s_size)>> = der

    {:ok,
     <<:binary.decode_unsigned(r)::unsigned-big-256,
       :binary.decode_unsigned(s)::unsigned-big-256>>}
  end

  @impl true
  def public_key({_role, name}), do: {:ok, public_key_of(name)}

  @impl true
  def thumbprint({_role, name}),
    do: BoundedAuthorityReportAdapter.public_key_thumbprint(public_key_of(name))

  @impl true
  def key_identity({_role, name}), do: {:ok, {name, public_key_of(name)}}

  @impl true
  def signing_identity({role, name}), do: {:ok, {role, name, public_key_of(name)}}

  # A P-256 private key is a scalar in [1, n - 1]; a SHA-256 digest is below n with
  # overwhelming probability, which is good enough for a development handle.
  defp private_key(name), do: :crypto.hash(:sha256, "development only: " <> name)

  defp public_key_of(name) do
    {public_key, _private_key} =
      :crypto.generate_key(:ecdh, :prime256v1, private_key(name))

    public_key
  end
end
```

The same reservation with a P-256 issuer and holder, capped at 1 to 50 units:

```elixir
{:ok, ec_holder_thumbprint} = MyApp.DevP256Key.thumbprint({:holder, "recipe-ec-holder"})
{:ok, {ec_issuer_key_id, ec_issuer_public_key}} = MyApp.DevP256Key.key_identity({:issuer, "recipe-ec-issuer"})

{:ok, %{grant: ec_stock_grant}} =
  BoundedAuthorityReportAdapter.V3.sign_grant(
    %{
      issuer: "https://issuer.example",
      grant_id: "urn:example:grant:stock-2",
      audiences: ["https://inventory.example"],
      issued_at: now,
      not_before: now,
      expires_at: now + 3600,
      holder_thumbprint: ec_holder_thumbprint,
      operations: [
        %V3.Operation{
          name: "reserve_stock",
          selectors: [
            {:equals, ["warehouse"], {:string, "north"}},
            {:gte, ["quantity"], {:integer, 1}},
            {:lte, ["quantity"], {:integer, 50}}
          ]
        }
      ]
    },
    {MyApp.DevP256Key, {:issuer, "recipe-ec-issuer"}}
  )

ec_trusted = %V1.TrustedIssuer{key_id: ec_issuer_key_id, public_key: ec_issuer_public_key}

reserve_v3 =
  &reserve.(
    BoundedAuthorityReportAdapter.V3,
    V3,
    ec_stock_grant,
    {MyApp.DevP256Key, {:holder, "recipe-ec-holder"}},
    ec_trusted,
    &1
  )

{
  match?({:ok, _facts}, reserve_v3.(~s({"warehouse":"north","quantity":50}))),
  reserve_v3.(~s({"warehouse":"north","quantity":51})),
  reserve_v3.(~s({"warehouse":"north","quantity":0}))
}
#=> {true, {:error, :invalid}, {:error, :invalid}}
```

## An attested issuer role

Requires: nothing beyond this package. The attestor is your authority service.

`sign_grant/3` signs only for a handle that declares the `:issuer` role, but a declaration
is the handle's word. With the `:role_attestation` option the role must also be attested,
for the handle's own key, by an attestor key you trust: a `bap-role-attestation/1` compact.
The adapter takes the subject from the handle's `signing_identity/1`, never from the
option, and refuses an option with any key besides `:compact`, `:attestor` and `:now`.

The attestor side, here in process for the example (in production it runs in your
authority service, which holds the attestor key):

```elixir
alias BoundedAuthorityProtocol.RoleAttestation.V1, as: RoleAttestation

attestor = {:attestor, "role-attestor-1"}
{:ok, attestor_public_key} = MyApp.DevKey.public_key(attestor)

{:ok, attestation_input} =
  RoleAttestation.attestation_signing_input(
    %RoleAttestation.RoleAttestation{
      attestor_key_id: "role-attestor-1",
      jti: "urn:example:attestation:issuer-key-1",
      key_id: "issuer-key-1",
      public_key: issuer_public_key,
      role: "issuer",
      nbf: now - 60,
      exp: now + 86_400
    },
    %{}
  )

{:ok, attestation_signature} = MyApp.DevKey.sign(attestation_input.message, attestor)
{:ok, attestation} = RoleAttestation.assemble_compact(attestation_input, attestation_signature)
```

The issuer side: the grant is signed only when the attestation verifies against the
attestor key you trust and names this handle's key as the issuer.

```elixir
trusted_attestor = %V1.HistoricalPublicKey{
  key_id: "role-attestor-1",
  public_key: attestor_public_key,
  valid_from: now - 3600,
  valid_before: :unbounded
}

attested_grant = %{
  issuer: "https://issuer.example",
  grant_id: "urn:example:grant:stock-3",
  audiences: ["https://inventory.example"],
  issued_at: now,
  not_before: now,
  expires_at: now + 3600,
  holder_thumbprint: holder_thumbprint,
  operations: [reserve_stock]
}

role_attestation = [compact: attestation, attestor: trusted_attestor, now: now]

{:ok, %{grant: _grant}} =
  BoundedAuthorityReportAdapter.sign_grant(attested_grant, issuer,
    role_attestation: role_attestation
  )

{
  # Another issuer key, which the attestation does not name.
  BoundedAuthorityReportAdapter.sign_grant(
    attested_grant,
    {MyApp.DevKey, {:issuer, "issuer-key-2"}},
    role_attestation: role_attestation
  ),
  # The same attestation checked against a key that did not sign it.
  BoundedAuthorityReportAdapter.sign_grant(attested_grant, issuer,
    role_attestation: [
      compact: attestation,
      attestor: %{trusted_attestor | public_key: issuer_public_key},
      now: now
    ]
  ),
  # A misspelled :now is refused, not replaced by the current time.
  BoundedAuthorityReportAdapter.sign_grant(attested_grant, issuer,
    role_attestation: [compact: attestation, attestor: trusted_attestor, nwo: now]
  )
}
#=> {{:error, :invalid_role_attestation}, {:error, :invalid_role_attestation}, {:error, :invalid_role_attestation}}
```

The role-attestation profile binds Ed25519 keys, so `BoundedAuthorityReportAdapter.V3.sign_grant/3`
refuses the option with `{:error, :invalid_role_attestation}`.
