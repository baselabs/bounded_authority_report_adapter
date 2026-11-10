# Recipes

Integration shapes, each runnable: the local-loopback development listener, a
network-HSM key handle, a KMS key-identity handle, an ES256 handle over a KMS or HSM that
returns DER, grants with selectors on both contract-majors, an attested issuer role, key
rotation, error handling with telemetry alerts, and a Plug consumer, plus a note on
porting the signing side to another language. Each recipe module names an integration
module that is yours to write (`MyApp.HsmClient`, `MyApp.KmsClient`,
`MyApp.EcKmsClient`, `MyApp.NonceLedger`). The test suite runs every recipe as written:
the HSM and KMS handles against real local Ed25519 and P-256 signers standing in for the
HSM and the KMS (the P-256 one returns DER, as a KMS does), with each `#=>` value checked;
the example app's tests run the Plug recipe with real `Plug.Conn` requests. The loopback
recipe is a fragment (its variables come from your application); the test suite compiles
it with those variables as stub parameters.

## Recipe: the local-loopback development listener

`sign_local_loopback_report/3` exists for one situation: a development
listener that is *on the literal loopback interface* and cannot do TLS. It
produces the byte-distinct `ba+loopback-proof` profile
(`bap-application-proof/local-loopback-http/1`); the standard
`dpop+jwt` verifier rejects those bytes and the profile verifier rejects
standard bytes, so the two flows can never be confused on the wire.

The two blocks below are fragments: `grant_compact`, `invocation_id`, `cast_arguments`,
the trusted-issuer values and `MyApp.ChallengeLedger` come from your application. The
repository's Livebook runs this flow end to end.

<!-- doc-sample: fragment -->
```elixir
# The holder side — the target is the listener's OWN canonical URL.
report = %{
  grant_compact: grant_compact,          # issuer-signed, passes through untouched
  operation: "run_local_tool",
  method: "POST",
  target_uri: "http://127.0.0.1:4000/invoke",   # or "http://[::1]:4000/invoke"
  invocation_id: invocation_id,           # a fresh UUID v4 per request
  cast_arguments: cast_arguments,         # the protocol's tagged Json.value() form
  nonce: challenge                        # required: the listener's challenge
}

{:ok, %{grant: grant, proof: proof}} =
  BoundedAuthorityReportAdapter.sign_local_loopback_report(
    report, {MyApp.DevKey, {:holder, "holder-key-1"}}, %{}
  )
```

The verifier (the listener's operator) checks it with the profile's envelope
verifier, deriving the expected target from the listener's own bound address —
never from a Host or X-Forwarded-* header:

<!-- doc-sample: fragment -->
```elixir
alias BoundedAuthorityProtocol.ApplicationProfile.LocalLoopbackHttp.V1, as: Loopback
alias BoundedAuthorityProtocol.V1, as: StandardV1

# 1. The LISTENER mints the challenge (single-use, atomically consumed at
#    verify) — the signer never chooses the nonce.
challenge = MyApp.ChallengeLedger.reserve()

# 2. The signer binds it (this is the adapter call above).

# 3. The verifier: the expected target comes from the listener's own bound
#    address — never a Host or X-Forwarded-* header.
:ok = MyApp.ChallengeLedger.consume!(challenge)

{:ok, _facts} =
  Loopback.check_envelope(
    %StandardV1.Credentials{grant: grant, proof: proof},
    %StandardV1.ExpectedRequest{
      trusted_issuer: trusted_issuer,
      issuer: issuer,
      audience: audience,
      method: "POST",
      target_uri: "http://127.0.0.1:4000/invoke",  # listener-derived
      invocation_id: invocation_id,
      operation: "run_local_tool",
      cast_arguments: cast_arguments,
      evaluation_time: System.system_time(:second),
      clock_skew: 60,
      proof_max_age: 300,
      nonce: {:required, challenge},          # mandatory on this profile
      bounds: StandardV1.Bounds.maximum()
    }
  )
```

The rules that bite:

- The nonce is **required** at signing and `{:required, nonce}` at
  verification — and it is the LISTENER's challenge, not the signer's choice:
  the receiver mints it (single-use) and consumes it atomically at
  verification, so a captured request cannot be replayed even once. The
  signer obtains the challenge first (in the example app, with a GET), then signs it in.
- Only **canonical literal-loopback targets** sign. `localhost`, `127.0.0.2`,
  `0x7f.0.0.1`, `2130706433`, `[0:0:0:0:0:0:0:1]`, `[::ffff:127.0.0.1]`,
  uppercase schemes, explicit `:80`, leading-zero ports, dot-segments,
  queries, fragments, and HTTPS all fail closed with
  `{:error, {:producer_error, :invalid}}`. Nothing is rewritten for you.
- Loopback HTTP is **not equivalent to HTTPS** — no confidentiality, no server
  authentication, and not process isolation. Keep it on the literal loopback
  interface and behind an explicit profile decision.

The runnable end-to-end version (sign, POST, verify and replay rejection over real
IPv4 and IPv6 sockets) is the edge-agent example's `EdgeAgent.run_local_loopback` function and
its receiver's `profile: :local_loopback` mode, in the repository's `examples/edge_agent`.


## Recipe: a network-HSM key handle

Requires: nothing beyond this package. The HSM client is injected through configuration;
your client module is the integration point.

The handle's `sign/2` fronts a network HSM. Three properties matter. The callback must
return `{:ok, binary}` or `{:error, term}`. A timeout must not crash your caller: the
adapter contains a callback that raises, throws or exits (a `GenServer.call` timeout is an
exit) and returns `:signing_failed` for `sign/2` or `:invalid_key_handle` for the other
callbacks. And the timeout is yours to set: the adapter runs every callback in the
caller's process with no timeout of its own, so a client call without one blocks the
signing call for as long as the HSM does not answer. Still, return errors explicitly
whenever you can.

**The P-256 variant (the `V3` surface).** The same recipe serves
`BoundedAuthorityReportAdapter.V3` with a P-256-backed handle, with THREE
suite-specific duties: `public_key/1` returns the 65-byte uncompressed-SEC1
point (`0x04 || x || y`); `sign/2` returns the RFC 7518 §3.4 RAW `r || s`
form (exactly 64 bytes) — convert your HSM's DER output first (decode the
SEQUENCE to `(r, s)` and re-encode as two padded big-endian 32-byte
integers); and `thumbprint/1` uses the EC RFC 7638 preimage
(`{"crv":"P-256","kty":"EC","x":X,"y":Y}`). Low-S is the adapter's duty —
it normalizes a high-S return — but a custodian that can emit low-S
directly should. Run `mix bounded_authority_report_adapter.doctor
--handle MyApp.HsmHandle --live` to preflight either surface (`--major 1`
or `--major 3` applies that surface's strict key-type gate).

```elixir
defmodule MyApp.HsmHandle do
  @moduledoc """
  Key handle backed by a network HSM. The handle term is the HSM's key reference
  (never key material). The client module is injected:

      config :my_app, :hsm_client, MyApp.HsmClient  # implements sign_ed25519/2

  A client timeout (a GenServer.call exit) never crashes your caller: the adapter
  contains it. A sign/2 timeout returns :signing_failed; a public_key/1, key_identity/1
  or signing_identity/1 timeout returns :invalid_key_handle.
  """

  @behaviour BoundedAuthorityReportAdapter

  @hsm Application.compile_env(:my_app, :hsm_client, MyApp.HsmClient)

  @impl true
  def sign(message, key_ref) when is_binary(message) do
    case @hsm.sign_ed25519(key_ref, message) do
      {:ok, signature} -> {:ok, signature}
      {:error, reason} -> {:error, reason}
    end
  end

  def sign(_message, _key_ref), do: {:error, :invalid_handle}

  @impl true
  def public_key(key_ref), do: @hsm.public_key(key_ref)

  @impl true
  def thumbprint(key_ref) do
    with {:ok, public_key} <- public_key(key_ref),
         do: BoundedAuthorityReportAdapter.public_key_thumbprint(public_key)
  end

  @impl true
  def key_identity(key_ref), do: @hsm.key_identity(key_ref)

  @impl true
  def signing_identity(key_ref), do: @hsm.signing_identity(key_ref)
end
```

## Recipe: a KMS key-identity handle (why the snapshot is ONE call)

Requires: nothing beyond this package (same config-injection shape as above).

`sign_anchor/3` and `sign_key_transition/3` resolve `key_id` AND `public_key` from ONE
atomic `key_identity/1` call. Against a KMS with key VERSIONS, a handle that resolves the
two in separate calls can straddle a rotation — kid from version N, public key from
version N+1 — and the signed header then names a key it was not signed with. One call,
one version:

```elixir
defmodule MyApp.KmsHandle do
  @moduledoc """
  A KMS-backed handle whose key_identity/1 takes the atomic snapshot.

      config :my_app, :kms_client, MyApp.KmsClient
      # implements current_version/1 returning {:ok, {key_id, public_key}}
      # from ONE versioned API call (or ONE cached snapshot of a version).
  """

  @behaviour BoundedAuthorityReportAdapter

  @kms Application.compile_env(:my_app, :kms_client, MyApp.KmsClient)

  @impl true
  def sign(message, key_ref) when is_binary(message),
    do: @kms.sign_current_version(key_ref, message)

  def sign(_message, _key_ref), do: {:error, :invalid_handle}

  @impl true
  def public_key(key_ref) do
    case key_identity(key_ref) do
      {:ok, {_key_id, public_key}} -> {:ok, public_key}
      error -> error
    end
  end

  @impl true
  def thumbprint(key_ref) do
    with {:ok, {_key_id, public_key}} <- key_identity(key_ref),
         do: BoundedAuthorityReportAdapter.public_key_thumbprint(public_key)
  end

  @impl true
  def key_identity(key_ref) do
    # ONE call. The adapter signs the kid into the header and verifies the
    # signature against this same public key — a split snapshot cannot pass
    # the wrong-key guard silently, but it CAN sign the wrong kid into the
    # header. Do not "helpfully" cache the halves separately.
    @kms.current_version(key_ref)
  end

  @impl true
  def signing_identity(key_ref) do
    with {:ok, {key_id, public_key}} <- key_identity(key_ref) do
      # :issuer only if this KMS key really is the issuer's. The adapter rejects
      # non-issuer declarations; it cannot verify them (docs/security.md).
      {:ok, {:issuer, key_id, public_key}}
    end
  end
end
```

## Recipe: an ES256 handle over a KMS or HSM that returns DER

Requires: nothing beyond this package. The KMS client is injected through configuration.

Cloud KMS ECDSA operations and PKCS#11 HSMs return a P-256 signature DER-encoded
(`SEQUENCE { INTEGER r, INTEGER s }`). The `BoundedAuthorityReportAdapter.V3` entry points
take the raw `r || s` form of RFC 7518 §3.4 and refuse DER with `{:error, :signing_failed}`,
so the handle converts it with the protocol package's `BoundedAuthorityProtocol.Es256`
helpers. `BoundedAuthorityProtocol.Es256.der_to_raw/1` rejects a malformed or non-minimal
DER value with `{:error, :invalid}`. `BoundedAuthorityProtocol.Es256.normalize_low_s/1` is
optional, because the adapter normalizes a
high-S signature itself, but with it the signature your device logged equals the one in the
compact.

```elixir
defmodule MyApp.EcKmsHandle do
  @moduledoc """
  A contract-major-3 key handle over a KMS whose ECDSA operation returns DER. The handle
  term is the KMS key reference. The client is injected:

      config :my_app, :ec_kms_client, MyApp.EcKmsClient
      # implements current_version/1 -> {:ok, {key_id, public_key}} (one versioned call),
      # sign_es256/2 -> {:ok, der_signature}, and role/1 -> :issuer | :holder.
  """

  @behaviour BoundedAuthorityReportAdapter

  @kms Application.compile_env(:my_app, :ec_kms_client, MyApp.EcKmsClient)

  @impl true
  def sign(message, key_ref) do
    with {:ok, der} <- @kms.sign_es256(key_ref, message),
         {:ok, raw} <- BoundedAuthorityProtocol.Es256.der_to_raw(der),
         do: BoundedAuthorityProtocol.Es256.normalize_low_s(raw)
  end

  @impl true
  def public_key(key_ref) do
    with {:ok, {_key_id, public_key}} <- key_identity(key_ref), do: {:ok, public_key}
  end

  @impl true
  def thumbprint(key_ref) do
    with {:ok, public_key} <- public_key(key_ref),
         do: BoundedAuthorityReportAdapter.public_key_thumbprint(public_key)
  end

  # The 65-byte uncompressed point (0x04 || x || y). A KMS that returns the public key as
  # DER SubjectPublicKeyInfo needs its last 65 bytes.
  @impl true
  def key_identity(key_ref), do: @kms.current_version(key_ref)

  @impl true
  def signing_identity(key_ref) do
    with {:ok, {key_id, public_key}} <- key_identity(key_ref),
         do: {:ok, {@kms.role(key_ref), key_id, public_key}}
  end
end
```

The same shape serves the major-1 surface with an Ed25519 key: there the KMS returns the
64-byte signature directly and no conversion is needed. Preflight a handle with
`mix bounded_authority_report_adapter.doctor --handle MyApp.EcKmsHandle --ref :issuer --live --major 3`.

## Recipe: grants with selectors

Requires: nothing beyond this package.

A grant names operations, and each operation can narrow the arguments it allows with
selectors over the request's `cast_arguments`. The issuer signs them;
`BoundedAuthorityProtocol.V1.check_envelope/2` (or `BoundedAuthorityProtocol.V3.check_envelope/2`)
enforces them at the verifier; the holder cannot widen them.

| Selector | Contract-major 1 (`BoundedAuthorityReportAdapter`) | Contract-major 3 (`.V3`) |
|---|---|---|
| `:all` — any arguments | yes | yes |
| `{:equals, path, value}` — the value at `path` equals `value` | yes | yes |
| `{:one_of, path, values}` — it equals one of `values` | yes | yes |
| `{:lte, path, bound}` / `{:gte, path, bound}` — inclusive numeric range | no | yes |

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

Contract-major 3 adds inclusive ranges. The same reservation with a P-256 issuer and holder
(the KMS handle from the previous recipe), now also capped at 1 to 50 units:

```elixir
{:ok, ec_holder_thumbprint} = MyApp.EcKmsHandle.thumbprint(:field_agent)
{:ok, {ec_issuer_key_id, ec_issuer_public_key}} = MyApp.EcKmsHandle.key_identity(:issuer)

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
    {MyApp.EcKmsHandle, :issuer}
  )

ec_trusted = %V1.TrustedIssuer{key_id: ec_issuer_key_id, public_key: ec_issuer_public_key}

reserve_v3 =
  &reserve.(
    BoundedAuthorityReportAdapter.V3,
    V3,
    ec_stock_grant,
    {MyApp.EcKmsHandle, :field_agent},
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

## Recipe: an attested issuer role

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

## Recipe: rotating a key with `sign_key_transition/3`

Requires: nothing beyond this package.

A key transition is the retiring key's signed statement that names its successor. Sign it
with the retiring key's handle before you switch; a verifier that trusts the retiring key
then learns the next one from the transition, through
`BoundedAuthorityProtocol.V1.verify_key_transition/4`, instead of from a side channel.
Both key ids come from the handles' `key_identity/1`, so the statement names exactly the
keys in your key store.

```elixir
retiring = {MyApp.DevKey, {:holder, "audit-chain-key-1"}}
{:ok, {retiring_key_id, retiring_public_key}} = MyApp.DevKey.key_identity(elem(retiring, 1))

{:ok, {next_key_id, next_public_key}} =
  MyApp.DevKey.key_identity({:holder, "audit-chain-key-2"})

transition = %{
  transition_id: "urn:example:transition:audit-chain-2",
  chain_id: "urn:example:chain:audit",
  effective_at: now,
  next_key_id: next_key_id,
  next_public_key: next_public_key
}

{:ok, %{key_transition: transition_compact}} =
  BoundedAuthorityReportAdapter.sign_key_transition(transition, retiring)

# The verifier's view: both keys with their validity windows, and what it expects.
historical = fn key_id, public_key ->
  %V1.HistoricalPublicKey{
    key_id: key_id,
    public_key: public_key,
    valid_from: now - 3600,
    valid_before: :unbounded
  }
end

fingerprint = fn public_key ->
  {:ok, thumbprint} = BoundedAuthorityReportAdapter.public_key_thumbprint(public_key)
  thumbprint
end

{:ok, transition_facts} =
  V1.verify_key_transition(
    transition_compact,
    historical.(retiring_key_id, retiring_public_key),
    historical.(next_key_id, next_public_key),
    %V1.ExpectedKeyTransition{
      transition_id: transition.transition_id,
      chain_id: transition.chain_id,
      effective_at: now,
      current_key_id: retiring_key_id,
      current_key_fingerprint: fingerprint.(retiring_public_key),
      next_key_id: next_key_id,
      next_key_fingerprint: fingerprint.(next_public_key),
      bounds: V1.Bounds.maximum()
    }
  )

transition_facts.verification
#=> :authenticated_transition
```

After the switch, the retiring key signs nothing more: retire it in your key store, and keep
its public key and validity window where verifiers of older objects can find it. The
`V3` surface has the same `sign_key_transition/3` for P-256 keys.

## Recipe: error handling, with telemetry for alerts

Requires: `:telemetry`, which this package already depends on.

Two channels, two jobs. A signing call's return value drives control flow: every error is
a closed atom, so a `case` can decide what to do. Telemetry drives alerts: the `:stop`
event's `result_class` lets one handler watch every signing call for the custody alarm,
`:signing_failed`, without wrapping each call site. The event carries no values, so
it never says which key or request failed; the caller still has the return value.

```elixir
defmodule MyApp.Signing do
  @doc "Signs a holder proof and maps each closed error to what the caller does next."
  def sign_report(report, handle) do
    case BoundedAuthorityReportAdapter.sign_report(report, handle) do
      {:ok, envelope} -> {:ok, envelope}
      # The request was wrong: report it to whoever built it. Retrying cannot help.
      {:error, :invalid_report} -> {:error, :bad_request}
      {:error, {:producer_error, :invalid}} -> {:error, :bad_request}
      # Custody is wrong or down: fail this call; the telemetry handler raises the alarm.
      {:error, :invalid_key_handle} -> {:error, :signing_unavailable}
      {:error, :signing_failed} -> {:error, :signing_unavailable}
    end
  end
end

defmodule MyApp.CustodyAlarm do
  @event [:bounded_authority_report_adapter, :sign, :stop]

  def attach(notify) do
    :telemetry.attach("my-app-custody-alarm", @event, &__MODULE__.handle_event/4, notify)
  end

  # Total by construction: it matches the alarm and ignores every other class, including
  # classes a later minor release may add.
  def handle_event(_event, _measurements, %{result_class: :signing_failed} = metadata, notify) do
    send(notify, {:custody_alarm, metadata.object})
  end

  def handle_event(_event, _measurements, _metadata, _notify), do: :ok
end

# A misconfigured handle: it reports one key and signs with another.
defmodule MyApp.SwappedKey do
  @behaviour BoundedAuthorityReportAdapter

  @impl true
  def sign(message, name), do: MyApp.DevKey.sign(message, {:holder, name <> "-old"})

  @impl true
  def public_key(name), do: MyApp.DevKey.public_key({:holder, name})

  @impl true
  def thumbprint(name), do: MyApp.DevKey.thumbprint({:holder, name})
end

:ok = MyApp.CustodyAlarm.attach(self())

{:ok, cast_arguments} = V1.Json.decode(~s({"warehouse":"north","unit":"box","quantity":3}))

report = %{
  grant_compact: stock_grant,
  operation: "reserve_stock",
  method: "POST",
  target_uri: "https://inventory.example/reservations",
  invocation_id: "9e8d7c6b-5a4f-4e3d-8c2b-1a0f9e8d7c6b",
  cast_arguments: cast_arguments,
  nonce: "nonce-alarm-1"
}

results = {
  MyApp.Signing.sign_report(report, {MyApp.SwappedKey, "holder-key-1"}),
  MyApp.Signing.sign_report(%{report | invocation_id: "not-a-uuid"}, holder),
  receive do
    {:custody_alarm, object} -> {:alarm, object}
  after
    0 -> :no_alarm
  end
}

:telemetry.detach("my-app-custody-alarm")
results
#=> {{:error, :signing_unavailable}, {:error, :bad_request}, {:alarm, :report}}
```

Keep handlers total and cheap: `:telemetry` detaches a handler that raises, after which the
alarm stops firing ([telemetry](telemetry.md#if-your-handler-raises)).

## Recipe: a Plug consumer

Requires: `plug`, which this package does not pull in. This is the request side in front of
`MyApp.EnvelopeVerifier` from [consumer integration](consumer-integration.md) §4: it
keeps the raw body, collects the envelope headers, looks up the authenticated identity's
key, and spends the nonce only after the envelope verified. `MyApp.NonceLedger` (§9) is
yours to write; the identity key comes from your authentication plug, which runs first.

```elixir
defmodule MyApp.ReportPlug do
  @behaviour Plug

  @headers ["x-ba-grant", "x-ba-proof", "x-ba-invocation-id", "x-ba-nonce"]

  @impl true
  def init(config), do: config

  @impl true
  def call(conn, config) do
    # Keep the raw body bytes: both sides decode cast_arguments from the same bytes,
    # and a parser in front of this plug would have consumed them.
    with {:ok, raw_body, conn} <- Plug.Conn.read_body(conn),
         {:ok, identity_public_key} <- Map.fetch(conn.assigns, :identity_public_key),
         headers = Map.new(@headers, &{&1, header(conn, &1)}),
         {:ok, _facts} <-
           MyApp.EnvelopeVerifier.verify(raw_body, headers, identity_public_key, config),
         # Spend the nonce the proof bound, keyed by identity (consumer integration §9).
         :ok <- MyApp.NonceLedger.spend(identity_public_key, headers["x-ba-nonce"]) do
      Plug.Conn.send_resp(conn, 200, "accepted")
    else
      # One uniform rejection, whatever failed (consumer integration §5).
      _any_failure -> Plug.Conn.send_resp(conn, 401, "invalid")
    end
  end

  # A missing header becomes nil, which the verifier's `with` rejects.
  defp header(conn, name) do
    case Plug.Conn.get_req_header(conn, name) do
      [value] -> value
      _missing_or_repeated -> nil
    end
  end
end
```

## Porting the signing side (beyond Elixir)

The adapter is a convenience, not a protocol requirement. What a holder in another language
must implement is defined by the Bounded Authority Protocol specification, in its sections
on signing inputs and compact serialization:

1. Produce the object's **signing input** as the specification defines it: the
   deterministic `protected.payload` bytes for each object kind (proof, grant, boundary
   anchor, key transition, content assertion).
2. **Sign those exact bytes** with the suite's algorithm: Ed25519 for contract-major 1,
   ES256 with a raw low-S `r || s` signature for contract-major 3. The key stays in your
   custody stack.
3. **Assemble the compact** as the specification defines it (unpadded base64url segments).
4. **Check yourself against the published conformance corpus.** The protocol package ships
   it under `priv/conformance`, and its vectors decide whether your port produces bytes
   the verifier accepts.

Do not port the key-handle indirection; it is an Elixir convenience. A port signs through
its own custody stack directly, but should keep the adapter's two checks: the signed key id
and public key come from one snapshot, and every signature is verified against the public
key before it is returned. Without them you inherit the failure modes
[security.md](security.md) names.
