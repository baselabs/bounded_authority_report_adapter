# Recipes

Four integration shapes: the local-loopback development listener, a network-HSM key
handle, a KMS key-identity handle and a Plug consumer, plus a note on porting the signing
side to another language. The handle and Plug modules compile as written; the test suite
compiles each one. Each names an integration module that is yours to write (`MyApp.HsmClient`,
`MyApp.KmsClient`, `MyApp.NonceLedger`), so compiling one before you write that module
warns that the module is undefined, and nothing else. The loopback recipe is a fragment:
its variables come from your application.

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

The handle's `sign/2` fronts a network HSM. Two properties matter. The callback must
return `{:ok, binary}` or `{:error, term}`. And a timeout must not crash your caller: the
adapter contains a callback that raises, throws or exits (a `GenServer.call` timeout is an
exit) and returns `:signing_failed` for `sign/2` or `:invalid_key_handle` for the other
callbacks. Still, return errors explicitly whenever you can.

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
         {:ok, jwk} <- BoundedAuthorityProtocol.V1.Jwk.encode_public(public_key, %{}),
         {:ok, thumbprint} <- BoundedAuthorityProtocol.V1.Jwk.thumbprint(jwk, %{}) do
      {:ok, Base.url_decode64!(thumbprint, padding: false)}
    end
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
         {:ok, jwk} <- BoundedAuthorityProtocol.V1.Jwk.encode_public(public_key, %{}),
         {:ok, thumbprint} <- BoundedAuthorityProtocol.V1.Jwk.thumbprint(jwk, %{}) do
      {:ok, Base.url_decode64!(thumbprint, padding: false)}
    end
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
