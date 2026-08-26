# Recipes

Four integration shapes: a network-HSM key handle, a KMS key-identity handle, a Plug
consumer, and a porting note for non-Elixir holders. Runnable shapes, not a runnable app —
each code block compiles as written against this package + the named dependencies. The
HSM/KMS recipes reference your client module via config; compiling them as-is emits
undefined-integration warnings naming exactly those modules — that is the paste-verify
passing (the marked integration points are yours to fill).

## Recipe: a network-HSM key handle

Requires: nothing beyond this package (the HSM client is injected via config — your client
module is the integration point).

The handle's `sign/2` fronts a network HSM. The two properties that matter: the callback
must return the closed `{:ok, binary} | {:error, term}` contract, and a TIMEOUT (a
`GenServer.call` exit) must not escape — the adapter's `safe_callback` catch-all maps an
exited callback to `:invalid_key_handle` / `:signing_failed` rather than crashing your
caller, so return errors explicitly whenever you can.

```elixir
defmodule MyApp.HsmHandle do
  @moduledoc """
  Key handle backed by a network HSM. The handle term is the HSM's key reference
  (never key material). The client module is injected:

      config :my_app, :hsm_client, MyApp.HsmClient  # implements sign_ed25519/2

  A client timeout (a GenServer.call exit) never crashes your caller — the adapter's
  safe_callback exit-catch contains it. WHERE it surfaces depends on the callback: a
  sign/2 timeout maps to :signing_failed; a public_key/key_identity/signing_identity
  timeout maps to :invalid_key_handle.
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
    with {:ok, public_key} <- public_key(key_ref) do
      BoundedAuthorityProtocol.V1.Jwk.public_key_thumbprint_raw(public_key, %{})
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
    with {:ok, {_key_id, public_key}} <- key_identity(key_ref) do
      BoundedAuthorityProtocol.V1.Jwk.public_key_thumbprint_raw(public_key, %{})
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
      # :issuer only if this KMS key REALLY is the issuer's — see the C1 note
      # in docs/security.md: the gate rejects non-issuer declarations, it does
      # not verify them.
      {:ok, {:issuer, key_id, public_key}}
    end
  end
end
```

## Recipe: a Plug consumer (condensed)

Requires: `plug` (named, not pulled by this package). The canonical long form lives in
[consumer integration](consumer-integration.md); this is the condensed request-side shape
— raw-body retention, the envelope headers, and the verify `with`:

```elixir
defmodule MyApp.ReportPlug do
  @behaviour Plug

  alias BoundedAuthorityProtocol.V1

  @impl true
  def init(opts), do: opts

  @impl true
  def call(conn, _opts) do
    # Retain the RAW body bytes: cast_arguments must come from
    # V1.Json.decode of the SAME bytes on both sides — parsing loses them.
    case read_body(conn) do
      {:ok, raw_body, conn} ->
        with {:ok, grant} <- header(conn, "x-ba-grant"),
             {:ok, proof} <- header(conn, "x-ba-proof"),
             {:ok, nonce} <- header(conn, "x-ba-nonce"),
             {:ok, cast_arguments} <- V1.Json.decode(raw_body, %{}),
             {:ok, facts} <-
               V1.check_envelope(
                 %V1.Credentials{grant: grant, proof: proof},
                 expected_request(conn, cast_arguments, nonce)
               ),
             :ok <- bind_identity(conn, facts),
             # The ledger spends the HEADER nonce (the value the proof bound) —
             # the facts struct carries no nonce field of its own.
             :ok <- MyApp.NonceLedger.spend(nonce) do
          send_resp(conn, 200, "accepted")
        else
          _ -> send_resp(conn, 401, "invalid")
        end

      _ ->
        send_resp(conn, 400, "bad body")
    end
  end

  # Your consumer obligations — consumer-integration.md §8/§9 are canonical.
  # BOTH stubs raise until filled: an integrator who skips identity binding must
  # crash in dev, not silently accept — a fail-open stub here IS the
  # cross-identity-replay misuse security.md names.
  defp bind_identity(_conn, _facts),
    do: raise("bind the verified holder to the authenticated reporter — consumer-integration §8")

  defp expected_request(_conn, _cast_arguments, _nonce),
    do: raise("build your ExpectedRequest — consumer-integration §4")

  defp read_body(conn) do
    case Plug.Conn.read_body(conn) do
      {:ok, body, conn} -> {:ok, body, conn}
      {:more, _partial, conn} -> {:error, :too_large, conn}
      {:error, _} = err -> err
    end
  end

  defp header(conn, name) do
    case Plug.Conn.get_req_header(conn, name) do
      [value] -> {:ok, value}
      _ -> {:error, :missing_header}
    end
  end

  defp send_resp(conn, status, body), do: Plug.Conn.send_resp(conn, status, body)
end
```

## Porting the signing side (beyond Elixir)

The adapter is a convenience, not a protocol requirement. What a non-Elixir holder
implements is normative in the protocol package's own spec — the "V1 signing inputs" and
"compact serialization" sections of the Bounded Authority Protocol specification (the
durable document identity; the protocol repo is its home), not any particular repo path:

1. Produce the object's **signing input** per the spec (the deterministic
   `protected.payload` bytes the protocol defines per object kind — proof, grant,
   boundary anchor, key transition).
2. **Ed25519-sign** those exact bytes with the holder's private key (the key stays in
   your custody stack; nothing about the port changes that).
3. **Assemble the compact** per the spec (unpadded base64url segments, the codec's
   field order).
4. Check yourself against the **published conformance corpus** — the protocol package
   ships it (`priv/conformance`), and its vectors are the oracle for whether your port
   produces bytes the verifier accepts. A port that round-trips the corpus is a port
   that verifies; anything less is a guess.

The one thing NOT to port: the key-handle indirection is an Elixir-library convenience.
A port signs with its own custody stack directly — but keep the adapter's invariant
(signed kid/key consistency and wrong-key rejection) or you inherit the failure modes
[security.md](security.md) names.
