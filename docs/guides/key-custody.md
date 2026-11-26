# Key custody and signature suites

A handle is `{module, opaque_reference}`. Keep private key bytes behind the callbacks,
never in the reference. The adapter passes the reference through without inspecting it;
this is an integrator obligation, not a memory isolation guarantee. Callback code runs in
the caller process. Bound every remote request, cancellation and retry in the handle.

`key_identity/1` returns key id and public key from one immutable key version;
`signing_identity/1` also returns its declared role. `sign/2` must use that same version.
Do not resolve a moving alias separately for identity and signing. A mismatched signature
fails the adapter's public-key self-check as `:signing_failed`.
`key_snapshot/1` captures the key ID and public key along with an opaque, immutable
provider reference for ES256 content assertions and action approvals. Resolve an alias
to its version before returning that reference. When the provider hashes internally,
pass the exact JWS input to its ES256 mechanism. When it requires a prehash, hash that
input with SHA-256 once and sign the digest. Return raw 64-byte `r || s`.


## Signature suites

The main module uses Ed25519: 32-byte public keys and 64-byte signatures over the exact
message. `BoundedAuthorityReportAdapter.V3` uses ES256: on-curve 65-byte uncompressed
P-256 points and raw 64-byte `r || s` signatures over SHA-256. Convert a custody provider's
DER with the protocol's documented `Es256.der_to_raw/1`; never pass DER to the adapter.
The adapter normalizes valid high-S returns to low-S. It does not translate between suites.

## Execute a custody handle

Run the [README quick start](../../README.md#quick-start) first. This local custody process
generates real Ed25519 and P-256 keys and implements both handles. It is a development
example of the callback contract, not an HSM security claim. The handle contains only
public metadata and opaque process/key references.

```elixir
defmodule Demo.Custody do
  use GenServer

  def start_link, do: GenServer.start_link(__MODULE__, %{})
  def new(pid, suite, key_id, role), do: GenServer.call(pid, {:new, suite, key_id, role})
  def sign(key, message), do: GenServer.call(key.custody, {:sign, key.reference, message}, 5_000)

  @impl true
  def init(keys), do: {:ok, keys}

  @impl true
  def handle_call({:new, suite, key_id, role}, _from, keys) do
    {public, private} =
      case suite do
        :ed25519 -> :crypto.generate_key(:eddsa, :ed25519)
        :p256 -> :crypto.generate_key(:ecdh, :prime256v1)
      end

    reference = make_ref()
    key = %{custody: self(), reference: reference, key_id: key_id, role: role, public: public}
    {:reply, key, Map.put(keys, reference, {suite, private})}
  end

  def handle_call({:sign, reference, message}, _from, keys) do
    signature =
      case Map.fetch!(keys, reference) do
        {:ed25519, private} -> :crypto.sign(:eddsa, :none, message, [private, :ed25519])
        {:p256, private} -> :crypto.sign(:ecdsa, :sha256, message, [private, :prime256v1])
      end

    {:reply, {:ok, signature}, keys}
  end
end

defmodule Demo.Ed25519Handle do
  @behaviour BoundedAuthorityReportAdapter

  @impl true
  def sign(message, key), do: Demo.Custody.sign(key, message)

  @impl true
  def public_key(key), do: {:ok, key.public}

  @impl true
  def thumbprint(key), do: BoundedAuthorityReportAdapter.public_key_thumbprint(key.public)

  @impl true
  def key_identity(key), do: {:ok, {key.key_id, key.public}}

  @impl true
  def key_snapshot(key) do
    {:ok, {key.key_id, key.public, Map.take(key, [:custody, :reference])}}
  end

  @impl true
  def signing_identity(key), do: {:ok, {key.role, key.key_id, key.public}}
end

defmodule Demo.P256Handle do
  @behaviour BoundedAuthorityReportAdapter

  @n 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

  @impl true
  def sign(message, key) do
    with {:ok, der} <- Demo.Custody.sign(key, message),
         {:ok, <<r::unsigned-big-256, s::unsigned-big-256>>} <-
           BoundedAuthorityProtocol.Es256.der_to_raw(der) do
      # Exercise the adapter's normalization with a valid high-S signature.
      high_s = if s > div(@n, 2), do: s, else: @n - s
      {:ok, <<r::unsigned-big-256, high_s::unsigned-big-256>>}
    end
  end

  @impl true
  def public_key(key), do: {:ok, key.public}

  @impl true
  def thumbprint(key), do: BoundedAuthorityReportAdapter.public_key_thumbprint(key.public)

  @impl true
  def key_identity(key), do: {:ok, {key.key_id, key.public}}

  @impl true
  def key_snapshot(key) do
    {:ok, {key.key_id, key.public, Map.take(key, [:custody, :reference])}}
  end

  @impl true
  def signing_identity(key), do: {:ok, {key.role, key.key_id, key.public}}
end

{:ok, custody} = Demo.Custody.start_link()
[Demo.Custody, Demo.Ed25519Handle, Demo.P256Handle]
```

Sign with the process, check the result and refuse a mismatched key:

```elixir
key = Demo.Custody.new(custody, :ed25519, "local-holder", :holder)
other = Demo.Custody.new(custody, :ed25519, "other-holder", :holder)
{:ok, signature} = Demo.Ed25519Handle.sign("custody probe", key)
true = :crypto.verify(:eddsa, :none, "custody probe", signature, [key.public, :ed25519])
false = :crypto.verify(:eddsa, :none, "custody probe", signature, [other.public, :ed25519])
ec_key = Demo.Custody.new(custody, :p256, "local-ec-holder", :holder)
{:ok, raw} = Demo.P256Handle.sign("custody probe", ec_key)
64 = byte_size(raw)
:ok = GenServer.stop(custody)
false = Process.alive?(custody)
```

The [ES256 custody notebook](../notebooks/es256-custody.livemd) exercises ES256 grant and
report signing, high-S normalization, a DER return refusal and wrong-key self-check
refusal. The [anchors and rotation notebook](../notebooks/anchors-and-rotation.livemd)
executes the ES256 anchor and key-transition signers.
