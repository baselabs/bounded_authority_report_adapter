defmodule BoundedAuthorityReportAdapter.StrictEd25519Handles do
  @moduledoc """
  Test-only key handles and key encodings for the strict Ed25519 suite.

  Two handles, both implementing every callback the six public sign functions resolve
  (`public_key/1`, `key_identity/1`, `signing_identity/1` as `:issuer`, `thumbprint/1`):

    * `WeakKey` presents a caller-chosen 32-byte public key and always answers `sign/2` with
      the forged signature `R = identity, S = 0`. Under the identity key (or any alias of it)
      that signature verifies for every message under a cofactorless backend; under a
      small-order key of order 2, 4 or 8 it verifies for the messages whose challenge scalar
      is a multiple of the point's order. The tests vary one input field until the forgery
      lands (or, after the fix, assert it never gets that far).
    * `NonceZero` holds a REAL key and signs with the nonce `r = 0`: `R = identity`,
      `S = k * a mod L`. That is a genuine signature under a genuine, acceptable key. A
      cofactorless backend accepts it; rule S1 refuses it because `R` is small-order.

  Both count `sign/2` calls in the process dictionary so a test can assert the signer was
  never reached.
  """

  @p 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED

  @identity_r <<1, 0::248>>

  @doc "The forged signature `R = identity, S = 0` (64 bytes)."
  def forged_signature, do: @identity_r <> <<0::256>>

  @doc """
  Small-order and non-canonical public-key encodings that a cofactorless backend decodes.

  Each entry is `{label, 32-byte encoding}`: the identity, a point of order 2, the two
  points of order 4 (`y = 0`), a point of order 8, and `y >= p` aliases of the identity and
  of an order-4 point.
  """
  def weak_keys do
    [
      {"identity (order 1)", <<1, 0::248>>},
      {"order 2", <<@p - 1::little-size(256)>>},
      {"order 4 (all zero)", <<0::256>>},
      {"order 8",
       Base.decode16!("26E8958FC2B227B045C3F489F2EF98F0D5DFAC05D3C63339B13802886D53FC05")},
      {"alias of the identity (y = p + 1)", <<@p + 1::little-size(256)>>},
      {"alias of an order-4 point (y = p)", <<@p::little-size(256)>>}
    ]
  end

  @doc "A canonical 32-byte string that is not the y-coordinate of any curve point (y = 2)."
  def off_curve_key, do: <<2::little-size(256)>>

  defmodule HonestKey do
    @moduledoc false
    @behaviour BoundedAuthorityReportAdapter

    alias BoundedAuthorityProtocol.V1.Jwk

    @kid "honest-key-001"

    @impl true
    def sign(message, seed) when is_binary(message) do
      {:ok, :crypto.sign(:eddsa, :none, message, [seed, :ed25519])}
    end

    @impl true
    def public_key(seed) do
      {public_key, _private} = :crypto.generate_key(:eddsa, :ed25519, seed)
      {:ok, public_key}
    end

    @impl true
    def thumbprint(seed) do
      {:ok, public_key} = public_key(seed)
      Jwk.public_key_thumbprint_raw(public_key, %{})
    end

    @impl true
    def key_identity(seed) do
      {:ok, public_key} = public_key(seed)
      {:ok, {@kid, public_key}}
    end

    @impl true
    def signing_identity(seed) do
      {:ok, public_key} = public_key(seed)
      {:ok, {:issuer, @kid, public_key}}
    end
  end

  defmodule WeakKey do
    @moduledoc false
    @behaviour BoundedAuthorityReportAdapter

    @kid "weak-key-001"
    @counter {__MODULE__, :sign_calls}

    @impl true
    def sign(message, _public_key) when is_binary(message) do
      Process.put(@counter, sign_calls() + 1)
      {:ok, BoundedAuthorityReportAdapter.StrictEd25519Handles.forged_signature()}
    end

    @impl true
    def public_key(public_key), do: {:ok, public_key}

    @impl true
    def thumbprint(_public_key), do: {:ok, <<0::256>>}

    @impl true
    def key_identity(public_key), do: {:ok, {@kid, public_key}}

    @impl true
    def signing_identity(public_key), do: {:ok, {:issuer, @kid, public_key}}

    def sign_calls, do: Process.get(@counter) || 0
    def reset, do: Process.put(@counter, 0)
  end

  defmodule NonceZero do
    @moduledoc false
    @behaviour BoundedAuthorityReportAdapter

    alias BoundedAuthorityProtocol.V1.Jwk

    @l 0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED
    @kid "nonce-zero-key-001"
    @counter {__MODULE__, :sign_calls}

    @impl true
    def sign(message, seed) when is_binary(message) do
      Process.put(@counter, sign_calls() + 1)
      {public_key, _private} = :crypto.generate_key(:eddsa, :ed25519, seed)
      r = <<1, 0::248>>
      <<k::little-size(512)>> = :crypto.hash(:sha512, r <> public_key <> message)
      s = rem(rem(k, @l) * scalar(seed), @l)
      {:ok, r <> <<s::little-size(256)>>}
    end

    @impl true
    def public_key(seed) do
      {public_key, _private} = :crypto.generate_key(:eddsa, :ed25519, seed)
      {:ok, public_key}
    end

    @impl true
    def thumbprint(seed) do
      {:ok, public_key} = public_key(seed)
      Jwk.public_key_thumbprint_raw(public_key, %{})
    end

    @impl true
    def key_identity(seed) do
      {:ok, public_key} = public_key(seed)
      {:ok, {@kid, public_key}}
    end

    @impl true
    def signing_identity(seed) do
      {:ok, public_key} = public_key(seed)
      {:ok, {:issuer, @kid, public_key}}
    end

    def sign_calls, do: Process.get(@counter) || 0
    def reset, do: Process.put(@counter, 0)

    # The clamped secret scalar of RFC 8032 section 5.1.5.
    defp scalar(seed) do
      <<lo::binary-size(32), _hi::binary-size(32)>> = :crypto.hash(:sha512, seed)
      <<first, middle::binary-size(30), last>> = lo

      <<clamped::little-size(256)>> =
        <<Bitwise.band(first, 248), middle::binary, Bitwise.bor(Bitwise.band(last, 127), 64)>>

      clamped
    end
  end
end
