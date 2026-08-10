defmodule BoundedAuthorityReportAdapter.Keys.RawKey do
  @moduledoc """
  TEST-ONLY reference implementation of the `BoundedAuthorityReportAdapter`
  key-handle behaviour.

  The handle term is a `{public_key, private_key}` tuple of raw 32-byte Ed25519
  keys. This compiles ONLY under `:test` (via `mix.exs` `elixirc_paths`) — it
  does NOT ship in the artifact.

  ## Why test-only (design C5 / strategy §4)

  A `{pub, priv}` tuple puts the private key in process memory as a recoverable
  BEAM binary. That posture is acceptable for tests and local development, but
  shipping it in `lib/` would pave a production road to the exact failure mode
  strategy §4 says the separate-repo architecture exists to prevent ("once the
  signing key is in the app, extracting it is a re-architecture, not a
  refactor"). Production holders implement the callbacks themselves with proper
  custody (HSM, OS keychain, a key server) — never this module.

  The callbacks match the `BoundedAuthorityReportAdapter` behaviour contract:
  `sign/2` performs the `:crypto.sign` (the holder's job), `public_key/1` +
  `thumbprint/1` expose the public material the adapter needs to build the proof.
  """

  @behaviour BoundedAuthorityReportAdapter

  @impl true
  def sign(message, {_public_key, private_key}) when is_binary(message) do
    {:ok, :crypto.sign(:eddsa, :ed25519, message, [private_key, :ed25519])}
  end

  def sign(_message, _handle), do: {:error, :invalid_handle}

  @impl true
  def public_key({public_key, _private_key}), do: {:ok, public_key}

  def public_key(_handle), do: {:error, :invalid_handle}

  @impl true
  def thumbprint({public_key, _private_key}) do
    {:ok, raw_thumbprint} =
      BoundedAuthorityProtocol.V1.Jwk.public_key_thumbprint_raw(public_key, %{})

    {:ok, raw_thumbprint}
  end

  def thumbprint(_handle), do: {:error, :invalid_handle}

  @impl true
  # The anchor's signed header `kid`. A test-only reference handle returns a
  # fixed id (a production handle returns its real registry key_id). Pinned so
  # the anchor round-trip test can build the matching HistoricalPublicKey.
  def key_id({_public_key, _private_key}), do: {:ok, "test-anchor-key-001"}

  def key_id(_handle), do: {:error, :invalid_handle}
end
