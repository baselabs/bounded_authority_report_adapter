defmodule EdgeAgent.Handle do
  @moduledoc """
  DEMO-ONLY proof-only key-handle for the edge agent.

  The handle term is a `{public_key, private_key}` tuple of raw 32-byte Ed25519
  keys. This mirrors the adapter's test-only `BoundedAuthorityReportAdapter.Keys.RawKey`
  reference implementation, but lives in THIS example app (not the library) and
  implements ONLY the proof-required callbacks (`sign/2`, `public_key/1`,
  `thumbprint/1`) — it never needs `key_identity/1` (anchor) or
  `signing_identity/1` (grant), because the edge agent calls `sign_report/3`.

  ## Why this is demo-only

  A `{pub, priv}` tuple puts the private key in process memory as a recoverable
  BEAM binary. That posture is fine for a runnable example, but a PRODUCTION
  edge agent must implement these callbacks against proper key custody — an HSM,
  the OS keychain, or a key server — so the private key is never extractable as a
  BEAM binary (the adapter's `docs/strategy.md` §4: once the signing key is in the
  app, extracting it is a re-architecture, not a refactor). The whole point of the
  `{module(), term()}` handle contract is that THIS module is the only place a real
  deployment swaps in custody; everything else stays identical.
  """

  @behaviour BoundedAuthorityReportAdapter

  alias BoundedAuthorityProtocol.V1.Jwk

  @impl true
  def sign(message, {_public_key, private_key}) when is_binary(message) do
    {:ok, :crypto.sign(:eddsa, :none, message, [private_key, :ed25519])}
  end

  def sign(_message, _handle), do: {:error, :invalid_handle}

  @impl true
  def public_key({public_key, _private_key}), do: {:ok, public_key}
  def public_key(_handle), do: {:error, :invalid_handle}

  @impl true
  def thumbprint({public_key, _private_key}) do
    {:ok, raw_thumbprint} = Jwk.public_key_thumbprint_raw(public_key, %{})
    {:ok, raw_thumbprint}
  end

  def thumbprint(_handle), do: {:error, :invalid_handle}
end
