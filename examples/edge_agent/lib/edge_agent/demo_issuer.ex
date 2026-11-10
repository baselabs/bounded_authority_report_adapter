defmodule EdgeAgent.DemoIssuer do
  @moduledoc """
  DEMO-ONLY grant minter — plays the ISSUER role so the example loop is
  self-contained, exactly as the Livebook and the adapter's `TestKeys` do.

  ## What this is, and is not

  The edge agent is the HOLDER: it signs proofs, never grants. A real grant is
  minted by your authority service (the issuer, which also owns issuer key
  custody and revocation) and arrives at the edge out of band as an
  issuer-signed compact string. THIS module exists ONLY so `EdgeAgent.run/0`
  has a real grant to bind a proof to, minted from the configured demo issuer key.
  It must never ship as anything but a demo helper.

  The grant binds to the holder key's thumbprint via `cnf.jkt` (the capability is
  issued TO a specific holder), authorizes the configured operation, and carries a
  time window the verifier's `evaluation_time` must fall inside.
  """

  alias BoundedAuthorityProtocol.V1

  defmodule Key do
    @moduledoc """
    DEMO-ONLY issuer key handle. The handle term is `{key_id, {public_key, private_key}}`;
    `signing_identity/1` declares the `:issuer` role that `sign_grant/3` requires. A
    production issuer handle forwards these calls to the authority service's key custody.
    """
    @behaviour BoundedAuthorityReportAdapter

    @impl true
    def sign(message, {_key_id, {_public_key, private_key}}),
      do: {:ok, :crypto.sign(:eddsa, :none, message, [private_key, :ed25519])}

    @impl true
    def public_key({_key_id, {public_key, _private_key}}), do: {:ok, public_key}

    @impl true
    def thumbprint({_key_id, {public_key, _private_key}}),
      do: BoundedAuthorityReportAdapter.public_key_thumbprint(public_key)

    @impl true
    def signing_identity({key_id, {public_key, _private_key}}),
      do: {:ok, {:issuer, key_id, public_key}}
  end

  @doc """
  Returns the demo issuer keypair (deterministic seed — never a production key).
  A production issuer's key is custodied by the authority runtime, not derived
  from a fixed seed.
  """
  def keypair, do: ed25519(seed())

  @doc """
  Signs a grant for the given holder thumbprint (raw 32 bytes) with
  `BoundedAuthorityReportAdapter.sign_grant/3` and the demo issuer key, returning
  `{compact, issuer_public_key}`. The public key is the one the receiver pins in its
  `TrustedIssuer` so the grant's issuer signature verifies.
  """
  def signed_grant(holder_thumbprint, opts \\ []) do
    {issuer_public_key, _private_key} = keypair = keypair()
    now = System.system_time(:second)

    grant_input = %{
      issuer: Keyword.get(opts, :issuer, cfg(:issuer)),
      grant_id: Keyword.get(opts, :grant_id, cfg(:grant_id)),
      audiences: Keyword.get(opts, :audiences, [cfg(:audience)]),
      issued_at: Keyword.get(opts, :issued_at, now - 60),
      not_before: Keyword.get(opts, :not_before, now - 60),
      expires_at: Keyword.get(opts, :expires_at, now + 3600),
      holder_thumbprint: holder_thumbprint,
      operations: [
        %V1.Operation{name: Keyword.get(opts, :operation, cfg(:operation)), selectors: [:all]}
      ]
    }

    issuer = {Key, {Keyword.get(opts, :key_id, cfg(:issuer_key_id)), keypair}}
    {:ok, %{grant: compact}} = BoundedAuthorityReportAdapter.sign_grant(grant_input, issuer)
    {compact, issuer_public_key}
  end

  defp seed, do: Application.fetch_env!(:edge_agent, :issuer_seed)
  defp cfg(key), do: Application.fetch_env!(:edge_agent, key)
  defp ed25519(seed), do: :crypto.generate_key(:eddsa, :ed25519, seed)
end
