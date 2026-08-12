defmodule EdgeAgent.DemoIssuer do
  @moduledoc """
  DEMO-ONLY grant minter — plays the ISSUER role so the example loop is
  self-contained, exactly as the Livebook and the adapter's `TestKeys` do.

  ## What this is, and is not

  The adapter is the HOLDER — it signs proofs, never grants. A real grant is
  minted by the `bounded_authority` authority RUNTIME (the issuer runtime that
  also owns issuer key custody + revocation) and arrives at the edge out-of-band
  as an issuer-signed compact string. THIS module exists ONLY so `EdgeAgent.run/0`
  has a real grant to bind a proof to, minted from the configured demo issuer key.
  It must never ship as anything but a demo helper.

  The grant binds to the holder key's thumbprint via `cnf.jkt` (the capability is
  issued TO a specific holder), authorizes the configured operation, and carries a
  time window the verifier's `evaluation_time` must fall inside.
  """

  alias BoundedAuthorityProtocol.V1

  @doc """
  Returns the demo issuer keypair (deterministic seed — never a production key).
  A production issuer's key is custodied by the authority runtime, not derived
  from a fixed seed.
  """
  def keypair, do: ed25519(seed())

  @doc """
  Builds an issuer-signed grant compact for the given holder thumbprint (raw
  32 bytes), returning `{compact, issuer_public_key}`. The public key is the one
  the receiver pins in its `TrustedIssuer` so the grant's issuer signature
  verifies.
  """
  def signed_grant(holder_thumbprint, opts \\ []) do
    {issuer_pub, issuer_priv} = keypair()
    now = System.system_time(:second)

    grant = %V1.Grant{
      key_id: Keyword.get(opts, :key_id, cfg(:issuer_key_id)),
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

    {:ok, signing_input} = V1.grant_signing_input(grant, %{})

    signature =
      :crypto.sign(:eddsa, :ed25519, signing_input.message, [issuer_priv, :ed25519])

    {:ok, compact} = V1.assemble_compact(signing_input, signature)
    {compact, issuer_pub}
  end

  defp seed, do: Application.fetch_env!(:edge_agent, :issuer_seed)
  defp cfg(key), do: Application.fetch_env!(:edge_agent, key)
  defp ed25519(seed), do: :crypto.generate_key(:eddsa, :ed25519, seed)
end
