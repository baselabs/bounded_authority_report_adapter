defmodule BoundedAuthorityReportAdapter.TestKeys do
  alias BoundedAuthorityProtocol.V1.Jwk

  @moduledoc """
  TEST-ONLY keypair fixtures + an issuer-side grant-signing helper for RA1's
  round-trip test.

  The adapter is the HOLDER — it never signs a grant. But RA1's round-trip test
  needs an **issuer-signed** grant compact to feed `sign_report/3`, so the TEST
  plays the issuer here (mirrors BAP's own `corpus_test.exs:signed_grant_compact/1`).
  This is test-only code: the adapter's `lib/` never calls `grant_signing_input`
  (the proof-only-sign tripwire in `sign_report_test.exs` enforces that).

  Compiled only in `:test` (via `mix.exs` `elixirc_paths`).
  """

  alias BoundedAuthorityProtocol.V1

  @doc """
  A deterministic issuer keypair (seeded) for tests. The ISSUER signs the grant.
  """
  def issuer_keypair, do: ed25519_keypair(<<1::256>>)

  @doc """
  A deterministic holder keypair (seeded) for tests. The HOLDER signs the proof
  (this is the adapter's role).
  """
  def holder_keypair, do: ed25519_keypair(<<2::256>>)

  @doc """
  Builds an issuer-signed grant compact (the fixture RA1's round-trip feeds to
  `sign_report/3` as `report.grant_compact`). The grant binds to the supplied
  holder thumbprint (raw 32 bytes) via `cnf.jkt`.

  Mirrors BAP `corpus_test.exs:signed_grant_compact/1`. The timestamps
  (`issued_at`/`not_before`/`expires_at`) are pinned so the test can pin the
  proof's `issued_at` + the verifier's `evaluation_time` into the grant's window
  (plan-review Finding 1: the grant + proof time windows must overlap).
  """
  def issuer_signed_grant_compact(holder_thumbprint_raw, opts \\ []) do
    {issuer_pub, issuer_priv} = issuer_keypair()

    grant = %V1.Grant{
      key_id: "issuer-2026-07",
      issuer: "https://issuer.example.test",
      grant_id: "urn:example:grant:ra1-test",
      audiences: ["https://verifier.example.test"],
      issued_at: Keyword.get(opts, :issued_at, 1_000),
      not_before: Keyword.get(opts, :not_before, 1_000),
      expires_at: Keyword.get(opts, :expires_at, 2_000),
      holder_thumbprint: holder_thumbprint_raw,
      operations: [%V1.Operation{name: "report_external_materialization", selectors: [:all]}]
    }

    {:ok, signing_input} = V1.grant_signing_input(grant, %{})

    signature =
      :crypto.sign(:eddsa, :ed25519, signing_input.message, [issuer_priv, :ed25519])

    {:ok, compact} = V1.assemble_compact(signing_input, signature)
    {compact, issuer_pub}
  end

  @doc """
  The raw RFC 7638 holder thumbprint for a public key (32 bytes), via BAP's JWK
  thumbprint derivation.
  """
  def holder_thumbprint_raw(holder_public_key) do
    {:ok, thumbprint} =
      Jwk.public_key_thumbprint_raw(holder_public_key, %{})

    thumbprint
  end

  defp ed25519_keypair(seed) do
    :crypto.generate_key(:eddsa, :ed25519, seed)
  end
end
