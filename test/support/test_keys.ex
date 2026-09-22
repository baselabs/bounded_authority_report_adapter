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
  alias BoundedAuthorityProtocol.V3

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
      :crypto.sign(:eddsa, :none, signing_input.message, [issuer_priv, :ed25519])

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

  # ------------------------------------------------------------------
  # v3 (BAP3-ES256-SHA256) fixtures — EC P-256 keys and the issuer-side
  # v3 grant builder (ADR-0021). The adapter's lib/ never calls
  # `grant_signing_input`; these mirror BAP's own corpus minting.
  # ------------------------------------------------------------------

  # NIST P-256 group order (RFC 6090 / SEC 2) — the low-S normalization
  # boundary for the producing-side fixtures.
  @ec_n 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
  @ec_half_n div(@ec_n, 2)

  @doc """
  A deterministic EC P-256 issuer keypair (seeded) for v3 tests. The ISSUER
  signs the v3 grant (`ES256`).
  """
  def ec_issuer_keypair, do: ec_keypair(<<1::256>>)

  @doc """
  A deterministic EC P-256 holder keypair (seeded) for v3 tests. The HOLDER
  signs the v3 proof (the adapter's role under `V3.sign_report/3`).
  """
  def ec_holder_keypair, do: ec_keypair(<<2::256>>)

  @doc "An arbitrary additional deterministic P-256 keypair (seed `s`)."
  def ec_keypair(seed), do: :crypto.generate_key(:ecdh, :prime256v1, seed)

  @doc """
  The raw RFC 7638 EC thumbprint (32 bytes) for a 65-byte uncompressed-SEC1
  P-256 public key — the v3 `cnf.jkt` preimage
  `{"crv":"P-256","kty":"EC","x":X,"y":Y}` hashed with SHA-256
  (spec/bap-v3.md §3.1).
  """
  def ec_thumbprint_raw(public_key) when byte_size(public_key) == 65 do
    {:ok, jwk_preimage} =
      V3.EcJwk.encode_public(public_key, %{})

    :crypto.hash(:sha256, jwk_preimage)
  end

  @doc """
  Signs `message` with a P-256 private key in the v3 wire form: RFC 7518 §3.4
  raw `r || s` (exactly 64 bytes) with low-S normalization — the producing
  posture ADR-0021 Decision 4 pins. OTP `:crypto.sign/5` emits DER; this
  converts and normalizes (test-only issuer/reference path).
  """
  def ec_sign_raw_low_s(message, private_key) do
    {r, s} = der_to_raw(:crypto.sign(:ecdsa, :sha256, message, [private_key, :prime256v1]))
    s = if s > @ec_half_n, do: @ec_n - s, else: s
    r_bytes = pad32(:binary.encode_unsigned(r))
    s_bytes = pad32(:binary.encode_unsigned(s))
    r_bytes <> s_bytes
  end

  @doc "The P-256 group order (the normalization boundary; exposed for tests)."
  def ec_n, do: @ec_n

  defp pad32(bytes) when byte_size(bytes) <= 32 do
    String.duplicate(<<0>>, 32 - byte_size(bytes)) <> bytes
  end

  # Minimal DER ECDSA-Sig-Value walk for the OTP-generated signature: SEQUENCE
  # { INTEGER r, INTEGER s } with minimal-octet unsigned integers.
  defp der_to_raw(<<48, _len, 2, rlen, r::binary-size(rlen), 2, slen, s::binary-size(slen)>>) do
    {:binary.decode_unsigned(r), :binary.decode_unsigned(s)}
  end

  @doc """
  Builds an issuer-signed v3 grant compact (the `BAP3-ES256-SHA256` suite)
  binding the supplied raw EC holder thumbprint via `cnf.jkt`. The v3
  counterpart of `issuer_signed_grant_compact/2`; timestamps pinned the same
  way.
  """
  def ec_issuer_signed_grant_compact(holder_thumbprint_raw, opts \\ []) do
    {issuer_pub, issuer_priv} = ec_issuer_keypair()

    grant = %V3.Grant{
      key_id: "issuer-2026-09",
      issuer: "https://issuer.example.test",
      grant_id: "urn:example:grant:v3-ra-test",
      audiences: ["https://verifier.example.test"],
      issued_at: Keyword.get(opts, :issued_at, 1_000),
      not_before: Keyword.get(opts, :not_before, 1_000),
      expires_at: Keyword.get(opts, :expires_at, 2_000),
      holder_thumbprint: holder_thumbprint_raw,
      operations: [%V3.Operation{name: "report_external_materialization", selectors: [:all]}]
    }

    {:ok, signing_input} = V3.grant_signing_input(grant, %{})
    signature = ec_sign_raw_low_s(signing_input.message, issuer_priv)
    {:ok, compact} = V3.assemble_compact(signing_input, signature)
    {compact, issuer_pub}
  end
end
