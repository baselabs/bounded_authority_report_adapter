defmodule BoundedAuthorityReportAdapter.SignGrantRoleAttestationTest do
  @moduledoc """
  RA11 — the BA-attested role gate on `sign_grant/3` (ADR-0008; BAP 0.6.0's
  `bap-role-attestation/1`). When the caller supplies `:role_attestation`, the gate calls
  `BoundedAuthorityProtocol.RoleAttestation.V1.verify_attestation/2` against the
  caller-trusted BA attestor, binds the expected subject to the handle's ATOMIC
  `signing_identity/1` snapshot (never caller input — the lying-handle defeat), and requires
  the BA-attested role to be `"issuer"`. The gate fires BEFORE `sign/2`; a holder-role,
  foreign-subject, wrong-trust-root, or window-expired attestation never signs.

  Every rejection leg is a tripwire: without the gate, `sign_grant/3` ignores the option and
  signs, so each `{:error, :invalid_role_attestation}` assertion (and each
  `sign_call_count == 0`) goes RED. The happy path proves no over-rejection; the
  absent-option legs pin the unchanged declaration-only behavior.
  """

  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.RoleAttestation.V1, as: RoleAttestationV1
  alias BoundedAuthorityProtocol.V1
  alias BoundedAuthorityReportAdapter.TestKeys

  @now 1_750_000_000

  @issuer "https://issuer.example.test"
  @audience "https://verifier.example.test"
  @operation "report_external_materialization"

  # A deterministic BA attestor keypair (the trust-root behind the gate).
  @attestor_pair :crypto.generate_key(:eddsa, :ed25519, <<211::256>>)
  @attestor_kid "ba-attestor-1"

  defp holder_thumbprint do
    {holder_pub, _} = TestKeys.holder_keypair()
    TestKeys.holder_thumbprint_raw(holder_pub)
  end

  defp grant_input do
    %{
      issuer: @issuer,
      grant_id: "urn:example:grant:ra11-test",
      audiences: [@audience],
      issued_at: @now - 100,
      not_before: @now - 100,
      expires_at: @now + 3600,
      holder_thumbprint: holder_thumbprint(),
      operations: [%V1.Operation{name: @operation, selectors: [:all]}]
    }
  end

  defp issuer_handle, do: {GrantIssuerHandle, TestKeys.issuer_keypair()}
  defp counting_issuer_handle, do: {GrantIssuerCountingHandle, TestKeys.issuer_keypair()}

  # Mint a BA-signed attestation compact through BAP's own profile producer (the same
  # surface BA's future issuance direction will call).
  defp mint_attestation(attestor_pair, subject_kid, subject_pub, role, opts \\ []) do
    attestation = %RoleAttestationV1.RoleAttestation{
      attestor_key_id: Keyword.get(opts, :attestor_kid, @attestor_kid),
      jti: Keyword.get(opts, :jti, "urn:example:attestation:ra11"),
      key_id: subject_kid,
      public_key: subject_pub,
      role: role,
      nbf: Keyword.get(opts, :nbf, @now - 100),
      exp: Keyword.get(opts, :exp, @now + 3600)
    }

    {:ok, input} = RoleAttestationV1.attestation_signing_input(attestation, %{})
    {attestor_pub, attestor_priv} = attestor_pair
    sig = :crypto.sign(:eddsa, :none, input.message, [attestor_priv, :ed25519])
    {:ok, compact} = RoleAttestationV1.assemble_compact(input, sig)
    {compact, attestor_pub}
  end

  defp issuer_attestation(role \\ "issuer", opts \\ []) do
    {issuer_pub, _} = TestKeys.issuer_keypair()
    mint_attestation(@attestor_pair, GrantIssuerHandle.issuer_kid(), issuer_pub, role, opts)
  end

  defp trust_root(attestor_pub, opts \\ []) do
    %V1.HistoricalPublicKey{
      key_id: @attestor_kid,
      public_key: attestor_pub,
      valid_from: Keyword.get(opts, :valid_from, @now - 600),
      valid_before: Keyword.get(opts, :valid_before, @now + 7200)
    }
  end

  # ra_overrides merge INTO the :role_attestation map (now / attestor / compact); top-level
  # opts (bounds) are added by the caller around it.
  defp attestation_opts({compact, attestor_pub}, ra_overrides \\ []) do
    base = %{compact: compact, attestor: trust_root(attestor_pub), now: @now}
    %{role_attestation: Map.merge(base, Map.new(ra_overrides))}
  end

  describe "the strengthened gate: a valid BA attestation lets the issuer sign" do
    test "an issuer-attested handle signs a grant that verifies via verify_grant/3" do
      opts = attestation_opts(issuer_attestation())

      assert {:ok, %{grant: compact}} =
               BoundedAuthorityReportAdapter.sign_grant(grant_input(), issuer_handle(), opts)

      assert {:ok, %V1.GrantFacts{}} =
               V1.verify_grant(compact, trusted_issuer(), expected_grant())
    end

    test "the gate consumes the option map's now (now == nbf accepts, boundary honored)" do
      opts = attestation_opts(issuer_attestation("issuer", nbf: @now, exp: @now + 600))

      assert {:ok, %{grant: _}} =
               BoundedAuthorityReportAdapter.sign_grant(grant_input(), issuer_handle(), opts)
    end
  end

  describe "a holder-role attestation never signs (the BA-asserted role gate)" do
    test "role == holder -> {:error, :invalid_role_attestation} BEFORE sign/2" do
      handle = counting_issuer_handle()
      opts = attestation_opts(issuer_attestation("holder"))

      assert {:error, :invalid_role_attestation} =
               BoundedAuthorityReportAdapter.sign_grant(grant_input(), handle, opts)

      assert GrantIssuerCountingHandle.sign_call_count() == 0
    end

    # Cross-vendor review B1: the keyword-list opts idiom must not silently drop the gate
    # (the normalizer's %{} default did exactly that — a holder-role attestation SIGNED).
    test "the keyword-list opts idiom runs the gate, not around it" do
      {compact, attestor_pub} = issuer_attestation("holder")
      handle = counting_issuer_handle()

      assert {:error, :invalid_role_attestation} =
               BoundedAuthorityReportAdapter.sign_grant(
                 grant_input(),
                 handle,
                 role_attestation: %{
                   compact: compact,
                   attestor: trust_root(attestor_pub),
                   now: @now
                 }
               )

      assert GrantIssuerCountingHandle.sign_call_count() == 0
    end

    test "an explicit nil role_attestation (map form) is malformed, not absent" do
      handle = counting_issuer_handle()

      assert {:error, :invalid_role_attestation} =
               BoundedAuthorityReportAdapter.sign_grant(grant_input(), handle, %{
                 role_attestation: nil
               })

      assert GrantIssuerCountingHandle.sign_call_count() == 0
    end

    # Nit coverage: the C1 declaration gate still fires FIRST for a holder handle even
    # with a perfectly valid issuer attestation for its own key.
    test "a holder handle with a valid issuer attestation -> C1 fires first (:invalid_key_handle)" do
      {pub, _} = TestKeys.issuer_keypair()
      attestation_for = mint_attestation(@attestor_pair, "holder-test", pub, "issuer")
      holder_handle = {GrantHolderCountingHandle, TestKeys.holder_keypair()}

      assert {:error, :invalid_key_handle} =
               BoundedAuthorityReportAdapter.sign_grant(
                 grant_input(),
                 holder_handle,
                 attestation_opts(attestation_for)
               )

      assert GrantHolderCountingHandle.sign_call_count() == 0
    end
  end

  describe "the lying handle: the subject binding comes from the snapshot, never the caller" do
    test "an attestation for a DIFFERENT key never signs (key binding)" do
      {foreign_pub, _} = :crypto.generate_key(:eddsa, :ed25519, <<212::256>>)

      {_compact, _} =
        attestation_for =
        mint_attestation(@attestor_pair, "issuer-2026-07", foreign_pub, "issuer")

      handle = counting_issuer_handle()

      # Decoy caller-supplied binding keys pointing at the ATTESTED subject: the gate must
      # bind to the HANDLE SNAPSHOT and ignore them (the lying-handle discriminator).
      assert {:error, :invalid_role_attestation} =
               BoundedAuthorityReportAdapter.sign_grant(
                 grant_input(),
                 handle,
                 attestation_opts(attestation_for,
                   subject_key_id: "issuer-2026-07",
                   subject_public_key: foreign_pub
                 )
               )

      assert GrantIssuerCountingHandle.sign_call_count() == 0
    end

    test "an attestation for a DIFFERENT key id never signs (kid binding)" do
      {issuer_pub, _} = TestKeys.issuer_keypair()
      attestation_for = mint_attestation(@attestor_pair, "some-other-kid", issuer_pub, "issuer")
      handle = counting_issuer_handle()

      # Decoy binding keys naming the attested kid — same discriminator, the kid axis.
      assert {:error, :invalid_role_attestation} =
               BoundedAuthorityReportAdapter.sign_grant(
                 grant_input(),
                 handle,
                 attestation_opts(attestation_for,
                   subject_key_id: "some-other-kid",
                   subject_public_key: issuer_pub
                 )
               )

      assert GrantIssuerCountingHandle.sign_call_count() == 0
    end
  end

  describe "the BA trust-root is caller-trusted and exact" do
    test "a wrong attestor public key never signs" do
      {wrong_pub, _} = :crypto.generate_key(:eddsa, :ed25519, <<213::256>>)
      {compact, _} = issuer_attestation()
      handle = counting_issuer_handle()

      assert {:error, :invalid_role_attestation} =
               BoundedAuthorityReportAdapter.sign_grant(grant_input(), handle, %{
                 role_attestation: %{compact: compact, attestor: trust_root(wrong_pub), now: @now}
               })

      assert GrantIssuerCountingHandle.sign_call_count() == 0
    end

    test "an attestation outliving the attestor key's validity never signs" do
      # The attestor window ends BEFORE the attestation's exp — containment fails.
      {compact, attestor_pub} = issuer_attestation("issuer", exp: @now + 8000)
      narrow = trust_root(attestor_pub, valid_before: @now + 4000)
      handle = counting_issuer_handle()

      assert {:error, :invalid_role_attestation} =
               BoundedAuthorityReportAdapter.sign_grant(grant_input(), handle, %{
                 role_attestation: %{compact: compact, attestor: narrow, now: @now}
               })

      assert GrantIssuerCountingHandle.sign_call_count() == 0
    end

    test "now == exp never signs (the half-open window)" do
      opts = attestation_opts(issuer_attestation(), now: @now + 3600)
      handle = counting_issuer_handle()

      assert {:error, :invalid_role_attestation} =
               BoundedAuthorityReportAdapter.sign_grant(grant_input(), handle, opts)

      assert GrantIssuerCountingHandle.sign_call_count() == 0
    end

    test "tampered attestation bytes never sign" do
      {compact, attestor_pub} = issuer_attestation()
      [header, payload, signature] = String.split(compact, ".")
      i = div(String.length(signature), 2)
      c = String.at(signature, i)
      flipped = if(c == "A", do: "B", else: "A")
      sig_tampered = String.replace(signature, c, flipped, global: false)
      assert sig_tampered != signature
      tampered = header <> "." <> payload <> "." <> sig_tampered
      handle = counting_issuer_handle()

      assert {:error, :invalid_role_attestation} =
               BoundedAuthorityReportAdapter.sign_grant(grant_input(), handle, %{
                 role_attestation: %{
                   compact: tampered,
                   attestor: trust_root(attestor_pub),
                   now: @now
                 }
               })

      assert GrantIssuerCountingHandle.sign_call_count() == 0
    end
  end

  describe "malformed option shapes fail closed" do
    test "a non-map role_attestation option" do
      assert {:error, :invalid_role_attestation} =
               BoundedAuthorityReportAdapter.sign_grant(grant_input(), issuer_handle(), %{
                 role_attestation: "not-a-map"
               })
    end

    test "missing compact / attestor keys" do
      {compact, _} = issuer_attestation()

      assert {:error, :invalid_role_attestation} =
               BoundedAuthorityReportAdapter.sign_grant(grant_input(), issuer_handle(), %{
                 role_attestation: %{
                   attestor: trust_root(elem(issuer_attestation(), 1)),
                   now: @now
                 }
               })

      assert {:error, :invalid_role_attestation} =
               BoundedAuthorityReportAdapter.sign_grant(grant_input(), issuer_handle(), %{
                 role_attestation: %{compact: compact, now: @now}
               })
    end
  end

  describe "absent option: the declaration-only C1 gate is unchanged" do
    test "sign_grant without :role_attestation still signs (zero regression)" do
      assert {:ok, %{grant: compact}} =
               BoundedAuthorityReportAdapter.sign_grant(grant_input(), issuer_handle(), %{})

      assert {:ok, %V1.GrantFacts{}} =
               V1.verify_grant(compact, trusted_issuer(), expected_grant())
    end

    test "bounds still forward (the gate rides the same caller bounds)" do
      %{role_attestation: ra} = attestation_opts(issuer_attestation())
      opts = %{role_attestation: ra, bounds: V1.Bounds.maximum()}

      assert {:ok, %{grant: _}} =
               BoundedAuthorityReportAdapter.sign_grant(grant_input(), issuer_handle(), opts)
    end
  end

  describe "the v3 surface fails closed on the option (the profile is Ed25519-bound)" do
    test "V3.sign_grant rejects a map-form role_attestation" do
      alias BoundedAuthorityReportAdapter.V3

      {compact, attestor_pub} = issuer_attestation()

      assert {:error, :invalid_role_attestation} =
               V3.sign_grant(grant_input(), issuer_handle(), %{
                 role_attestation: %{
                   compact: compact,
                   attestor: trust_root(attestor_pub),
                   now: @now
                 }
               })
    end

    test "V3.sign_grant rejects the keyword-list idiom too (no silent drop)" do
      alias BoundedAuthorityReportAdapter.V3

      assert {:error, :invalid_role_attestation} =
               V3.sign_grant(grant_input(), issuer_handle(), role_attestation: :anything)
    end
  end

  defp trusted_issuer do
    {pub, _} = TestKeys.issuer_keypair()
    %V1.TrustedIssuer{key_id: GrantIssuerHandle.issuer_kid(), public_key: pub}
  end

  defp expected_grant do
    %V1.ExpectedGrant{
      issuer: @issuer,
      audience: @audience,
      evaluation_time: @now,
      clock_skew: 60,
      bounds: V1.Bounds.maximum()
    }
  end
end
