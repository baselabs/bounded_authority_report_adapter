defmodule BoundedAuthorityReportAdapter.V3SignTest do
  @moduledoc """
  The contract-major-3 signing suite — ADR-0021's failure-modes-and-proofs
  matrix, RED-first against the unimplemented surface.

  Legs (each names the ADR decision it proves):
    * round-trips for all four objects through BAP's v3 façade (D1, D6);
    * the cross-type matrix — every operation × both directions (D2);
    * point validation incl. the grant path and `next_public_key` (D2);
    * scalar ordering and boundaries — range check BEFORE normalization (D4);
    * high-S normalization + low-S pass-through (D4);
    * DER rejection (D3);
    * wrong-key rotation race + right-width wrong-suite (D5);
    * differential agreement with BAP's `V3.Es256.verify/3` (D5);
    * cross-major byte-distinctness and mixed-major fail-fast (D8);
    * the C1 role gate under the v3 surface (D1).
  """

  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.V1

  alias BoundedAuthorityProtocol.V1.{
    Credentials,
    ExpectedAnchor,
    ExpectedGrant,
    ExpectedKeyTransition,
    ExpectedRequest,
    HistoricalPublicKey,
    TrustedIssuer
  }

  alias BoundedAuthorityProtocol.V3
  alias BoundedAuthorityReportAdapter.Keys.RawKey
  alias BoundedAuthorityReportAdapter.TestKeys

  alias BoundedAuthorityReportAdapter.TestKeys
  alias CapturingECKeyHandle
  alias CraftedSignatureHandle
  alias DerReturnECKeyHandle
  alias ECSnapshotIssuerHandle
  alias EdSnapshotIssuerHandle
  alias GrantHolderECKeyHandle
  alias GrantIssuerECKeyHandle
  alias HighSECKeyHandle
  alias OffCurveIssuerKeyHandle
  alias OffCurveKeyHandle
  alias OffCurveKeyIdentityHandle
  alias WrongCurveIssuerKeyHandle
  alias WrongCurveKeyHandle
  alias WrongKeyECHandle
  alias WrongSuiteHandle

  @now 1_500
  @ec_n TestKeys.ec_n()
  @cast_arguments {:object, [{"record", {:object, [{"region", {:string, "us-east"}}]}}]}

  defp ec_holder, do: TestKeys.ec_holder_keypair()

  defp report_fixture(grant_compact) do
    %{
      grant_compact: grant_compact,
      operation: "report_external_materialization",
      method: "POST",
      target_uri: "https://api.example.test/invoke",
      invocation_id: "123e4567-e89b-42d3-a456-426614174000",
      cast_arguments: @cast_arguments,
      nonce: nil
    }
  end

  defp grant_fixture(holder_thumbprint) do
    %{
      issuer: "https://issuer.example.test",
      grant_id: "urn:example:grant:v3-roundtrip",
      audiences: ["https://verifier.example.test"],
      issued_at: 1_000,
      not_before: 1_000,
      expires_at: 2_000,
      holder_thumbprint: holder_thumbprint,
      operations: [
        %BoundedAuthorityProtocol.V3.Operation{
          name: "report_external_materialization",
          selectors: [:all]
        }
      ]
    }
  end

  defp anchor_fixture do
    %{
      anchor_id: "urn:example:anchor:v3-roundtrip",
      chain_id: "urn:example:chain:v3-roundtrip",
      sequence: 3,
      chain_hash: <<0xCD::256>>
    }
  end

  defp transition_fixture(next_pub) do
    %{
      transition_id: "urn:example:transition:v3-roundtrip",
      chain_id: "urn:example:chain:v3-roundtrip",
      effective_at: 2_000,
      next_key_id: "next-key-v3-roundtrip",
      next_public_key: next_pub
    }
  end

  defp ec_thumb(pub), do: TestKeys.ec_thumbprint_raw(pub)

  defp historical(key_id, public_key, around) do
    %HistoricalPublicKey{
      key_id: key_id,
      public_key: public_key,
      valid_from: around - 100,
      valid_before: around + 100
    }
  end

  # A genuinely signed v2 grant (EdDSA header like v1; payload v: 2 and a
  # range selector) — the discriminator leg for the payload-major gate.
  defp mismatched_major_grant_compact(holder_thumbprint) do
    alias BoundedAuthorityProtocol.V2

    {_pub, priv} = TestKeys.issuer_keypair()

    grant = %V2.Grant{
      key_id: "issuer-2026-07",
      issuer: "https://issuer.example.test",
      grant_id: "urn:example:grant:v2-gate-test",
      audiences: ["https://verifier.example.test"],
      issued_at: 1_000,
      not_before: 1_000,
      expires_at: 2_000,
      holder_thumbprint: holder_thumbprint,
      operations: [
        %V2.Operation{
          name: "report_external_materialization",
          selectors: [{:gte, ["limit"], {:integer, 10}}]
        }
      ]
    }

    {:ok, signing_input} = V2.grant_signing_input(grant, %{})
    signature = :crypto.sign(:eddsa, :none, signing_input.message, [priv, :ed25519])
    {:ok, compact} = V2.assemble_compact(signing_input, signature)
    compact
  end

  defp ed_grant_input(holder_thumbprint) do
    %{
      issuer: "https://issuer.example.test",
      grant_id: "urn:example:grant:ed-improper-list",
      audiences: ["https://verifier.example.test"],
      issued_at: 1_000,
      not_before: 1_000,
      expires_at: 2_000,
      holder_thumbprint: holder_thumbprint,
      operations: [
        %BoundedAuthorityProtocol.V1.Operation{
          name: "report_external_materialization",
          selectors: [:all]
        }
      ]
    }
  end

  defp ed25519_handle do
    {pub, priv} = TestKeys.holder_keypair()
    {RawKey, {pub, priv}}
  end

  # ------------------------------------------------------------- round-trips

  describe "round-trips through the dependency's v3 façade" do
    test "V3.sign_report/3 → V3.check_envelope/2 green (EC holder, v3 grant)" do
      {pub, priv} = ec_holder()
      {grant_compact, issuer_pub} = TestKeys.ec_issuer_signed_grant_compact(ec_thumb(pub))

      assert {:ok, %{grant: grant, proof: proof}} =
               BoundedAuthorityReportAdapter.V3.sign_report(
                 report_fixture(grant_compact),
                 {RawKey, {pub, priv}},
                 %{issued_at: @now, proof_id: "v3-roundtrip-proof-001"}
               )

      assert grant == grant_compact

      assert {:ok, _facts} =
               V3.check_envelope(
                 %Credentials{grant: grant, proof: proof},
                 %ExpectedRequest{
                   trusted_issuer: %TrustedIssuer{
                     key_id: "issuer-2026-09",
                     public_key: issuer_pub
                   },
                   issuer: "https://issuer.example.test",
                   audience: "https://verifier.example.test",
                   method: "POST",
                   target_uri: "https://api.example.test/invoke",
                   invocation_id: "123e4567-e89b-42d3-a456-426614174000",
                   operation: "report_external_materialization",
                   cast_arguments: @cast_arguments,
                   evaluation_time: @now + 50,
                   clock_skew: 60,
                   proof_max_age: 300,
                   nonce: :not_required,
                   bounds: V1.Bounds.maximum()
                 }
               )
    end

    test "V3.sign_grant/3 → V3.verify_grant/3 green" do
      {pub, priv} = ec_holder()

      assert {:ok, %{grant: grant}} =
               BoundedAuthorityReportAdapter.V3.sign_grant(
                 grant_fixture(ec_thumb(pub)),
                 {GrantIssuerECKeyHandle, {pub, priv}},
                 %{}
               )

      assert {:ok, _facts} =
               V3.verify_grant(
                 grant,
                 %TrustedIssuer{key_id: "issuer-2026-09", public_key: pub},
                 %ExpectedGrant{
                   issuer: "https://issuer.example.test",
                   audience: "https://verifier.example.test",
                   evaluation_time: 1_500,
                   clock_skew: 60,
                   bounds: V1.Bounds.maximum()
                 }
               )
    end

    test "V3.sign_anchor/3 → V3.verify_historical_anchor/3 green" do
      {pub, priv} = ec_holder()

      assert {:ok, %{anchor: anchor}} =
               BoundedAuthorityReportAdapter.V3.sign_anchor(
                 anchor_fixture(),
                 {RawKey, {pub, priv}},
                 %{anchored_at: @now}
               )

      assert {:ok, _facts} =
               V3.verify_historical_anchor(
                 anchor,
                 historical("test-anchor-key-001", pub, @now),
                 %ExpectedAnchor{
                   anchor_id: "urn:example:anchor:v3-roundtrip",
                   anchored_at: @now,
                   chain_id: "urn:example:chain:v3-roundtrip",
                   sequence: 3,
                   chain_hash: <<0xCD::256>>,
                   key_id: "test-anchor-key-001",
                   key_fingerprint: ec_thumb(pub),
                   bounds: V1.Bounds.maximum()
                 }
               )
    end

    test "V3.sign_key_transition/3 → V3.verify_key_transition/4 green" do
      {pub, priv} = ec_holder()
      {next_pub, _} = TestKeys.ec_keypair(<<8::256>>)

      assert {:ok, %{key_transition: transition}} =
               BoundedAuthorityReportAdapter.V3.sign_key_transition(
                 transition_fixture(next_pub),
                 {RawKey, {pub, priv}},
                 %{}
               )

      assert {:ok, _facts} =
               V3.verify_key_transition(
                 transition,
                 historical("test-anchor-key-001", pub, 2_000),
                 historical("next-key-v3-roundtrip", next_pub, 2_000),
                 %ExpectedKeyTransition{
                   transition_id: "urn:example:transition:v3-roundtrip",
                   chain_id: "urn:example:chain:v3-roundtrip",
                   effective_at: 2_000,
                   current_key_id: "test-anchor-key-001",
                   current_key_fingerprint: ec_thumb(pub),
                   next_key_id: "next-key-v3-roundtrip",
                   next_key_fingerprint: ec_thumb(next_pub),
                   bounds: V1.Bounds.maximum()
                 }
               )
    end
  end

  # ----------------------------------------------------- cross-type matrix

  describe "the cross-type matrix — every operation, both directions (D2)" do
    setup do
      {pub, priv} = ec_holder()
      ec_pair = %{pub: pub, priv: priv}

      {grant_compact, _} = TestKeys.ec_issuer_signed_grant_compact(ec_thumb(pub))

      # A v1-side report + issuer grant for the v1-direction legs.
      {ed_pub, ed_priv} = TestKeys.holder_keypair()
      ed_thumb = TestKeys.holder_thumbprint_raw(ed_pub)
      {v1_grant, _} = TestKeys.issuer_signed_grant_compact(ed_thumb)

      %{
        ec: ec_pair,
        ec_report: report_fixture(grant_compact),
        grant_input: grant_fixture(ec_thumb(pub)),
        anchor_input: anchor_fixture(),
        transition_input_fn: fn next -> transition_fixture(next) end,
        ed_handle: {RawKey, {ed_pub, ed_priv}},
        ed_report: %{
          grant_compact: v1_grant,
          operation: "report_external_materialization",
          method: "POST",
          target_uri: "https://api.example.test/invoke",
          invocation_id: "123e4567-e89b-42d3-a456-426614174000",
          cast_arguments: @cast_arguments,
          nonce: nil
        },
        ed_grant: %{
          issuer: "https://issuer.example.test",
          grant_id: "urn:example:grant:ed-cross-type",
          audiences: ["https://verifier.example.test"],
          issued_at: 1_000,
          not_before: 1_000,
          expires_at: 2_000,
          holder_thumbprint: ed_thumb,
          operations: [
            %BoundedAuthorityProtocol.V1.Operation{
              name: "report_external_materialization",
              selectors: [:all]
            }
          ]
        },
        ed_anchor: %{
          anchor_id: "urn:example:anchor:ed-cross-type",
          chain_id: "urn:example:chain:ed-cross-type",
          sequence: 1,
          chain_hash: <<0xCE::256>>
        },
        ed_transition: %{
          transition_id: "urn:example:transition:ed-cross-type",
          chain_id: "urn:example:chain:ed-cross-type",
          effective_at: 2_000,
          next_key_id: "next-ed",
          next_public_key: elem(TestKeys.ec_keypair(<<9::256>>), 0)
        }
      }
    end

    test "an Ed25519 key is rejected by every V3 entry point", ctx do
      ed = ctx.ed_handle

      assert {:error, :invalid_key_handle} =
               BoundedAuthorityReportAdapter.V3.sign_report(ctx.ec_report, ed, %{
                 issued_at: @now
               })

      assert {:error, :invalid_key_handle} =
               BoundedAuthorityReportAdapter.V3.sign_grant(ctx.grant_input, ed, %{})

      assert {:error, :invalid_key_handle} =
               BoundedAuthorityReportAdapter.V3.sign_anchor(ctx.anchor_input, ed, %{})

      assert {:error, :invalid_key_handle} =
               BoundedAuthorityReportAdapter.V3.sign_key_transition(
                 ctx.transition_input_fn.(elem(TestKeys.ec_keypair(<<8::256>>), 0)),
                 ed,
                 %{}
               )
    end

    test "an EC P-256 key is rejected by every v1 entry point", ctx do
      ec = {RawKey, {ctx.ec.pub, ctx.ec.priv}}

      assert {:error, :invalid_key_handle} =
               BoundedAuthorityReportAdapter.sign_report(ctx.ed_report, ec, %{
                 issued_at: @now
               })

      assert {:error, :invalid_key_handle} =
               BoundedAuthorityReportAdapter.sign_grant(
                 ctx.ed_grant,
                 {GrantIssuerECKeyHandle, {ctx.ec.pub, ctx.ec.priv}},
                 %{}
               )

      assert {:error, :invalid_key_handle} =
               BoundedAuthorityReportAdapter.sign_anchor(ctx.ed_anchor, ec, %{})

      assert {:error, :invalid_key_handle} =
               BoundedAuthorityReportAdapter.sign_key_transition(ctx.ed_transition, ec, %{})
    end

    test "the v3 grant C1 gate still gates with a wrong-width issuer snapshot", ctx do
      # The width literal and the :issuer role share a clause head in the
      # resolver (adversarial finding 5): a {:issuer, kid, 32-byte-key}
      # snapshot must be rejected, proving C1 did not weaken when the clause
      # widened. And the mirror: a v1 {:issuer, kid, 65-byte-key} snapshot is
      # rejected by the v1 grant path.
      {ed_pub, ed_priv} = TestKeys.holder_keypair()
      {ec_pub, ec_priv} = ec_holder()

      with_ed_snapshot = fn ->
        BoundedAuthorityReportAdapter.V3.sign_grant(
          ctx.grant_input,
          {EdSnapshotIssuerHandle, {ed_pub, ed_priv}},
          %{}
        )
      end

      assert {:error, :invalid_key_handle} = with_ed_snapshot.()
      assert EdSnapshotIssuerHandle.sign_call_count() == 0

      assert {:error, :invalid_key_handle} =
               BoundedAuthorityReportAdapter.sign_grant(
                 ctx.ed_grant,
                 {ECSnapshotIssuerHandle, {ec_pub, ec_priv}},
                 %{}
               )
    end

    test "a 33-byte compressed point and a 64-byte blob are invalid under both majors", ctx do
      {ec_pub, ec_priv} = ec_holder()
      compressed = <<2>> <> binary_part(ec_pub, 1, 32)
      blob64 = :binary.part(ec_pub, 0, 64)

      for bad <- [compressed, blob64] do
        assert {:error, :invalid_key_handle} =
                 BoundedAuthorityReportAdapter.V3.sign_report(
                   ctx.ec_report,
                   {RawKey, {bad, ec_priv}},
                   %{}
                 )

        assert {:error, :invalid_key_handle} =
                 BoundedAuthorityReportAdapter.sign_report(
                   ctx.ed_report,
                   {RawKey, {bad, ec_priv}},
                   %{
                     issued_at: @now
                   }
                 )
      end
    end

    test "a v3 transition's next_public_key must be a 65-byte P-256 point (32 is invalid)", ctx do
      {pub, priv} = ec_holder()
      {next_pub, _} = TestKeys.ec_keypair(<<8::256>>)
      {ed_next, _} = TestKeys.holder_keypair()

      assert {:error, :invalid_transition} =
               BoundedAuthorityReportAdapter.V3.sign_key_transition(
                 transition_fixture(ed_next),
                 {RawKey, {pub, priv}},
                 %{}
               )

      assert {:error, :invalid_transition} =
               BoundedAuthorityReportAdapter.V3.sign_key_transition(
                 transition_fixture(<<4>> <> String.duplicate(<<0xFF>>, 64)),
                 {RawKey, {pub, priv}},
                 %{}
               )

      # The v1 mirror: a 65-byte successor is invalid for a v1 transition.
      assert {:error, :invalid_transition} =
               BoundedAuthorityReportAdapter.sign_key_transition(
                 ctx.ed_transition,
                 ctx.ed_handle,
                 %{}
               )

      # Control: the 65-byte valid successor signs green.
      assert {:ok, _} =
               BoundedAuthorityReportAdapter.V3.sign_key_transition(
                 transition_fixture(next_pub),
                 {RawKey, {pub, priv}},
                 %{}
               )
    end
  end

  # ------------------------------------------------------- point validation

  describe "point validation at the resolvers (D2)" do
    setup do
      {pub, priv} = ec_holder()
      {grant_compact, _} = TestKeys.ec_issuer_signed_grant_compact(ec_thumb(pub))

      %{
        ec: {pub, priv},
        report: report_fixture(grant_compact),
        grant: grant_fixture(ec_thumb(pub))
      }
    end

    # Review repair (B2 round): the malformed-point handles now carry the
    # issuer-role snapshot / atomic key identity, so the rejection provably
    # comes from POINT VALIDATION, not from a missing optional callback
    # rejecting first.
    test "an off-curve 65-byte key is :invalid_key_handle on report, grant, AND anchor", ctx do
      assert {:error, :invalid_key_handle} =
               BoundedAuthorityReportAdapter.V3.sign_report(
                 ctx.report,
                 {OffCurveKeyHandle, :ref},
                 %{
                   issued_at: @now
                 }
               )

      assert {:error, :invalid_key_handle} =
               BoundedAuthorityReportAdapter.V3.sign_grant(
                 ctx.grant,
                 {OffCurveIssuerKeyHandle, :ref},
                 %{}
               )

      assert OffCurveIssuerKeyHandle.sign_call_count() == 0

      assert {:error, :invalid_key_handle} =
               BoundedAuthorityReportAdapter.V3.sign_anchor(
                 anchor_fixture(),
                 {OffCurveKeyIdentityHandle, :ref},
                 %{}
               )
    end

    test "a valid secp256k1 point (wrong curve) is :invalid_key_handle", ctx do
      assert {:error, :invalid_key_handle} =
               BoundedAuthorityReportAdapter.V3.sign_report(
                 ctx.report,
                 {WrongCurveKeyHandle, :ref},
                 %{
                   issued_at: @now
                 }
               )

      assert {:error, :invalid_key_handle} =
               BoundedAuthorityReportAdapter.V3.sign_grant(
                 ctx.grant,
                 {WrongCurveIssuerKeyHandle, :ref},
                 %{}
               )
    end
  end

  # -------------------------------------------------- scalars and low-S/DER

  describe "scalar ordering, boundaries, low-S, and DER (D3, D4)" do
    setup do
      {pub, priv} = ec_holder()
      {grant_compact, _} = TestKeys.ec_issuer_signed_grant_compact(ec_thumb(pub))
      %{ec: {pub, priv}, report: report_fixture(grant_compact)}
    end

    defp n_bytes, do: pad(:_unused, @ec_n)

    defp pad(_ctx, int) do
      bytes = :binary.encode_unsigned(int)
      String.duplicate(<<0>>, 32 - byte_size(bytes)) <> bytes
    end

    test "a high-S valid signature is normalized: the emitted compact carries s ≤ n/2 and verifies",
         ctx do
      {pub, priv} = ctx.ec

      assert {:ok, %{proof: proof}} =
               BoundedAuthorityReportAdapter.V3.sign_report(
                 ctx.report,
                 {HighSECKeyHandle, {pub, priv}},
                 %{
                   issued_at: @now,
                   proof_id: "v3-high-s-normalized-001"
                 }
               )

      [_protected, _payload, sig_b64] = String.split(proof, ".")
      sig = Base.url_decode64!(sig_b64, padding: false)
      <<_r::binary-32, s::binary-32>> = sig
      assert :binary.decode_unsigned(s) <= div(@ec_n, 2)

      # And the normalized compact verifies green through the v3 façade
      # (the tightest statement: the emitted bytes are conforming).
      {issuer_pub, _} = TestKeys.ec_issuer_keypair()
      grant = ctx.report.grant_compact

      assert {:ok, _} =
               V3.check_envelope(
                 %Credentials{grant: grant, proof: proof},
                 %ExpectedRequest{
                   trusted_issuer: %TrustedIssuer{
                     key_id: "issuer-2026-09",
                     public_key: issuer_pub
                   },
                   issuer: "https://issuer.example.test",
                   audience: "https://verifier.example.test",
                   method: "POST",
                   target_uri: "https://api.example.test/invoke",
                   invocation_id: "123e4567-e89b-42d3-a456-426614174000",
                   operation: "report_external_materialization",
                   cast_arguments: @cast_arguments,
                   evaluation_time: @now + 50,
                   clock_skew: 60,
                   proof_max_age: 300,
                   nonce: :not_required,
                   bounds: V1.Bounds.maximum()
                 }
               )
    end

    test "a low-S valid signature passes through byte-identically", ctx do
      {pub, priv} = ctx.ec

      assert {:ok, %{proof: proof}} =
               BoundedAuthorityReportAdapter.V3.sign_report(
                 ctx.report,
                 {CapturingECKeyHandle, {pub, priv}},
                 %{issued_at: @now, proof_id: "v3-low-s-passthrough-001"}
               )

      # Pass-through, stated precisely: the signature segment the compact
      # carries EQUALS the bytes the handle returned (the return was already
      # low-S, so normalization is a no-op — not a re-sign, not a re-spell).
      # ECDSA's per-signature nonce means this cannot be asserted by signing
      # twice; it is asserted against the handle's own captured return.
      returned = CapturingECKeyHandle.captured_signature()
      assert is_binary(returned) and byte_size(returned) == 64
      <<_r::binary-32, s::binary-32>> = returned
      assert :binary.decode_unsigned(s) <= div(@ec_n, 2)

      [_protected, _payload, sig_b64] = String.split(proof, ".")
      assert Base.url_decode64!(sig_b64, padding: false) == returned
    end

    test "a DER-native return is :signing_failed, never converted", ctx do
      {pub, priv} = ctx.ec

      assert {:error, :signing_failed} =
               BoundedAuthorityReportAdapter.V3.sign_report(
                 ctx.report,
                 {DerReturnECKeyHandle, {pub, priv}},
                 %{
                   issued_at: @now
                 }
               )
    end

    test "out-of-range scalars collapse closed — the range check precedes normalization", ctx do
      {pub, _priv} = ctx.ec
      two = pad(:x, 2)

      crafted = %{
        "r = 0" => <<0::256>> <> two,
        "r = n" => n_bytes() <> two,
        "s = n" => two <> n_bytes(),
        "s = n + 1" => two <> pad(:x, @ec_n + 1)
      }

      for {label, blob} <- crafted do
        assert {:error, :signing_failed} =
                 BoundedAuthorityReportAdapter.V3.sign_report(
                   ctx.report,
                   {CraftedSignatureHandle, {pub, blob}},
                   %{issued_at: @now}
                 ),
               "scalar leg #{label} did not close as :signing_failed"
      end
    end

    test "s = n − 1 (in-range, high) normalizes then fails the verify — closed, no raise", ctx do
      # s = n − 1 passes the raw range check and normalizes to s' = 1, but
      # the crafted (r, 1) is not a signature for the key: the VERIFY guard
      # closes it. This is the boundary that punishes normalize-before-check
      # orderings with a negative scalar.
      {pub, _priv} = ctx.ec
      two = pad(:x, 2)
      blob = two <> pad(:x, @ec_n - 1)

      assert {:error, :signing_failed} =
               BoundedAuthorityReportAdapter.V3.sign_report(
                 ctx.report,
                 {CraftedSignatureHandle, {pub, blob}},
                 %{issued_at: @now}
               )
    end
  end

  # -------------------------------------------------------- wrong-key guard

  describe "the wrong-key verify guard under ES256 (D5)" do
    setup do
      {pub, priv} = ec_holder()
      {grant_compact, _} = TestKeys.ec_issuer_signed_grant_compact(ec_thumb(pub))
      %{ec: {pub, priv}, report: report_fixture(grant_compact)}
    end

    test "a handle that snapshots key A and signs with key B is :signing_failed", ctx do
      {pub, priv} = ctx.ec

      assert {:error, :signing_failed} =
               BoundedAuthorityReportAdapter.V3.sign_report(
                 ctx.report,
                 {WrongKeyECHandle, {pub, priv}},
                 %{
                   issued_at: @now
                 }
               )
    end

    test "right-width wrong-suite: an Ed25519 signature under a P-256 key is :signing_failed",
         ctx do
      {pub, _priv} = ctx.ec
      {_ed_pub, ed_priv} = TestKeys.holder_keypair()

      assert {:error, :signing_failed} =
               BoundedAuthorityReportAdapter.V3.sign_report(
                 ctx.report,
                 {WrongSuiteHandle, {pub, ed_priv}},
                 %{
                   issued_at: @now
                 }
               )
    end
  end

  # ------------------------------------------------- differential agreement

  describe "differential agreement with BAP's V3.Es256.verify/3 (D5)" do
    test "valid low-S signatures and single-bit mutations agree on every sample" do
      for seed <- 1..25 do
        {pub, priv} = TestKeys.ec_keypair(<<seed::256>>)

        {grant_compact, _} =
          TestKeys.ec_issuer_signed_grant_compact(ec_thumb(pub),
            issued_at: 1_000,
            not_before: 1_000,
            expires_at: 2_000
          )

        report = report_fixture(grant_compact)
        opts = %{issued_at: @now, proof_id: "v3-differential-#{seed}"}

        # Capture BAP's exact signing input message by signing once for real;
        # the valid sample is the signature over THAT message (a crafted
        # signature over any other message is a wrong-message signature, not
        # a differential sample).
        assert {:ok, _} =
                 BoundedAuthorityReportAdapter.V3.sign_report(
                   report,
                   {CapturingECKeyHandle, {pub, priv}},
                   opts
                 )

        message = CapturingECKeyHandle.captured_message()
        low_s = CapturingECKeyHandle.captured_signature()

        # The adapter's verdict: a handle returning exactly `low_s` (same
        # report + opts → same signing input) signs green.
        assert {:ok, _} =
                 BoundedAuthorityReportAdapter.V3.sign_report(
                   report,
                   {CraftedSignatureHandle, {pub, low_s}},
                   opts
                 ),
               "seed #{seed}: a signature BAP's Es256 accepts was rejected"

        assert V3.Es256.verify(message, low_s, pub),
               "seed #{seed}: fixture is not actually Es256-valid"

        # Single-bit mutations of the last byte: both verifiers must reject.
        <<pre::binary-size(63), last>> = low_s
        mutated = <<pre::binary, Bitwise.bxor(last, 0x01)>>

        assert not V3.Es256.verify(message, mutated, pub),
               "seed #{seed}: Es256 accepted a mutated signature"

        assert {:error, :signing_failed} =
                 BoundedAuthorityReportAdapter.V3.sign_report(
                   report,
                   {CraftedSignatureHandle, {pub, mutated}},
                   opts
                 ),
               "seed #{seed}: the adapter accepted a mutated signature"
      end
    end
  end

  # --------------------------------------------- cross-major + mixed-major

  describe "cross-major byte-distinctness and mixed-major fail-fast (D8)" do
    setup do
      {pub, priv} = ec_holder()
      {grant_compact, issuer_pub} = TestKeys.ec_issuer_signed_grant_compact(ec_thumb(pub))
      %{ec: {pub, priv}, signed_grant: grant_compact, issuer_pub: issuer_pub}
    end

    test "a v3 envelope reds under V1.check_envelope/2 and vice versa", ctx do
      assert {:ok, %{grant: grant, proof: proof}} =
               BoundedAuthorityReportAdapter.V3.sign_report(
                 report_fixture(ctx.signed_grant),
                 {RawKey, ctx.ec},
                 %{issued_at: @now, proof_id: "v3-cross-major-001"}
               )

      assert {:error, :invalid} =
               V1.check_envelope(
                 %Credentials{grant: grant, proof: proof},
                 %ExpectedRequest{
                   trusted_issuer: %TrustedIssuer{
                     key_id: "issuer-2026-09",
                     public_key: ctx.issuer_pub
                   },
                   issuer: "https://issuer.example.test",
                   audience: "https://verifier.example.test",
                   method: "POST",
                   target_uri: "https://api.example.test/invoke",
                   invocation_id: "123e4567-e89b-42d3-a456-426614174000",
                   operation: "report_external_materialization",
                   cast_arguments: @cast_arguments,
                   evaluation_time: @now + 50,
                   clock_skew: 60,
                   proof_max_age: 300,
                   nonce: :not_required,
                   bounds: V1.Bounds.maximum()
                 }
               )

      # The mirror: a v1 envelope reds under V3.check_envelope/2.
      {ed_pub, ed_priv} = TestKeys.holder_keypair()
      ed_thumb = TestKeys.holder_thumbprint_raw(ed_pub)
      {v1_grant, v1_issuer_pub} = TestKeys.issuer_signed_grant_compact(ed_thumb)

      assert {:ok, %{proof: v1_proof}} =
               BoundedAuthorityReportAdapter.sign_report(
                 %{
                   grant_compact: v1_grant,
                   operation: "report_external_materialization",
                   method: "POST",
                   target_uri: "https://api.example.test/invoke",
                   invocation_id: "123e4567-e89b-42d3-a456-426614174000",
                   cast_arguments: @cast_arguments,
                   nonce: nil
                 },
                 {RawKey, {ed_pub, ed_priv}},
                 %{issued_at: @now, proof_id: "v1-cross-major-001"}
               )

      assert {:error, :invalid} =
               V3.check_envelope(
                 %Credentials{grant: v1_grant, proof: v1_proof},
                 %ExpectedRequest{
                   trusted_issuer: %TrustedIssuer{
                     key_id: "issuer-2026-07",
                     public_key: v1_issuer_pub
                   },
                   issuer: "https://issuer.example.test",
                   audience: "https://verifier.example.test",
                   method: "POST",
                   target_uri: "https://api.example.test/invoke",
                   invocation_id: "123e4567-e89b-42d3-a456-426614174000",
                   operation: "report_external_materialization",
                   cast_arguments: @cast_arguments,
                   evaluation_time: @now + 50,
                   clock_skew: 60,
                   proof_max_age: 300,
                   nonce: :not_required,
                   bounds: V1.Bounds.maximum()
                 }
               )
    end

    test "V3.sign_report/3 with a v1 grant fails fast as :invalid_report", ctx do
      {ed_pub, _} = TestKeys.holder_keypair()
      ed_thumb = TestKeys.holder_thumbprint_raw(ed_pub)
      {v1_grant, _} = TestKeys.issuer_signed_grant_compact(ed_thumb)

      assert {:error, :invalid_report} =
               BoundedAuthorityReportAdapter.V3.sign_report(
                 report_fixture(v1_grant),
                 {RawKey, ctx.ec},
                 %{issued_at: @now}
               )
    end

    test "sign_report/3 (v1) with a v3 grant fails fast as :invalid_report", ctx do
      assert {:error, :invalid_report} =
               BoundedAuthorityReportAdapter.sign_report(
                 %{
                   grant_compact: ctx.signed_grant,
                   operation: "report_external_materialization",
                   method: "POST",
                   target_uri: "https://api.example.test/invoke",
                   invocation_id: "123e4567-e89b-42d3-a456-426614174000",
                   cast_arguments: @cast_arguments,
                   nonce: nil
                 },
                 ed25519_handle(),
                 %{issued_at: @now}
               )
    end
  end

  # --------------------------------------------- review-repair regressions

  describe "cross-vendor review repairs (B2 round)" do
    test "an improper-list audiences value is :invalid_grant on BOTH grant paths, no raise" do
      {pub, priv} = ec_holder()

      assert {:error, :invalid_grant} =
               BoundedAuthorityReportAdapter.V3.sign_grant(
                 Map.put(grant_fixture(ec_thumb(pub)), :audiences, [
                   "https://verifier.example.test" | :bad_tail
                 ]),
                 {GrantIssuerECKeyHandle, {pub, priv}},
                 %{}
               )

      {ed_pub, ed_priv} = TestKeys.holder_keypair()
      ed_thumb = TestKeys.holder_thumbprint_raw(ed_pub)

      assert {:error, :invalid_grant} =
               BoundedAuthorityReportAdapter.sign_grant(
                 Map.put(ed_grant_input(ed_thumb), :audiences, [
                   "https://verifier.example.test" | :bad_tail
                 ]),
                 {GrantIssuerHandle, {ed_pub, ed_priv}},
                 %{}
               )
    end

    test "a v2 grant fails both report gates as :invalid_report (the payload names the major)" do
      # v1 and v2 grants share the EdDSA header, so a header-only gate cannot
      # separate them — the payload's v claim does (review finding 2). The
      # fixture grant is GENUINELY valid first — proven green through the V2
      # facade — so the gate's rejection is a major rejection, not a
      # malformed-input rejection.
      {ed_pub, ed_priv} = TestKeys.holder_keypair()
      ed_thumb = TestKeys.holder_thumbprint_raw(ed_pub)
      foreign_grant = mismatched_major_grant_compact(ed_thumb)

      {v2_issuer_pub, _} = TestKeys.issuer_keypair()

      assert {:ok, _facts} =
               BoundedAuthorityProtocol.V2.verify_grant(
                 foreign_grant,
                 %TrustedIssuer{key_id: "issuer-2026-07", public_key: v2_issuer_pub},
                 %ExpectedGrant{
                   issuer: "https://issuer.example.test",
                   audience: "https://verifier.example.test",
                   evaluation_time: 1_500,
                   clock_skew: 60,
                   bounds: V1.Bounds.maximum()
                 }
               )

      assert {:error, :invalid_report} =
               BoundedAuthorityReportAdapter.sign_report(
                 %{
                   grant_compact: foreign_grant,
                   operation: "report_external_materialization",
                   method: "POST",
                   target_uri: "https://api.example.test/invoke",
                   invocation_id: "123e4567-e89b-42d3-a456-426614174000",
                   cast_arguments: @cast_arguments,
                   nonce: nil
                 },
                 {RawKey, {ed_pub, ed_priv}},
                 %{issued_at: @now}
               )

      {ec_pub, ec_priv} = ec_holder()

      assert {:error, :invalid_report} =
               BoundedAuthorityReportAdapter.V3.sign_report(
                 report_fixture(foreign_grant),
                 {RawKey, {ec_pub, ec_priv}},
                 %{issued_at: @now}
               )
    end
  end

  # ----------------------------------------------------------- the C1 gate

  describe "the C1 role gate under the v3 surface (D1)" do
    test "a :holder P-256 handle is rejected by V3.sign_grant/3 before sign/2" do
      {pub, priv} = ec_holder()

      assert {:error, :invalid_key_handle} =
               BoundedAuthorityReportAdapter.V3.sign_grant(
                 grant_fixture(ec_thumb(pub)),
                 {GrantHolderECKeyHandle, {pub, priv}},
                 %{}
               )

      assert GrantHolderECKeyHandle.sign_call_count() == 0
    end
  end
end
