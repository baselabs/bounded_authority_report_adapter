defmodule BoundedAuthorityReportAdapter.SignLocalLoopbackReportTest do
  @moduledoc """
  `sign_local_loopback_report/3` — the explicit holder-side signer for the
  byte-distinct local-loopback HTTP application proof
  (`bap-application-proof/local-loopback-http/1`, BAP 0.3.0 / BAP ADR-0027).

  The contract under test (design note 2026-08-31, .kimosabe/intents/):

    * same `report()` field set as `sign_report/3`, but the nonce is REQUIRED
      (non-empty binary) and `target_uri` must be a CANONICAL
      `http://127.0.0.1`/`http://[::1]` target — admission is DELEGATED to
      BAP's producer (BARA adds no URI logic; every deceptive form fails
      closed as `{:producer_error, :invalid}`);
    * profile selection is the FUNCTION NAME — never inferred, never an
      option on `sign_report/3`;
    * the produced bytes are profile-distinct (`ba+loopback-proof`, kind
      `:local_loopback_http_proof`) and mutually rejected with the standard
      `dpop+jwt` profile in BOTH directions;
    * errors are the closed `sign_error()` set — no key material, nonce
      values, proof bytes, or report content ever ride an error or a
      telemetry event;
    * the message handed to `sign/2` is EXACTLY BAP's local-profile signing
      input, and assembly is BAP's (never recreated locally).
  """

  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.ApplicationProfile.LocalLoopbackHttp.V1, as: Loopback
  alias BoundedAuthorityProtocol.V1
  alias BoundedAuthorityProtocol.V1.{Bounds, Credentials, ExpectedRequest, TrustedIssuer}
  alias BoundedAuthorityReportAdapter.Keys.RawKey
  alias BoundedAuthorityReportAdapter.TestKeys

  @now 1_750_000_000
  @cast {:object, [{"record", {:object, [{"region", {:string, "us-east"}}]}}]}
  @invocation_id "123e4567-e89b-42d3-a456-426614174000"
  @nonce "challenge-local-001"

  # A complete valid report over a canonical IPv4 loopback target.
  defp loopback_report(opts \\ []) do
    {holder_pub, _} = TestKeys.holder_keypair()
    thumb = TestKeys.holder_thumbprint_raw(holder_pub)

    {grant_compact, _issuer_pub} =
      TestKeys.issuer_signed_grant_compact(thumb,
        issued_at: @now - 100,
        not_before: @now - 100,
        expires_at: @now + 3600
      )

    %{
      grant_compact: Keyword.get(opts, :grant_compact, grant_compact),
      operation: "report_external_materialization",
      method: "POST",
      target_uri: Keyword.get(opts, :target_uri, "http://127.0.0.1:4000/invoke"),
      invocation_id: @invocation_id,
      cast_arguments: Keyword.get(opts, :cast_arguments, @cast),
      nonce: Keyword.get(opts, :nonce, @nonce)
    }
  end

  defp handle, do: {RawKey, TestKeys.holder_keypair()}

  defp sign(report, key_handle \\ handle(), opts \\ %{}) do
    BoundedAuthorityReportAdapter.sign_local_loopback_report(report, key_handle, opts)
  end

  # The verifier-side expected request the LISTENER would build: the same
  # bound fields, the reserved nonce expectation, and the listener-derived
  # canonical target.
  defp expected_request(report) do
    {issuer_pub, _issuer_priv} = TestKeys.issuer_keypair()

    %ExpectedRequest{
      trusted_issuer: %TrustedIssuer{key_id: "issuer-2026-07", public_key: issuer_pub},
      issuer: "https://issuer.example.test",
      audience: "https://verifier.example.test",
      method: "POST",
      target_uri: report.target_uri,
      invocation_id: report.invocation_id,
      operation: report.operation,
      cast_arguments: report.cast_arguments,
      evaluation_time: @now,
      clock_skew: 60,
      proof_max_age: 300,
      nonce: {:required, report.nonce},
      bounds: Bounds.maximum()
    }
  end

  describe "valid production — both literal loopback families" do
    test "an IPv4 target signs and verifies green via check_local_loopback_envelope" do
      report = loopback_report()

      assert {:ok, %{grant: grant, proof: proof}} =
               sign(report, handle(), %{issued_at: @now - 50, proof_id: "llh-ipv4-001"})

      assert grant == report.grant_compact

      assert {:ok, _facts} =
               Loopback.check_envelope(
                 %Credentials{grant: grant, proof: proof},
                 expected_request(report)
               )
    end

    test "an IPv6 target signs and verifies green via check_local_loopback_envelope" do
      report = loopback_report(target_uri: "http://[::1]:4001/invoke")

      assert {:ok, %{proof: proof}} =
               sign(report, handle(), %{issued_at: @now - 50, proof_id: "llh-ipv6-001"})

      assert {:ok, _facts} =
               Loopback.check_envelope(
                 %Credentials{grant: report.grant_compact, proof: proof},
                 expected_request(report)
               )
    end

    test "a portless canonical IPv4 target (the default-port-elided form) is signable" do
      report = loopback_report(target_uri: "http://127.0.0.1/invoke")

      assert {:ok, %{proof: proof}} =
               sign(report, handle(), %{issued_at: @now - 50, proof_id: "llh-noport-001"})

      assert {:ok, _} = Loopback.decode_proof(proof, %{})
    end

    test "the protected header self-declares typ ba+loopback-proof (byte-distinctness)" do
      report = loopback_report()

      assert {:ok, %{proof: proof}} = sign(report)

      [protected_b64, _payload, _sig] = String.split(proof, ".")

      assert {:ok, {:object, header_members}} =
               V1.Json.decode(Base.url_decode64!(protected_b64, padding: false), Bounds.maximum())

      assert {"typ", {:string, "ba+loopback-proof"}} = List.keyfind(header_members, "typ", 0)
      assert {"alg", {:string, "EdDSA"}} = List.keyfind(header_members, "alg", 0)
    end

    test "the proof decodes under the profile decoder and NOT under the standard decoder" do
      report = loopback_report()

      assert {:ok, %{proof: proof}} = sign(report)

      assert {:ok, decoded} = Loopback.decode_proof(proof, %{})
      assert decoded.target_uri == report.target_uri
      assert decoded.nonce == report.nonce

      assert {:error, :invalid} = V1.decode_proof(proof, %{})
    end
  end

  describe "the nonce is mandatory" do
    test "a nil nonce is rejected as :invalid_report" do
      report = loopback_report(nonce: nil)

      assert {:error, :invalid_report} = sign(report)
    end

    test "an empty nonce is rejected as :invalid_report" do
      report = loopback_report(nonce: "")

      assert {:error, :invalid_report} = sign(report)
    end

    test "a non-binary nonce is rejected as :invalid_report" do
      report = loopback_report(nonce: 5)

      assert {:error, :invalid_report} = sign(report)
    end

    test "a non-UTF8 nonce fails closed at BAP's producer (the BARA/BAP duty split)" do
      # BARA checks presence + binary shape; BAP's valid_nonce? requires a
      # valid UTF-8 string — a binary that is not a string is the producer's
      # to reject (the same split every other field uses).
      report = loopback_report(nonce: <<0xFF, 0xFE>>)

      assert {:error, {:producer_error, :invalid}} = sign(report)
    end

    test "a valid envelope with the WRONG reserved nonce is rejected by the verifier" do
      report = loopback_report()

      assert {:ok, %{grant: grant, proof: proof}} =
               sign(report, handle(), %{issued_at: @now - 50, proof_id: "llh-wrong-nonce"})

      # The correct expectation verifies green; a different reserved nonce reds.
      assert {:ok, _} =
               Loopback.check_envelope(
                 %Credentials{grant: grant, proof: proof},
                 expected_request(report)
               )

      wrong = %{expected_request(report) | nonce: {:required, "other-challenge"}}

      assert {:error, :invalid} =
               Loopback.check_envelope(%Credentials{grant: grant, proof: proof}, wrong)
    end
  end

  describe "literal-host admission is delegated to BAP and fails closed" do
    @deceptive_targets [
      "http://localhost:4000/invoke",
      "http://127.0.0.2:4000/invoke",
      "http://0x7f.0.0.1:4000/invoke",
      "http://2130706433:4000/invoke",
      "http://0177.0.0.1:4000/invoke",
      "http://127.1:4000/invoke",
      "http://[0:0:0:0:0:0:0:1]:4001/invoke",
      "http://[::ffff:127.0.0.1]:4000/invoke",
      "http://[::1%25eth0]:4001/invoke",
      "http://user@127.0.0.1:4000/invoke",
      "http://127.0.0.1.:4000/invoke",
      "http://user:pass@127.0.0.1:4000/invoke",
      "https://127.0.0.1:4000/invoke",
      "HTTPS://127.0.0.1:4000/invoke",
      "HTTP://127.0.0.1:4000/invoke",
      "http://127.0.0.1:80/invoke",
      "http://127.0.0.1:0400/invoke",
      "http://127.0.0.1:0/invoke",
      "http://127.0.0.1:65536/invoke",
      "http://127.0.0.1:4000/invoke?x=1",
      "http://127.0.0.1:4000/invoke#frag",
      "http://127.0.0.1:4000/a/../invoke",
      "http://127.0.0.1",
      "http://127.0.0.1:4000/%2f",
      "http://127.0.0.1:4000/invoke ",
      "http://127.0.0.1:4000/inv\u00f8ke"
    ]

    test "every deceptive or non-canonical target is {:producer_error, :invalid}" do
      for target <- @deceptive_targets do
        report = loopback_report(target_uri: target)

        assert {:error, {:producer_error, :invalid}} = sign(report),
               "target #{inspect(target)} did not fail closed"
      end
    end

    test "a non-binary target is :invalid_report (BARA presence+shape, as every field)" do
      report = loopback_report(target_uri: :not_a_uri)

      assert {:error, :invalid_report} = sign(report)
    end
  end

  describe "profile cross-rejection — the two proof families are mutually exclusive" do
    test "a loopback proof is rejected by the STANDARD envelope verifier and decoder" do
      report = loopback_report()

      assert {:ok, %{grant: grant, proof: proof}} =
               sign(report, handle(), %{issued_at: @now - 50, proof_id: "llh-x-001"})

      assert {:error, :invalid} =
               V1.check_envelope(
                 %Credentials{grant: grant, proof: proof},
                 expected_request(report)
               )

      assert {:error, :invalid} = V1.decode_proof(proof, %{})
    end

    test "a standard dpop+jwt proof is rejected by the LOOPBACK verifier and decoder" do
      report = loopback_report()

      standard_report = %{
        report
        | target_uri: "https://api.example.test/invoke"
      }

      assert {:ok, %{proof: standard_proof}} =
               BoundedAuthorityReportAdapter.sign_report(
                 standard_report,
                 handle(),
                 %{issued_at: @now - 50, proof_id: "std-x-001"}
               )

      # The STANDARD bytes must be rejected by the loopback surfaces...
      assert {:error, :invalid} = Loopback.decode_proof(standard_proof, %{})

      loopback_expected = %ExpectedRequest{
        expected_request(standard_report)
        | target_uri: standard_report.target_uri,
          nonce: {:required, standard_report.nonce}
      }

      assert {:error, :invalid} =
               Loopback.check_envelope(
                 %Credentials{grant: standard_report.grant_compact, proof: standard_proof},
                 loopback_expected
               )

      # ...and the two families never produce the same bytes for the same report.
      assert {:ok, %{proof: loopback_proof}} =
               sign(report, handle(), %{issued_at: @now - 50, proof_id: "std-x-001"})

      assert loopback_proof != standard_proof
    end

    test "sign_report/3 rejects a loopback http target (the standard profile is https-only)" do
      # The disjointness runs both directions: the standard producer admits no
      # http URI, so a caller cannot reach loopback bytes through sign_report/3.
      report = loopback_report()

      assert {:error, {:producer_error, :invalid}} =
               BoundedAuthorityReportAdapter.sign_report(report, handle(), %{
                 issued_at: @now - 50,
                 proof_id: "std-http-001"
               })
    end
  end

  describe "malformed inputs" do
    test "a malformed grant compact fails at the producer (BAP's ath hashing)" do
      report = loopback_report(grant_compact: "not-a-jws")

      assert {:error, {:producer_error, :invalid}} =
               sign(report, handle(), %{issued_at: @now - 50, proof_id: "llh-bad-grant"})
    end

    test "a missing required report field is :invalid_report" do
      report = loopback_report()
      drop = Map.delete(report, :invocation_id)

      assert {:error, :invalid_report} = sign(drop)
    end

    test "a non-map report is :invalid_report" do
      assert {:error, :invalid_report} = sign(:not_a_report)
    end

    test "a nil cast_arguments is :invalid_report" do
      report = loopback_report(cast_arguments: nil)

      assert {:error, :invalid_report} = sign(report)
    end
  end

  describe "the key-handle contract (unchanged callbacks, same defenses)" do
    test "a handle whose sign/2 rejects returns :signing_failed" do
      report = loopback_report()

      assert {:error, :signing_failed} =
               sign(report, {FailingKeyHandle, TestKeys.holder_keypair()}, %{})
    end

    test "a handle violating the {:ok,_}|{:error,_} contract returns :signing_failed" do
      report = loopback_report()

      assert {:error, :signing_failed} =
               sign(report, {BadContractHandle, TestKeys.holder_keypair()}, %{})
    end

    test "a short public key fails fast as :invalid_key_handle" do
      report = loopback_report()

      assert {:error, :invalid_key_handle} = sign(report, {ShortKeyHandle, :unused}, %{})
    end

    test "a raising/exiting public_key/1 callback collapses to :invalid_key_handle" do
      report = loopback_report()

      assert {:error, :invalid_key_handle} =
               sign(report, {ExitingKeyHandle, TestKeys.holder_keypair()}, %{})
    end

    test "the rotation race (public_key A, sign with B) is :signing_failed, never false success" do
      report = loopback_report()

      assert {:error, :signing_failed} =
               sign(report, {WrongKeyHandle, TestKeys.holder_keypair()}, %{})
    end

    test "a malformed handle shape is :invalid_key_handle" do
      report = loopback_report()

      assert {:error, :invalid_key_handle} = sign(report, {NotAModule, :x})
      assert {:error, :invalid_key_handle} = sign(report, :not_a_handle)
    end

    test "exactly one sign/2 call is made (the shared-tail discipline)" do
      report = loopback_report()

      assert {:ok, _} = sign(report, {CountingKeyHandle, TestKeys.holder_keypair()}, %{})
      assert CountingKeyHandle.sign_call_count() == 1
    end
  end

  describe "bounds propagation (opts[:bounds] reaches BAP's producer AND assembler)" do
    test "default (maximum) bounds sign green" do
      report = loopback_report()

      assert {:ok, %{proof: proof}} =
               sign(report, handle(), %{issued_at: @now - 50, proof_id: "llh-bounds-max"})

      assert {:ok, _} = Loopback.decode_proof(proof, %{})
    end

    test "a uri_bytes ceiling below the target length fails at the producer" do
      report = loopback_report()
      tight = %{Bounds.maximum() | uri_bytes: 10}

      assert {:error, {:producer_error, :invalid}} =
               sign(report, handle(), %{bounds: tight, issued_at: @now - 50})
    end

    test "a nonce_bytes ceiling below the nonce length fails at the producer" do
      report = loopback_report()
      tight = %{Bounds.maximum() | nonce_bytes: 2}

      assert {:error, {:producer_error, :invalid}} =
               sign(report, handle(), %{bounds: tight, issued_at: @now - 50})
    end

    test "a compact_bytes ceiling below the assembled width fails at assembly" do
      report = loopback_report()
      tight = %{Bounds.maximum() | compact_bytes: 64}

      assert {:error, {:producer_error, :invalid}} =
               sign(report, handle(), %{bounds: tight, issued_at: @now - 50})
    end
  end

  describe "delegation proof — the signed message IS BAP's local-profile signing input" do
    test "sign/2 receives byte-exactly BAP's input, and BAP's assembler reproduces the compact" do
      report = loopback_report()
      opts = %{issued_at: @now - 50, proof_id: "llh-delegation-001"}

      assert {:ok, %{proof: proof_compact}} =
               sign(report, {CapturingKeyHandle, TestKeys.holder_keypair()}, opts)

      captured = CapturingKeyHandle.captured_message()
      assert is_binary(captured)

      # Independently produce BAP's local-profile signing input from the SAME
      # pinned fields (no adapter code on this path).
      {holder_pub, holder_priv} = TestKeys.holder_keypair()

      bap_proof = %V1.Proof{
        holder_public_key: holder_pub,
        proof_id: opts.proof_id,
        method: report.method,
        target_uri: report.target_uri,
        issued_at: opts.issued_at,
        nonce: report.nonce,
        invocation_id: report.invocation_id,
        operation: report.operation,
        grant_compact: report.grant_compact,
        cast_arguments: report.cast_arguments
      }

      assert {:ok, signing_input} = Loopback.proof_signing_input(bap_proof, %{})

      # The profile kind is BAP's loopback kind — the standard producer's
      # :proof can never appear here.
      assert signing_input.kind == :local_loopback_http_proof

      # BYTE-EXACT message equality: the handle signed exactly what BAP produced.
      assert captured == signing_input.message

      # Assembly is BAP's: feeding BAP's input + a locally-computed signature
      # through BAP's profile assembler reproduces the adapter's compact.
      signature = :crypto.sign(:eddsa, :none, signing_input.message, [holder_priv, :ed25519])

      assert {:ok, assembled} = Loopback.assemble_compact(signing_input, signature, %{})
      assert assembled == proof_compact
    end
  end

  describe "the closed error contract (value-free)" do
    @closed_errors [
      :invalid_report,
      :invalid_key_handle,
      :signing_failed,
      {:producer_error, :invalid}
    ]

    test "every reachable failure path returns a member of the closed set, never a value" do
      report = loopback_report()

      results = [
        sign(:not_a_report),
        sign(%{report | nonce: nil}),
        sign(report, {NotAModule, :x}),
        sign(report, {FailingKeyHandle, TestKeys.holder_keypair()}, %{}),
        sign(loopback_report(target_uri: "http://localhost:4000/invoke")),
        sign(loopback_report(grant_compact: "not-a-jws"))
      ]

      for result <- results do
        assert {:error, error} = result
        assert error in @closed_errors, "off-contract error shape: #{inspect(error)}"
      end
    end

    test "a non-map opts is coerced to defaults rather than crashing" do
      report = loopback_report()

      assert {:ok, %{proof: proof}} = sign(report, handle(), :not_a_map)
      assert {:ok, _} = Loopback.decode_proof(proof, %{})
    end
  end

  describe "telemetry — the closed, value-free span" do
    test "the span emits :local_loopback_report start/stop with closed metadata only" do
      report = loopback_report()
      events = self()

      handler = fn event, measurements, metadata, _config ->
        send(events, {event, measurements, metadata})
      end

      :telemetry.attach_many(
        "test-llh-#{inspect(self())}",
        [
          [:bounded_authority_report_adapter, :sign, :start],
          [:bounded_authority_report_adapter, :sign, :stop]
        ],
        handler,
        nil
      )

      assert {:ok, _} =
               sign(report, handle(), %{issued_at: @now - 50, proof_id: "llh-tele-001"})

      assert_received {[:bounded_authority_report_adapter, :sign, :start], %{count: 1},
                       %{object: :local_loopback_report}}

      assert_received {[:bounded_authority_report_adapter, :sign, :stop], %{duration: d},
                       %{object: :local_loopback_report, result_class: :ok}}

      assert is_integer(d) and d >= 0
    after
      :telemetry.detach("test-llh-#{inspect(self())}")
    end

    test "an input failure classifies as :invalid_input (no values ride along)" do
      report = loopback_report(nonce: nil)
      events = self()

      handler = fn event, _measurements, metadata, _config ->
        if event == [:bounded_authority_report_adapter, :sign, :stop], do: send(events, metadata)
      end

      :telemetry.attach_many(
        "test-llh-err-#{inspect(self())}",
        [[:bounded_authority_report_adapter, :sign, :stop]],
        handler,
        nil
      )

      assert {:error, :invalid_report} = sign(report)
      assert_received %{object: :local_loopback_report, result_class: :invalid_input}
    after
      :telemetry.detach("test-llh-err-#{inspect(self())}")
    end
  end
end
