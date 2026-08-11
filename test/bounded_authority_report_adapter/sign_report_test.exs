defmodule BoundedAuthorityReportAdapter.SignReportTest do
  @moduledoc """
  The RA1 envelope-sign test suite — the enforcement for the C1 (proof-only-
  signing), key-never-leaves, and no-canonical-bytes-fork invariants, plus the
  round-trip acceptance proof.

  ## Contract learnings baked into the fixtures (discovered building this suite)

    * `cast_arguments` must be in BAP's **tagged** `Json.value()` form
      (`{:object, members}`, `{:string, _}`, `{:integer, _}`, ...), NOT a raw
      Elixir map. `RequestDigest.typed/1` rejects raw maps. A caller passing
      `%{"record" => ...}` gets `{:error, {:producer_error, :invalid}}`.
    * The proof's `operation` MUST match a `name` in the grant's `operations`
      list — `verify_proof_parsed` checks the operation is authorized by the
      grant (`unique_operation` + `Selector.match_all`).
    * The grant's time window (`nbf`/`exp`) and the proof's `iat` must overlap
      the verifier's `evaluation_time` (plan-review Finding 1).
  """

  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.V1
  alias BoundedAuthorityReportAdapter.TestKeys

  # A fixed evaluation time so all tests share aligned grant/proof/verify windows.
  @now 1_750_000_000

  # The cast_arguments MUST be the tagged Json.value() form (not a raw map).
  @cast_arguments {:object, [{"record", {:object, [{"region", {:string, "us-east"}}]}}]}

  @operation "report_external_materialization"

  defp build_report(opts \\ []) do
    {holder_pub, _holder_priv} = TestKeys.holder_keypair()
    thumb = TestKeys.holder_thumbprint_raw(holder_pub)

    {grant_compact, _issuer_pub} =
      TestKeys.issuer_signed_grant_compact(thumb,
        issued_at: @now - 100,
        not_before: @now - 100,
        expires_at: @now + 3600
      )

    %{
      grant_compact: grant_compact,
      operation: Keyword.get(opts, :operation, @operation),
      method: "POST",
      target_uri: "https://api.example.test/invoke",
      invocation_id: "123e4567-e89b-42d3-a456-426614174000",
      cast_arguments: Keyword.get(opts, :cast_arguments, @cast_arguments),
      nonce: Keyword.get(opts, :nonce, "challenge-001")
    }
  end

  defp holder_handle do
    {BoundedAuthorityReportAdapter.Keys.RawKey, TestKeys.holder_keypair()}
  end

  defp expected_request(report, issuer_pub, opts \\ []) do
    %V1.ExpectedRequest{
      trusted_issuer: %V1.TrustedIssuer{key_id: "issuer-2026-07", public_key: issuer_pub},
      issuer: "https://issuer.example.test",
      audience: "https://verifier.example.test",
      method: report.method,
      target_uri: report.target_uri,
      invocation_id: report.invocation_id,
      operation: report.operation,
      cast_arguments: report.cast_arguments,
      evaluation_time: Keyword.get(opts, :evaluation_time, @now),
      clock_skew: 60,
      proof_max_age: 300,
      nonce: if(report.nonce, do: {:required, report.nonce}, else: :not_required),
      bounds: V1.Bounds.maximum()
    }
  end

  describe "the round-trip (RA1 acceptance clause 1)" do
    test "an envelope signed through the adapter verifies cleanly via check_envelope/2" do
      report = build_report()
      issuer_pub = issuer_pub()

      assert {:ok, %{grant: grant, proof: proof}} =
               BoundedAuthorityReportAdapter.sign_report(report, holder_handle(), %{
                 issued_at: @now - 50
               })

      assert {:ok, _envelope_facts} =
               V1.check_envelope(
                 %V1.Credentials{grant: grant, proof: proof},
                 expected_request(report, issuer_pub)
               )
    end

    test "the default-generated proof_id (a UUID v4, not pinned) verifies green" do
      # Closes the coverage gap flagged by the correctness closeout lens: the
      # round-trip above pins a fixed proof_id via opts; this one omits :proof_id
      # so the adapter's generate_uuid/0 default flows through check_envelope,
      # exercising that the generated jti satisfies BAP's valid_identifier? gate.
      report = build_report()
      issuer_pub = issuer_pub()

      assert {:ok, %{proof: proof}} =
               BoundedAuthorityReportAdapter.sign_report(report, holder_handle(), %{
                 issued_at: @now - 50
               })

      assert {:ok, _envelope_facts} =
               V1.check_envelope(
                 %V1.Credentials{grant: report.grant_compact, proof: proof},
                 expected_request(report, issuer_pub)
               )
    end
  end

  describe "C1 enforcement: the adapter signs ONLY the proof (never the grant)" do
    # The protected mutation: if the adapter reverted to signing the grant too,
    # sign/2 would be called twice (once for grant, once for proof). This test
    # counts sign/2 calls and asserts exactly ONE. A regression that re-signs
    # the grant makes this go red.
    test "sign/2 is called exactly once (for the proof), never for the grant" do
      report = build_report()
      counting_handle = {CountingKeyHandle, TestKeys.holder_keypair()}

      assert {:ok, _envelope} =
               BoundedAuthorityReportAdapter.sign_report(report, counting_handle, %{
                 issued_at: @now - 50
               })

      # The proof is the ONE signing artifact. A grant-signing regression would
      # bump this to 2.
      assert CountingKeyHandle.sign_call_count() == 1
    end
  end

  describe "key-never-leaves + no-canonical-bytes-fork" do
    # The protected mutation (no-fork): if the adapter hand-built the JWS message
    # instead of calling V1.proof_signing_input, the message handed to sign/2
    # would NOT equal V1.proof_signing_input(proof, %{}).message. This test
    # captures the message and re-derives the expected input from the same proof
    # to assert byte-equality.
    test "sign/2 receives exactly V1.proof_signing_input(proof).message (no canonical-bytes fork)" do
      report = build_report()
      {holder_pub, _} = TestKeys.holder_keypair()
      capture_handle = {CapturingKeyHandle, TestKeys.holder_keypair()}

      assert {:ok, _envelope} =
               BoundedAuthorityReportAdapter.sign_report(report, capture_handle, %{
                 issued_at: @now - 50,
                 proof_id: "fixed-proof-id-001"
               })

      captured_message = CapturingKeyHandle.captured_message()

      # Re-derive the expected signing input from the same proof the adapter
      # built. The proof fields are deterministic given the report + opts.
      expected_proof = %V1.Proof{
        holder_public_key: holder_pub,
        proof_id: "fixed-proof-id-001",
        method: report.method,
        target_uri: report.target_uri,
        issued_at: @now - 50,
        nonce: report.nonce,
        invocation_id: report.invocation_id,
        operation: report.operation,
        grant_compact: report.grant_compact,
        cast_arguments: report.cast_arguments
      }

      {:ok, expected_input} = V1.proof_signing_input(expected_proof, %{})

      # If the adapter forked the canonical-bytes construction, this fails.
      assert captured_message == expected_input.message
    end
  end

  describe "grant pass-through (the adapter does not re-encode the grant)" do
    test "envelope.grant is byte-identical to report.grant_compact" do
      report = build_report()

      assert {:ok, %{grant: grant}} =
               BoundedAuthorityReportAdapter.sign_report(report, holder_handle(), %{
                 issued_at: @now - 50
               })

      assert grant == report.grant_compact
    end
  end

  describe "failure paths (closed-atom error set)" do
    test "a non-tuple key_handle returns {:error, :invalid_key_handle}" do
      report = build_report()

      assert {:error, :invalid_key_handle} =
               BoundedAuthorityReportAdapter.sign_report(report, :not_a_tuple, %{})
    end

    test "a key_handle whose module is undefined returns {:error, :invalid_key_handle}" do
      report = build_report()

      assert {:error, :invalid_key_handle} =
               BoundedAuthorityReportAdapter.sign_report(report, {NonexistentModule, :x}, %{})
    end

    test "sign/2 returning {:error, _} yields {:error, :signing_failed}" do
      report = build_report()
      # FailingKeyHandle.public_key/1 needs a real keypair handle to succeed
      # (so the adapter reaches sign/2, which then fails).
      failing_handle = {FailingKeyHandle, TestKeys.holder_keypair()}

      assert {:error, :signing_failed} =
               BoundedAuthorityReportAdapter.sign_report(report, failing_handle, %{
                 issued_at: @now - 50
               })
    end

    test "a missing required report field returns {:error, :invalid_report}" do
      incomplete_report = %{grant_compact: "x"}

      assert {:error, :invalid_report} =
               BoundedAuthorityReportAdapter.sign_report(incomplete_report, holder_handle(), %{})
    end

    # Cross-vendor closeout finding (Codex + Claude): sign_via_handle/2's case
    # was non-total — a sign/2 returning :ok / nil / a bare binary (not {:ok,_}/
    # {:error,_}) raised CaseClauseError out of sign_report/3. The catch-all
    # clause now maps it to :signing_failed (no raise escapes).
    test "sign/2 returning a non-tuple (e.g. :ok) yields {:error, :signing_failed}, not a raise" do
      report = build_report()
      bad_contract_handle = {BadContractHandle, TestKeys.holder_keypair()}

      assert {:error, :signing_failed} =
               BoundedAuthorityReportAdapter.sign_report(report, bad_contract_handle, %{
                 issued_at: @now - 50
               })
    end

    # Cross-vendor closeout finding: a short public key passed the is_binary
    # guard then failed downstream as {:producer_error, :invalid} instead of the
    # documented :invalid_key_handle. The guard now requires 32 bytes.
    test "a handle returning a short public key yields {:error, :invalid_key_handle}" do
      report = build_report()
      short_key_handle = {ShortKeyHandle, :x}

      assert {:error, :invalid_key_handle} =
               BoundedAuthorityReportAdapter.sign_report(report, short_key_handle, %{
                 issued_at: @now - 50
               })
    end

    # Cross-vendor round 2 (blocking): safe_callback rescued exceptions but not
    # exit/throw — a production HSM/key-server callback that times out (a
    # GenServer.call timeout = an :exit) crashed the caller instead of returning
    # {:error, _}. The catch clauses now contain exits + throws.
    test "a callback that exit/1s yields {:error, :invalid_key_handle}, not a crash" do
      report = build_report()
      exiting_handle = {ExitingKeyHandle, :x}

      assert {:error, :invalid_key_handle} =
               BoundedAuthorityReportAdapter.sign_report(report, exiting_handle, %{})
    end

    # Cross-vendor round 2 (should-fix): sign_via_handle validated only 64-byte
    # length, never that the signature verifies against the resolved public key.
    # A wrong-key sign (public_key/1 returns key A, sign/2 uses key B) produced
    # a {pub_A, sig_B} envelope returned as {:ok, _} — false success. The
    # adapter now verifies the signature against the public key before accepting.
    test "a signature signed with the wrong key yields {:error, :signing_failed}" do
      report = build_report()
      wrong_key_handle = {WrongKeyHandle, TestKeys.holder_keypair()}

      assert {:error, :signing_failed} =
               BoundedAuthorityReportAdapter.sign_report(report, wrong_key_handle, %{
                 issued_at: @now - 50
               })
    end
  end

  describe "opts normalization (closed-atom: a non-map opts coerces, never crashes)" do
    test "a non-map opts uses defaults instead of a value-echoing BadMapError" do
      assert {:ok, _} =
               BoundedAuthorityReportAdapter.sign_report(
                 build_report(),
                 holder_handle(),
                 :not_a_map
               )
    end
  end

  # --- helpers ---

  defp issuer_pub do
    # The fixture grant is signed by TestKeys' seeded issuer keypair
    # (:crypto.generate_key/2 returns {public, private}).
    {issuer_public, _issuer_private} = TestKeys.issuer_keypair()
    issuer_public
  end
end
