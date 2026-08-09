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
  end

  # --- helpers ---

  defp issuer_pub do
    # The fixture grant is signed by TestKeys' seeded issuer keypair
    # (:crypto.generate_key/2 returns {public, private}).
    {issuer_public, _issuer_private} = TestKeys.issuer_keypair()
    issuer_public
  end
end

# --- test-only key-handle modules (the tripwires) ---
#
# These use the PROCESS DICTIONARY (not named Agents) so they're async-safe:
# each test process has its own dictionary, so concurrent tests don't share
# state. The handle term carries the {pub, priv} keypair; the process dict
# carries the test's count/capture state under a fixed key.

defmodule CountingKeyHandle do
  @moduledoc "Counts sign/2 calls — the C1 tripwire (asserts exactly one signing call)."
  @behaviour BoundedAuthorityReportAdapter

  @key {__MODULE__, :sign_count}

  @impl true
  def sign(message, {_public_key, private_key}) do
    Process.put(@key, (Process.get(@key) || 0) + 1)
    {:ok, :crypto.sign(:eddsa, :ed25519, message, [private_key, :ed25519])}
  end

  @impl true
  def public_key({public_key, _private_key}), do: {:ok, public_key}

  @impl true
  def thumbprint({public_key, _private_key}) do
    {:ok, raw} = BoundedAuthorityProtocol.V1.Jwk.public_key_thumbprint_raw(public_key, %{})
    {:ok, raw}
  end

  def sign_call_count, do: Process.get(@key) || 0
end

defmodule CapturingKeyHandle do
  @moduledoc "Captures the message handed to sign/2 — the no-canonical-bytes-fork tripwire."
  @behaviour BoundedAuthorityReportAdapter

  @key {__MODULE__, :message}

  @impl true
  def sign(message, {_public_key, private_key}) do
    Process.put(@key, message)
    {:ok, :crypto.sign(:eddsa, :ed25519, message, [private_key, :ed25519])}
  end

  @impl true
  def public_key({public_key, _private_key}), do: {:ok, public_key}

  @impl true
  def thumbprint({public_key, _private_key}) do
    {:ok, raw} = BoundedAuthorityProtocol.V1.Jwk.public_key_thumbprint_raw(public_key, %{})
    {:ok, raw}
  end

  def captured_message, do: Process.get(@key)
end

defmodule FailingKeyHandle do
  @moduledoc "A key-handle whose sign/2 always fails — exercises the :signing_failed path."
  @behaviour BoundedAuthorityReportAdapter

  @impl true
  def sign(_message, _handle), do: {:error, :always_fails}

  @impl true
  def public_key({public_key, _private_key}), do: {:ok, public_key}

  @impl true
  def thumbprint({public_key, _private_key}) do
    {:ok, raw} = BoundedAuthorityProtocol.V1.Jwk.public_key_thumbprint_raw(public_key, %{})
    {:ok, raw}
  end
end
