defmodule BoundedAuthorityReportAdapter.SignGrantTest do
  @moduledoc """
  RA7 — the grant-signing suite. Enforces the C1 role gate (the design-adversarial
  atomic-signing-identity revision), the key_id-from-handle invariant, the wrong-key +
  rotation-race guards, the no-canonical-bytes-fork, output + verifier non-vacuity,
  exit/throw containment, and the closed-atom error set, plus the round-trip acceptance
  proof through `verify_grant/3` and the full `check_envelope/2` loop.

  Mirrors `sign_anchor_test.exs`'s discipline; both paths flow through the same shared
  signing tail (`sign_via_handle → verify_signature → assemble_compact`). The C1 tripwire
  mirrors `sign_report_test.exs`'s `sign_call_count == 1`, pointed the other way
  (a `:holder` handle → `:invalid_key_handle`, `sign_call_count == 0`).
  """

  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.V1
  alias BoundedAuthorityReportAdapter.TestKeys

  # A fixed evaluation time inside the grant's validity window + the proof's freshness window.
  @now 1_750_000_000

  @issuer "https://issuer.example.test"
  @audience "https://verifier.example.test"
  @operation "report_external_materialization"

  # The cast_arguments MUST be BAP's tagged Json.value() form (not a raw map).
  @cast_arguments {:object, [{"record", {:object, [{"region", {:string, "us-east"}}]}}]}

  defp holder_thumbprint do
    {holder_pub, _} = TestKeys.holder_keypair()
    TestKeys.holder_thumbprint_raw(holder_pub)
  end

  defp grant_input(opts \\ []) do
    %{
      issuer: @issuer,
      grant_id: Keyword.get(opts, :grant_id, "urn:example:grant:ra7-test"),
      audiences: Keyword.get(opts, :audiences, [@audience]),
      issued_at: Keyword.get(opts, :issued_at, @now - 100),
      not_before: Keyword.get(opts, :not_before, @now - 100),
      expires_at: Keyword.get(opts, :expires_at, @now + 3600),
      holder_thumbprint: Keyword.get(opts, :holder_thumbprint, holder_thumbprint()),
      operations: [
        %V1.Operation{name: Keyword.get(opts, :operation, @operation), selectors: [:all]}
      ]
    }
  end

  defp issuer_handle do
    {GrantIssuerHandle, TestKeys.issuer_keypair()}
  end

  defp issuer_pub do
    {pub, _} = TestKeys.issuer_keypair()
    pub
  end

  defp trusted_issuer do
    %V1.TrustedIssuer{key_id: GrantIssuerHandle.issuer_kid(), public_key: issuer_pub()}
  end

  defp expected_grant(opts \\ []) do
    %V1.ExpectedGrant{
      issuer: @issuer,
      audience: Keyword.get(opts, :audience, @audience),
      evaluation_time: @now,
      clock_skew: 60,
      bounds: V1.Bounds.maximum()
    }
  end

  describe "the round-trip (RA7 acceptance clause 4)" do
    test "a grant signed through the adapter verifies via verify_grant/3" do
      input = grant_input()

      assert {:ok, %{grant: compact}} =
               BoundedAuthorityReportAdapter.sign_grant(input, issuer_handle(), %{})

      assert {:ok, %V1.GrantFacts{} = facts} =
               V1.verify_grant(compact, trusted_issuer(), expected_grant())

      # The verified facts echo the signed grant's content back.
      assert facts.issuer == @issuer
      assert facts.grant_id == input.grant_id
      assert facts.holder_thumbprint == input.holder_thumbprint
      assert facts.matched_audience == @audience
    end
  end

  describe "the full envelope loop (RA7 ↔ RA1 — design Q8)" do
    test "a sign_grant grant fed into sign_report verifies via check_envelope/2" do
      # The issuer signs the grant (RA7), binding it to the holder's thumbprint.
      {:ok, %{grant: grant_compact}} =
        BoundedAuthorityReportAdapter.sign_grant(grant_input(), issuer_handle(), %{})

      # The holder signs the proof (RA1), binding the grant to a application report.
      report = %{
        grant_compact: grant_compact,
        operation: @operation,
        method: "POST",
        target_uri: "https://api.example.test/invoke",
        invocation_id: "123e4567-e89b-42d3-a456-426614174000",
        cast_arguments: @cast_arguments,
        nonce: "challenge-001"
      }

      holder_handle = {BoundedAuthorityReportAdapter.Keys.RawKey, TestKeys.holder_keypair()}

      assert {:ok, %{proof: proof}} =
               BoundedAuthorityReportAdapter.sign_report(report, holder_handle, %{
                 issued_at: @now - 50
               })

      # The verifier verifies the envelope — grant signature against the issuer key,
      # proof signature against the holder key, proof.thumbprint == grant.holder_thumbprint.
      expected = %V1.ExpectedRequest{
        trusted_issuer: trusted_issuer(),
        issuer: @issuer,
        audience: @audience,
        method: report.method,
        target_uri: report.target_uri,
        invocation_id: report.invocation_id,
        operation: report.operation,
        cast_arguments: report.cast_arguments,
        evaluation_time: @now,
        clock_skew: 60,
        proof_max_age: 300,
        nonce: {:required, report.nonce},
        bounds: V1.Bounds.maximum()
      }

      assert {:ok, _envelope_facts} =
               V1.check_envelope(%V1.Credentials{grant: grant_compact, proof: proof}, expected)
    end
  end

  describe "C1 enforcement: the holder role never signs a grant" do
    test "a :holder handle is rejected BEFORE sign/2 (sign_call_count == 0)" do
      input = grant_input()
      holder_handle = {GrantHolderCountingHandle, TestKeys.holder_keypair()}

      assert {:error, :invalid_key_handle} =
               BoundedAuthorityReportAdapter.sign_grant(input, holder_handle, %{})

      # The holder key was never used to sign the grant — the role gate fired first.
      assert GrantHolderCountingHandle.sign_call_count() == 0
    end

    test "a roleless handle (no signing_identity/1) is rejected as :invalid_key_handle" do
      input = grant_input()
      roleless_handle = {GrantRolelessHandle, TestKeys.issuer_keypair()}

      assert {:error, :invalid_key_handle} =
               BoundedAuthorityReportAdapter.sign_grant(input, roleless_handle, %{})
    end
  end

  describe "atomic signing-identity snapshot (the design-adversarial TOCTOU fix)" do
    test "a post-snapshot sign/2 key swap is caught -> :signing_failed" do
      # signing_identity/1 returns {:issuer, kid_a, pub_a}, then flips state so sign/2
      # signs with priv_b. The atomic snapshot means role+kid+pub cannot drift; the
      # verify_signature guard catches the sign/2-vs-snapshot mismatch.
      {pub_a, priv_a} = :crypto.generate_key(:eddsa, :ed25519, <<201::256>>)
      {_pub_b, priv_b} = :crypto.generate_key(:eddsa, :ed25519, <<202::256>>)

      {:ok, pid} =
        Agent.start_link(fn ->
          %{kid: "issuer-2026-07", pub_a: pub_a, priv_a: priv_a, priv_b: priv_b, rotated: false}
        end)

      on_exit(fn -> if Process.alive?(pid), do: Agent.stop(pid) end)

      assert {:error, :signing_failed} =
               BoundedAuthorityReportAdapter.sign_grant(
                 grant_input(),
                 {GrantRacingIdentityHandle, pid},
                 %{}
               )
    end
  end

  describe "wrong-key guard (the shared-tail verify_signature step)" do
    test "a signature signed with the wrong key yields {:error, :signing_failed}" do
      input = grant_input()
      wrong_key_handle = {GrantWrongKeyHandle, TestKeys.issuer_keypair()}

      assert {:error, :signing_failed} =
               BoundedAuthorityReportAdapter.sign_grant(input, wrong_key_handle, %{})
    end
  end

  describe "key identity from the handle (atomic snapshot — never trusted from the caller)" do
    test "a caller-supplied :key_id / :public_key in the grant map are ignored" do
      # Smuggle bogus key-identifiers through the grant map. The adapter must ignore them:
      # {key_id, public_key} come from the handle's signing_identity/1 snapshot. The signed
      # grant therefore verifies under the HANDLE's TrustedIssuer (kid "issuer-2026-07"),
      # not under any bogus caller value.
      input =
        Map.merge(grant_input(), %{
          key_id: "BOGUS-CALLER-KEY-ID",
          public_key: <<0::256>>
        })

      assert {:ok, %{grant: compact}} =
               BoundedAuthorityReportAdapter.sign_grant(input, issuer_handle(), %{})

      # Green under the handle's issuer key (kid "issuer-2026-07"). Had the adapter used the
      # caller's "BOGUS-CALLER-KEY-ID", verify_grant would fail on the kid mismatch.
      assert {:ok, _facts} = V1.verify_grant(compact, trusted_issuer(), expected_grant())
    end
  end

  describe "no canonical-bytes fork (sign/2 receives exactly BAP's message)" do
    test "the message handed to sign/2 equals V1.grant_signing_input(grant).message" do
      input = grant_input()
      capture_handle = {GrantCapturingKeyHandle, TestKeys.issuer_keypair()}

      assert {:ok, _} = BoundedAuthorityReportAdapter.sign_grant(input, capture_handle, %{})

      captured = GrantCapturingKeyHandle.captured_message()

      # Re-derive the signing input from the exact grant the adapter built (key_id from the
      # handle's snapshot, the rest from caller content).
      expected_grant_struct = %V1.Grant{
        key_id: GrantIssuerHandle.issuer_kid(),
        issuer: input.issuer,
        grant_id: input.grant_id,
        audiences: input.audiences,
        issued_at: input.issued_at,
        not_before: input.not_before,
        expires_at: input.expires_at,
        holder_thumbprint: input.holder_thumbprint,
        operations: input.operations
      }

      {:ok, expected_input} = V1.grant_signing_input(expected_grant_struct, %{})

      # If the adapter forked the canonical-bytes construction, this fails.
      assert captured == expected_input.message
    end
  end

  describe "output + verifier non-vacuity" do
    # Output non-vacuity: sign_grant's compact is the artifact verify_grant checks. A wiring
    # break (sign_grant returning a constant/wrong compact) is caught by the round-trip test
    # above (verify_grant's content checks, runtime.ex:464-469). The flipped-byte test below
    # is verifier-non-vacuity (verify_grant checks the signature) — its non-vacuity is
    # inherited from BAP/RA2; it confirms the end-to-end wiring (the slice cannot mutate BAP).

    test "a flipped signature byte in sign_grant's compact makes verify_grant/3 reject" do
      input = grant_input()

      assert {:ok, %{grant: compact}} =
               BoundedAuthorityReportAdapter.sign_grant(input, issuer_handle(), %{})

      [protected, payload, signature] = String.split(compact, ".")
      flipped_signature = flip_last_char(signature)
      tampered = [protected, payload, flipped_signature] |> Enum.join(".")

      assert {:error, :invalid} =
               V1.verify_grant(tampered, trusted_issuer(), expected_grant())
    end

    test "a tampered expected audience makes verify_grant/3 reject a correctly-signed grant" do
      input = grant_input()

      assert {:ok, %{grant: compact}} =
               BoundedAuthorityReportAdapter.sign_grant(input, issuer_handle(), %{})

      tampered_expected = %{expected_grant() | audience: "https://wrong-audience.example.test"}

      assert {:error, :invalid} = V1.verify_grant(compact, trusted_issuer(), tampered_expected)
    end
  end

  describe "exit/throw containment (safe_callback)" do
    test "a signing_identity/1 that exit/1s yields {:error, :invalid_key_handle}, not a crash" do
      input = grant_input()
      exiting_handle = {GrantExitingHandle, TestKeys.issuer_keypair()}

      assert {:error, :invalid_key_handle} =
               BoundedAuthorityReportAdapter.sign_grant(input, exiting_handle, %{})
    end
  end

  describe "failure paths (closed-atom error set)" do
    test "a non-tuple key_handle returns {:error, :invalid_key_handle}" do
      assert {:error, :invalid_key_handle} =
               BoundedAuthorityReportAdapter.sign_grant(grant_input(), :not_a_tuple, %{})
    end

    test "a missing required grant field returns {:error, :invalid_grant}" do
      assert {:error, :invalid_grant} =
               BoundedAuthorityReportAdapter.sign_grant(%{issuer: "x"}, issuer_handle(), %{})
    end

    test "an empty audiences list returns {:error, :invalid_grant}" do
      bad_input = %{grant_input() | audiences: []}

      assert {:error, :invalid_grant} =
               BoundedAuthorityReportAdapter.sign_grant(bad_input, issuer_handle(), %{})
    end

    test "sign/2 returning {:error, _} yields {:error, :signing_failed}" do
      failing_handle = {GrantFailingKeyHandle, TestKeys.issuer_keypair()}

      assert {:error, :signing_failed} =
               BoundedAuthorityReportAdapter.sign_grant(grant_input(), failing_handle, %{})
    end
  end

  # --- helpers ---

  defp flip_last_char(signature) do
    # Flip one bit in the last base64url char so the decoded signature changes.
    size = byte_size(signature)
    rest = binary_part(signature, 0, size - 1)
    <<byte::8>> = binary_part(signature, size - 1, 1)
    rest <> <<Bitwise.bxor(byte, 1)::8>>
  end
end
