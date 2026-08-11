defmodule BoundedAuthorityReportAdapter.SignAnchorTest do
  @moduledoc """
  RA4 — the boundary-anchor signing suite. Enforces the wrong-key guard, the
  key_id-from-handle invariant, exit/throw containment, the no-canonical-bytes-fork,
  and non-vacuity (defect injection), plus the round-trip acceptance proof through
  BAP's `verify_historical_anchor/3`.

  Mirrors `sign_report_test.exs`'s discipline; both paths flow through the same
  shared signing tail (`sign_via_handle → verify_signature → assemble_compact`).
  """

  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.V1
  alias BoundedAuthorityReportAdapter.TestKeys

  # A fixed anchor/evaluation time inside the HistoricalPublicKey validity window.
  @now 1_750_000_000

  # The handle's key_id (RawKey.key_identity/1 + the anchor handles all return this).
  @key_id "test-anchor-key-001"

  # A 32-byte chain hash for a non-zero sequence (the codec requires the zero hash
  # only when sequence == 0).
  @chain_hash :crypto.hash(:sha256, "ra4-test-chain")

  defp anchor_input(opts \\ []) do
    %{
      anchor_id: Keyword.get(opts, :anchor_id, "urn:example:anchor:ra4-001"),
      chain_id: Keyword.get(opts, :chain_id, "urn:example:chain:ra4"),
      sequence: Keyword.get(opts, :sequence, 1),
      chain_hash: Keyword.get(opts, :chain_hash, @chain_hash)
    }
  end

  defp anchor_handle do
    {BoundedAuthorityReportAdapter.Keys.RawKey, TestKeys.holder_keypair()}
  end

  defp holder_pub do
    {pub, _priv} = TestKeys.holder_keypair()
    pub
  end

  defp historical_key(public_key) do
    %V1.HistoricalPublicKey{
      key_id: @key_id,
      public_key: public_key,
      valid_from: @now - 1000,
      valid_before: @now + 1000
    }
  end

  defp expected_anchor(anchor_input, public_key, opts \\ []) do
    {:ok, fingerprint} = V1.Jwk.public_key_thumbprint_raw(public_key, %{})

    %V1.ExpectedAnchor{
      anchor_id: anchor_input.anchor_id,
      anchored_at: Keyword.get(opts, :anchored_at, @now),
      chain_id: anchor_input.chain_id,
      sequence: anchor_input.sequence,
      chain_hash: anchor_input.chain_hash,
      key_id: @key_id,
      key_fingerprint: fingerprint,
      bounds: V1.Bounds.maximum()
    }
  end

  describe "the round-trip (RA4 acceptance)" do
    test "an anchor signed through the adapter verifies via verify_historical_anchor/3" do
      input = anchor_input()
      pub = holder_pub()

      assert {:ok, %{anchor: compact}} =
               BoundedAuthorityReportAdapter.sign_anchor(input, anchor_handle(), %{
                 anchored_at: @now
               })

      assert {:ok, %V1.AnchorFacts{verification: :signature_and_window} = facts} =
               V1.verify_historical_anchor(
                 compact,
                 historical_key(pub),
                 expected_anchor(input, pub)
               )

      # The verified facts echo the signed anchor's identity back.
      assert facts.anchor_id == input.anchor_id
      assert facts.chain_id == input.chain_id
      assert facts.sequence == input.sequence
    end
  end

  describe "wrong-key guard (the shared-tail verify_signature step)" do
    test "a signature signed with the wrong key yields {:error, :signing_failed}" do
      input = anchor_input()
      # public_key/1 returns key A; sign/2 signs with key B.
      wrong_key_handle = {AnchorWrongKeyHandle, TestKeys.holder_keypair()}

      assert {:error, :signing_failed} =
               BoundedAuthorityReportAdapter.sign_anchor(input, wrong_key_handle, %{
                 anchored_at: @now
               })
    end
  end

  describe "key identity from the handle (atomic snapshot — never trusted from the caller)" do
    test "a caller-supplied :key_id / :public_key in the anchor map are ignored" do
      # Smuggle bogus key-identifiers through the anchor map. The adapter must
      # ignore them: {key_id, public_key} come from the handle's key_identity/1.
      # The signed anchor therefore verifies under the HANDLE's
      # HistoricalPublicKey (key_id "test-anchor-key-001"), not under any bogus
      # caller value.
      input =
        Map.merge(anchor_input(), %{
          key_id: "BOGUS-CALLER-KEY-ID",
          public_key: <<0::256>>
        })

      pub = holder_pub()

      assert {:ok, %{anchor: compact}} =
               BoundedAuthorityReportAdapter.sign_anchor(input, anchor_handle(), %{
                 anchored_at: @now
               })

      # Green under the handle's key (key_id @key_id). Had the adapter used the
      # caller's "BOGUS-CALLER-KEY-ID", this verify would fail on kid mismatch.
      assert {:ok, _facts} =
               V1.verify_historical_anchor(
                 compact,
                 historical_key(pub),
                 expected_anchor(input, pub)
               )
    end

    test "a handle without key_identity/1 (proof-only) yields {:error, :invalid_key_handle}" do
      # key_identity/1 is the optional callback; a proof-only handle does not
      # implement it, so sign_anchor cannot resolve the signed header kid.
      input = anchor_input()
      proof_only_handle = {CountingKeyHandle, TestKeys.holder_keypair()}

      assert {:error, :invalid_key_handle} =
               BoundedAuthorityReportAdapter.sign_anchor(input, proof_only_handle, %{
                 anchored_at: @now
               })
    end

    test "a rotation race (atomic snapshot, then sign/2 with the rotated key) is caught at sign" do
      # The cross-vendor (Codex) rotation-race probe, now defended at sign time:
      # key_identity/1 returns a consistent {key_id, pub_a} snapshot in ONE call,
      # so kid+public_key cannot drift; it then flips state so sign/2 signs with
      # key-b. The verify_signature guard catches the sign/2-vs-snapshot mismatch
      # -> :signing_failed, never a silent false-success.
      {pub_a, priv_a} = :crypto.generate_key(:eddsa, :ed25519, <<201::256>>)
      {_pub_b, priv_b} = :crypto.generate_key(:eddsa, :ed25519, <<202::256>>)

      {:ok, pid} =
        Agent.start_link(fn ->
          %{
            key_id: "test-anchor-key-001",
            pub_a: pub_a,
            priv_a: priv_a,
            priv_b: priv_b,
            rotated: false
          }
        end)

      on_exit(fn -> if Process.alive?(pid), do: Agent.stop(pid) end)

      assert {:error, :signing_failed} =
               BoundedAuthorityReportAdapter.sign_anchor(
                 anchor_input(),
                 {RacingKeyIdentityHandle, pid},
                 %{
                   anchored_at: @now
                 }
               )
    end
  end

  describe "exit/throw containment (safe_callback)" do
    test "a key_identity/1 that exit/1s yields {:error, :invalid_key_handle}, not a crash" do
      input = anchor_input()
      exiting_handle = {AnchorExitingKeyHandle, TestKeys.holder_keypair()}

      assert {:error, :invalid_key_handle} =
               BoundedAuthorityReportAdapter.sign_anchor(input, exiting_handle, %{})
    end
  end

  describe "no canonical-bytes fork (sign/2 receives exactly BAP's message)" do
    test "the message handed to sign/2 equals V1.boundary_anchor_signing_input(anchor).message" do
      input = anchor_input()
      pub = holder_pub()
      capture_handle = {AnchorCapturingKeyHandle, TestKeys.holder_keypair()}

      assert {:ok, _} =
               BoundedAuthorityReportAdapter.sign_anchor(input, capture_handle, %{
                 anchored_at: @now
               })

      captured = AnchorCapturingKeyHandle.captured_message()

      # Re-derive the signing input from the exact anchor the adapter built.
      expected_anchor_struct = %V1.BoundaryAnchor{
        anchor_id: input.anchor_id,
        anchored_at: @now,
        chain_id: input.chain_id,
        sequence: input.sequence,
        chain_hash: input.chain_hash,
        key_id: @key_id,
        public_key: pub
      }

      {:ok, expected_input} = V1.boundary_anchor_signing_input(expected_anchor_struct, %{})

      # If the adapter forked the canonical-bytes construction, this fails.
      assert captured == expected_input.message
    end
  end

  describe "non-vacuity (defect injection — the signed anchor is real)" do
    test "a flipped signature byte makes verify_historical_anchor/3 reject" do
      input = anchor_input()
      pub = holder_pub()

      assert {:ok, %{anchor: compact}} =
               BoundedAuthorityReportAdapter.sign_anchor(input, anchor_handle(), %{
                 anchored_at: @now
               })

      # Tamper the compact's trailing 86 base64url chars (the signature segment).
      [protected, payload, signature] = String.split(compact, ".")
      flipped_signature = flip_last_char(signature)
      tampered = [protected, payload, flipped_signature] |> Enum.join(".")

      assert {:error, :invalid} =
               V1.verify_historical_anchor(
                 tampered,
                 historical_key(pub),
                 expected_anchor(input, pub)
               )
    end

    test "a tampered chain_hash makes verify_historical_anchor/3 reject (constant-time mismatch)" do
      input = anchor_input()
      pub = holder_pub()

      assert {:ok, %{anchor: compact}} =
               BoundedAuthorityReportAdapter.sign_anchor(input, anchor_handle(), %{
                 anchored_at: @now
               })

      tampered_expected = %{
        expected_anchor(input, pub)
        | chain_hash: :crypto.hash(:sha256, "different")
      }

      assert {:error, :invalid} =
               V1.verify_historical_anchor(compact, historical_key(pub), tampered_expected)
    end
  end

  describe "failure paths (closed-atom error set)" do
    test "a non-tuple key_handle returns {:error, :invalid_key_handle}" do
      assert {:error, :invalid_key_handle} =
               BoundedAuthorityReportAdapter.sign_anchor(anchor_input(), :not_a_tuple, %{})
    end

    test "a missing required anchor field returns {:error, :invalid_anchor}" do
      assert {:error, :invalid_anchor} =
               BoundedAuthorityReportAdapter.sign_anchor(%{anchor_id: "x"}, anchor_handle(), %{})
    end

    test "a negative sequence returns {:error, :invalid_anchor}" do
      bad_input = %{anchor_input() | sequence: -1}

      assert {:error, :invalid_anchor} =
               BoundedAuthorityReportAdapter.sign_anchor(bad_input, anchor_handle(), %{
                 anchored_at: @now
               })
    end

    test "sign/2 returning {:error, _} yields {:error, :signing_failed}" do
      failing_handle = {AnchorFailingKeyHandle, TestKeys.holder_keypair()}

      assert {:error, :signing_failed} =
               BoundedAuthorityReportAdapter.sign_anchor(anchor_input(), failing_handle, %{
                 anchored_at: @now
               })
    end
  end

  describe "opts normalization (closed-atom: a non-map opts coerces, never crashes)" do
    test "a non-map opts uses defaults instead of a value-echoing BadMapError" do
      assert {:ok, _} =
               BoundedAuthorityReportAdapter.sign_anchor(
                 anchor_input(),
                 anchor_handle(),
                 :not_a_map
               )
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
