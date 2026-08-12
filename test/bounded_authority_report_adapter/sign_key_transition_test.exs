defmodule BoundedAuthorityReportAdapter.SignKeyTransitionTest do
  @moduledoc """
  The RA8 key-transition test suite — the 4th instantiation of the universal
  companion-signer tail. `sign_key_transition/3` signs a `KeyTransition` (the current
  retiring key's assertion of its successor) and the compact round-trips through
  `BoundedAuthorityProtocol.V1.verify_key_transition/4`.

  Role-agnostic (mirrors `sign_anchor/3`, NOT `sign_grant/3`): the current key's identity
  is resolved atomically via `key_identity/1`; there is NO issuer-role gate (a transition
  is a historical-key operation, verified via `HistoricalPublicKey`). See ADR-0009.

  ## Mutation-proven

  The wrong-key + racing tests fail RED if the shared `verify_signature` guard is removed
  (the wrong-key signature would assemble as `{:ok, _}`); the proofs are noted inline.
  """

  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.V1
  alias BoundedAuthorityReportAdapter.Keys.RawKey

  # A fixed effective_at so the grant/proof/verify windows align. The HistoricalPublicKey
  # windows span this instant for both the current (retiring) + next (successor) keys.
  @now 1_750_000_000

  # RawKey.key_identity/1 returns this kid; the signed header `kid` is the current_key_id.
  @current_kid "test-anchor-key-001"
  @next_kid "next-key-2026-08"

  # --- keypairs + thumbprints -------------------------------------------------

  defp current_keypair, do: ed25519(<<2::256>>)
  defp next_keypair, do: ed25519(<<3::256>>)
  defp ed25519(seed), do: :crypto.generate_key(:eddsa, :ed25519, seed)
  defp thumb(pub), do: elem(V1.Jwk.public_key_thumbprint_raw(pub, %{}), 1)

  # --- fixtures ---------------------------------------------------------------

  defp build_transition_input(opts \\ []) do
    {next_pub, _next_priv} = next_keypair()

    %{
      transition_id: Keyword.get(opts, :transition_id, "urn:test:transition:1"),
      chain_id: Keyword.get(opts, :chain_id, "urn:test:chain:1"),
      effective_at: Keyword.get(opts, :effective_at, @now),
      next_key_id: Keyword.get(opts, :next_key_id, @next_kid),
      next_public_key: Keyword.get(opts, :next_public_key, next_pub)
    }
  end

  defp current_handle, do: {RawKey, current_keypair()}

  defp historical_key(key_id, pub, opts \\ []) do
    %V1.HistoricalPublicKey{
      key_id: key_id,
      public_key: pub,
      valid_from: Keyword.get(opts, :valid_from, @now - 3600),
      valid_before: Keyword.get(opts, :valid_before, :unbounded)
    }
  end

  defp expected_transition(transition_input, current_pub, next_pub) do
    %V1.ExpectedKeyTransition{
      transition_id: transition_input.transition_id,
      chain_id: transition_input.chain_id,
      effective_at: transition_input.effective_at,
      current_key_id: @current_kid,
      current_key_fingerprint: thumb(current_pub),
      next_key_id: transition_input.next_key_id,
      next_key_fingerprint: thumb(next_pub),
      bounds: V1.Bounds.maximum()
    }
  end

  # --- the round-trip (ROADMAP RA8 acceptance) --------------------------------

  describe "the round-trip" do
    test "a transition signed through the adapter verifies via verify_key_transition/4" do
      {current_pub, _current_priv} = current_keypair()
      {next_pub, _next_priv} = next_keypair()
      transition_input = build_transition_input()

      assert {:ok, %{key_transition: compact}} =
               BoundedAuthorityReportAdapter.sign_key_transition(
                 transition_input,
                 current_handle(),
                 %{}
               )

      assert {:ok, %V1.KeyTransitionFacts{verification: :authenticated_transition}} =
               V1.verify_key_transition(
                 compact,
                 historical_key(@current_kid, current_pub),
                 historical_key(@next_kid, next_pub),
                 expected_transition(transition_input, current_pub, next_pub)
               )
    end
  end

  # --- the defenses are real (RED-capable) ------------------------------------

  describe "wrong-key + atomic-snapshot drift (the verify_signature guard)" do
    # MUTATION PROOF: remove the verify_signature guard in sign_and_assemble/3 and these
    # two tests go RED — the wrong-key signature would assemble as {:ok, _} instead of
    # {:error, :signing_failed}.

    test "a handle signing with a different key than its key_identity snapshot is rejected" do
      # TransitionWrongKeyHandle: key_identity/1 returns the handle's pub A; sign/2 signs
      # with a different key B. verify_signature catches the mismatch -> :signing_failed.
      {current_pub, current_priv} = current_keypair()

      assert {:error, :signing_failed} =
               BoundedAuthorityReportAdapter.sign_key_transition(
                 build_transition_input(),
                 {TransitionWrongKeyHandle, {current_pub, current_priv}},
                 %{}
               )
    end

    test "a post-snapshot sign/2 key swap is caught (the atomic-snapshot tripwire)" do
      # TransitionRacingKeyIdentityHandle: key_identity/1 returns {kid, pub_a}, then flips
      # state so sign/2 signs with priv_b. The atomic snapshot means kid+pub cannot drift;
      # verify_signature catches the sign/2-vs-snapshot mismatch -> :signing_failed.
      {pub_a, priv_a} = current_keypair()
      {_pub_b, priv_b} = ed25519(<<4::256>>)

      {:ok, pid} =
        Agent.start_link(fn ->
          %{key_id: @current_kid, pub_a: pub_a, priv_a: priv_a, priv_b: priv_b, rotated: false}
        end)

      assert {:error, :signing_failed} =
               BoundedAuthorityReportAdapter.sign_key_transition(
                 build_transition_input(),
                 {TransitionRacingKeyIdentityHandle, pid},
                 %{}
               )
    end
  end

  describe "no canonical-bytes fork (the adapter signs exactly BAP's bytes)" do
    test "the message handed to sign/2 equals key_transition_signing_input's output" do
      {current_pub, _current_priv} = current_keypair()
      handle = {TransitionCapturingKeyHandle, current_keypair()}
      transition_input = build_transition_input()

      assert {:ok, %{key_transition: _compact}} =
               BoundedAuthorityReportAdapter.sign_key_transition(transition_input, handle, %{})

      # Reconstruct the EXACT struct the adapter built + the signing input BAP produced.
      transition = %V1.KeyTransition{
        transition_id: transition_input.transition_id,
        chain_id: transition_input.chain_id,
        effective_at: transition_input.effective_at,
        current_key_id: @current_kid,
        current_public_key: current_pub,
        next_key_id: transition_input.next_key_id,
        next_public_key: transition_input.next_public_key
      }

      {:ok, signing_input} = V1.key_transition_signing_input(transition, %{})
      assert TransitionCapturingKeyHandle.captured_message() == signing_input.message
    end
  end

  describe "defect injection (ROADMAP RA8 acceptance)" do
    test "a tampered transition byte is rejected by verify_key_transition/4" do
      {current_pub, _current_priv} = current_keypair()
      {next_pub, _next_priv} = next_keypair()
      transition_input = build_transition_input()

      assert {:ok, %{key_transition: compact}} =
               BoundedAuthorityReportAdapter.sign_key_transition(
                 transition_input,
                 current_handle(),
                 %{}
               )

      tampered = tamper_signature(compact)

      assert {:error, :invalid} =
               V1.verify_key_transition(
                 tampered,
                 historical_key(@current_kid, current_pub),
                 historical_key(@next_kid, next_pub),
                 expected_transition(transition_input, current_pub, next_pub)
               )
    end
  end

  describe "self-transition + bad inputs (the closed-atom errors)" do
    test "a self-transition (next_public_key == current_public_key) is rejected" do
      # BAP's distinct_fingerprints rejects a transition to the same key at produce-time
      # -> {:producer_error, :invalid}. The adapter does NOT pre-check (design Q6).
      {current_pub, _current_priv} = current_keypair()

      assert {:error, {:producer_error, :invalid}} =
               BoundedAuthorityReportAdapter.sign_key_transition(
                 build_transition_input(next_public_key: current_pub, next_key_id: @current_kid),
                 current_handle(),
                 %{}
               )
    end

    test "a missing content field is :invalid_transition" do
      # next_public_key omitted -> the 32-byte pre-check in build_key_transition fails fast.
      bad_input = %{build_transition_input() | next_public_key: nil}

      assert {:error, :invalid_transition} =
               BoundedAuthorityReportAdapter.sign_key_transition(bad_input, current_handle(), %{})
    end

    test "a non-32-byte next_public_key is :invalid_transition (the design Q7 pre-check)" do
      bad_input = build_transition_input(next_public_key: <<0::128>>)

      assert {:error, :invalid_transition} =
               BoundedAuthorityReportAdapter.sign_key_transition(bad_input, current_handle(), %{})
    end
  end

  describe "the key-handle contract" do
    test "a handle that exits in key_identity/1 is :invalid_key_handle (not a crash)" do
      assert {:error, :invalid_key_handle} =
               BoundedAuthorityReportAdapter.sign_key_transition(
                 build_transition_input(),
                 {TransitionExitingKeyHandle, current_keypair()},
                 %{}
               )
    end

    test "a roleless handle (no key_identity/1) is :invalid_key_handle" do
      # CountingKeyHandle implements sign/2 + public_key/1 + thumbprint/1 but NOT
      # key_identity/1. The UndefinedFunctionError from apply/3 is caught by safe_callback.
      assert {:error, :invalid_key_handle} =
               BoundedAuthorityReportAdapter.sign_key_transition(
                 build_transition_input(),
                 {CountingKeyHandle, current_keypair()},
                 %{}
               )
    end
  end

  # --- helpers ----------------------------------------------------------------

  # Flip one byte of the compact's 64-byte Ed25519 signature. The compact is
  # `protected.payload.signature` (base64url segments); flipping one signature byte breaks
  # the signature without touching the signed content.
  defp tamper_signature(compact) do
    [protected, payload, sig_b64] = String.split(compact, ".")
    sig = Base.url_decode64!(sig_b64, padding: false)
    size = byte_size(sig) - 1
    <<head::binary-size(^size), last>> = sig
    tampered = Base.url_encode64(<<head::binary, Bitwise.bxor(last, 1)>>, padding: false)
    [protected, payload, tampered] |> Enum.join(".")
  end
end
