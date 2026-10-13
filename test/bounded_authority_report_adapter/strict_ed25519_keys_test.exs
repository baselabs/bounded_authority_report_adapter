defmodule BoundedAuthorityReportAdapter.StrictEd25519KeysTest do
  @moduledoc """
  Strict Ed25519 key acceptance and self-check, across every public sign function.

  Two defects, one rule (BAP's rule S1, `BoundedAuthorityProtocol.Ed25519`):

    * A key handle whose public key is small-order (the identity, or a point of order 2, 4
      or 8) or a non-canonical alias (`y >= p`) was accepted by all six sign functions, and
      the raw `:crypto.verify` self-check admitted the forged signature `R = identity,
      S = 0` under it. Each function must now refuse such a handle as
      `{:error, :invalid_key_handle}` before `sign/2` runs.
    * The self-check itself accepted a signature whose `R` is the identity even under a
      genuine key (nonce `r = 0`). It must now be `verify_strict/3`, so the same signature
      is `{:error, :signing_failed}`.

  The weak-key tests vary one input field per attempt until the forgery lands. Under a
  small-order key of order 2, 4 or 8 the forged signature verifies only for the messages
  whose challenge scalar is a multiple of the order, so the loop is bounded by
  `@max_attempts` (the miss probability for order 8 is `(7/8)^256`, about `1.5e-15`). After
  the fix the first attempt is refused and `sign/2` is never called.
  """

  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.ContentAssertion.V1, as: Content
  alias BoundedAuthorityProtocol.Ed25519
  alias BoundedAuthorityProtocol.V1
  alias BoundedAuthorityReportAdapter, as: Adapter

  alias BoundedAuthorityReportAdapter.StrictEd25519Handles
  alias BoundedAuthorityReportAdapter.StrictEd25519Handles.{HonestKey, NonceZero, WeakKey}
  alias BoundedAuthorityReportAdapter.TestKeys

  @max_attempts 256
  @now 1_750_000_000
  @cast {:object, [{"record", {:object, [{"region", {:string, "us-east"}}]}}]}
  @operation "report_external_materialization"
  @seed :crypto.hash(:sha256, "strict-ed25519-keys-test-seed")

  # --- one runner per public sign function: (attempt index, handle) -> result ------------

  defp holder_grant_compact do
    {holder_pub, _} = TestKeys.holder_keypair()

    {compact, _issuer_pub} =
      TestKeys.issuer_signed_grant_compact(TestKeys.holder_thumbprint_raw(holder_pub),
        issued_at: @now - 100,
        not_before: @now - 100,
        expires_at: @now + 3600
      )

    compact
  end

  defp report(i) do
    %{
      grant_compact: holder_grant_compact(),
      operation: @operation,
      method: "POST",
      target_uri: "https://api.example.test/invoke",
      invocation_id: "123e4567-e89b-42d3-a456-426614174000",
      cast_arguments: @cast,
      nonce: "challenge-#{i}"
    }
  end

  defp run(:sign_report, i, handle), do: Adapter.sign_report(report(i), handle)

  defp run(:sign_local_loopback_report, i, handle) do
    report = %{report(i) | target_uri: "http://127.0.0.1:4000/invoke"}
    Adapter.sign_local_loopback_report(report, handle)
  end

  defp run(:sign_anchor, i, handle) do
    Adapter.sign_anchor(
      %{
        anchor_id: "urn:example:anchor:strict-#{i}",
        chain_id: "urn:example:chain:strict",
        sequence: 1,
        chain_hash: :crypto.hash(:sha256, "strict-chain")
      },
      handle,
      %{anchored_at: @now}
    )
  end

  defp run(:sign_grant, i, handle) do
    {holder_pub, _} = TestKeys.holder_keypair()

    Adapter.sign_grant(
      %{
        issuer: "https://issuer.example.test",
        grant_id: "urn:example:grant:strict-#{i}",
        audiences: ["https://verifier.example.test"],
        issued_at: @now - 100,
        not_before: @now - 100,
        expires_at: @now + 3600,
        holder_thumbprint: TestKeys.holder_thumbprint_raw(holder_pub),
        operations: [%V1.Operation{name: @operation, selectors: [:all]}]
      },
      handle
    )
  end

  defp run(:sign_key_transition, i, handle) do
    {next_pub, _} = :crypto.generate_key(:eddsa, :ed25519, <<3::256>>)

    Adapter.sign_key_transition(
      %{
        transition_id: "urn:test:transition:strict-#{i}",
        chain_id: "urn:test:chain:strict",
        effective_at: @now,
        next_key_id: "next-key-2026-08",
        next_public_key: next_pub
      },
      handle
    )
  end

  defp run(:sign_content_assertion, i, handle) do
    {:ok, content_digest} = Content.content_digest("exact external bytes", %{})

    Adapter.sign_content_assertion(
      %{
        jti: "urn:example:assertion:strict-#{i}",
        iss: "urn:example:issuer",
        aud: "urn:example:audience",
        sub: "urn:example:lineage",
        profile: "urn:example:profile",
        profile_digest: :crypto.hash(:sha256, "schema bytes"),
        content_digest: content_digest,
        gen: 1,
        prev: <<0::256>>,
        iat: 100,
        nbf: 110,
        exp: 200
      },
      handle,
      %{}
    )
  end

  @sign_functions [
    :sign_report,
    :sign_local_loopback_report,
    :sign_anchor,
    :sign_grant,
    :sign_key_transition,
    :sign_content_assertion
  ]

  # Runs attempts until one is not a self-check refusal. A forgery that lands comes back as
  # {:ok, _}; a refused key comes back as {:error, :invalid_key_handle} on attempt one.
  defp grind(function, handle) do
    Enum.reduce_while(1..@max_attempts, nil, fn i, _previous ->
      case run(function, i, handle) do
        {:error, :signing_failed} = miss -> {:cont, miss}
        landed -> {:halt, landed}
      end
    end)
  end

  describe "every public sign function refuses a weak public key before sign/2" do
    for function <- @sign_functions,
        {label, key} <- StrictEd25519Handles.weak_keys() do
      test "#{function}: #{label}" do
        WeakKey.reset()

        assert {:error, :invalid_key_handle} = grind(unquote(function), {WeakKey, unquote(key)})
        assert WeakKey.sign_calls() == 0
      end
    end
  end

  describe "every public sign function refuses a public key that is not on the curve" do
    for function <- @sign_functions do
      test "#{function}" do
        WeakKey.reset()
        handle = {WeakKey, StrictEd25519Handles.off_curve_key()}

        assert {:error, :invalid_key_handle} = run(unquote(function), 1, handle)
        assert WeakKey.sign_calls() == 0
      end
    end
  end

  describe "sign_key_transition refuses a weak successor key" do
    # The successor is caller input, not the signing key. BAP 0.8.0's producer owns the
    # check; the adapter surfaces it as the closed producer error.
    for {label, key} <- StrictEd25519Handles.weak_keys() do
      test label do
        {:ok, {_kid, _pub}} = HonestKey.key_identity(@seed)

        assert {:error, {:producer_error, :invalid}} =
                 Adapter.sign_key_transition(
                   %{
                     transition_id: "urn:test:transition:weak-next",
                     chain_id: "urn:test:chain:strict",
                     effective_at: @now,
                     next_key_id: "next-key-2026-08",
                     next_public_key: unquote(key)
                   },
                   {HonestKey, @seed}
                 )
      end
    end
  end

  describe "the self-check is strict" do
    test "the fixture signature is accepted by the raw backend and refused by rule S1" do
      message = "fixture message"
      {:ok, public_key} = NonceZero.public_key(@seed)
      {:ok, signature} = NonceZero.sign(message, @seed)

      assert Ed25519.acceptable_public_key?(public_key)
      assert :crypto.verify(:eddsa, :none, message, signature, [public_key, :ed25519])
      refute Ed25519.verify_strict(message, signature, public_key)
    end

    for function <- @sign_functions do
      test "#{function}: a genuine key signing with the nonce r = 0 is :signing_failed" do
        NonceZero.reset()

        assert {:error, :signing_failed} = run(unquote(function), 1, {NonceZero, @seed})
        assert NonceZero.sign_calls() == 1
      end
    end
  end

  describe "positive control: an honest, acceptable key still signs through every function" do
    for function <- @sign_functions do
      test "#{function}" do
        assert {:ok, %{} = signed} = run(unquote(function), 1, {HonestKey, @seed})
        assert map_size(signed) >= 1
        assert Enum.all?(Map.values(signed), &(is_binary(&1) and byte_size(&1) > 0))
      end
    end
  end
end
