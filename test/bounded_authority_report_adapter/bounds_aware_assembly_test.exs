defmodule BoundedAuthorityReportAdapter.BoundsAwareAssemblyTest do
  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.V1
  alias BoundedAuthorityReportAdapter.Keys.RawKey
  alias BoundedAuthorityReportAdapter.TestKeys

  @now 1_750_000_000
  @operation "report_external_materialization"

  test "every signing path rejects a compact ceiling below its produced artifact" do
    for {kind, sign} <- signing_cases() do
      assert {:ok, compact} = sign.(%{}), inspect(kind)

      assert {:error, {:producer_error, :invalid}} =
               sign.(%{compact_bytes: byte_size(compact) - 1}),
             inspect(kind)
    end
  end

  test "the shared tail and all four callers carry one bounds binding into assemble_compact/3" do
    source = File.read!("lib/bounded_authority_report_adapter.ex")

    shared_tail_and_calls =
      Regex.scan(
        ~r/sign_and_assemble\(\s*key_handle,\s*signing_input,\s*(?:holder_public_key|public_key|current_public_key),\s*bounds\s*\)/,
        source
      )

    assert length(shared_tail_and_calls) == 5

    assert source =~
             "BoundedAuthorityProtocol.V1.assemble_compact(signing_input, signature, bounds)"

    refute source =~ "BoundedAuthorityProtocol.V1.assemble_compact(signing_input, signature)"
  end

  defp signing_cases do
    [
      {:proof, &sign_proof/1},
      {:boundary_anchor, &sign_anchor/1},
      {:grant, &sign_grant/1},
      {:key_transition, &sign_key_transition/1}
    ]
  end

  defp sign_proof(bounds) do
    {holder_public_key, _holder_private_key} = TestKeys.holder_keypair()

    {grant_compact, _issuer_public_key} =
      TestKeys.issuer_signed_grant_compact(
        TestKeys.holder_thumbprint_raw(holder_public_key),
        issued_at: @now - 100,
        not_before: @now - 100,
        expires_at: @now + 3_600
      )

    report = %{
      grant_compact: grant_compact,
      operation: @operation,
      method: "POST",
      target_uri: "https://api.example.test/invoke",
      invocation_id: "123e4567-e89b-42d3-a456-426614174000",
      cast_arguments: {:object, [{"record", {:string, "example"}}]},
      nonce: "bounds-aware"
    }

    case BoundedAuthorityReportAdapter.sign_report(report, holder_handle(), %{
           bounds: bounds,
           issued_at: @now - 50,
           proof_id: "urn:example:proof:bounds-aware"
         }) do
      {:ok, %{proof: compact}} -> {:ok, compact}
      error -> error
    end
  end

  defp sign_anchor(bounds) do
    input = %{
      anchor_id: "urn:example:anchor:bounds-aware",
      chain_id: "urn:example:chain:bounds-aware",
      sequence: 1,
      chain_hash: :crypto.hash(:sha256, "bounds-aware-anchor")
    }

    case BoundedAuthorityReportAdapter.sign_anchor(input, holder_handle(), %{
           bounds: bounds,
           anchored_at: @now
         }) do
      {:ok, %{anchor: compact}} -> {:ok, compact}
      error -> error
    end
  end

  defp sign_grant(bounds) do
    {holder_public_key, _holder_private_key} = TestKeys.holder_keypair()

    input = %{
      issuer: "https://issuer.example.test",
      grant_id: "urn:example:grant:bounds-aware",
      audiences: ["https://verifier.example.test"],
      issued_at: @now - 100,
      not_before: @now - 100,
      expires_at: @now + 3_600,
      holder_thumbprint: TestKeys.holder_thumbprint_raw(holder_public_key),
      operations: [%V1.Operation{name: @operation, selectors: [:all]}]
    }

    case BoundedAuthorityReportAdapter.sign_grant(input, issuer_handle(), %{bounds: bounds}) do
      {:ok, %{grant: compact}} -> {:ok, compact}
      error -> error
    end
  end

  defp sign_key_transition(bounds) do
    {next_public_key, _next_private_key} =
      :crypto.generate_key(:eddsa, :ed25519, <<3::unsigned-integer-size(256)>>)

    input = %{
      transition_id: "urn:example:transition:bounds-aware",
      chain_id: "urn:example:chain:bounds-aware",
      effective_at: @now,
      next_key_id: "next-key-bounds-aware",
      next_public_key: next_public_key
    }

    case BoundedAuthorityReportAdapter.sign_key_transition(input, holder_handle(), %{
           bounds: bounds
         }) do
      {:ok, %{key_transition: compact}} -> {:ok, compact}
      error -> error
    end
  end

  defp holder_handle, do: {RawKey, TestKeys.holder_keypair()}
  defp issuer_handle, do: {GrantIssuerHandle, TestKeys.issuer_keypair()}
end
