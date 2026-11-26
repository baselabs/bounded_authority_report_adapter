defmodule BoundedAuthorityReportAdapter.ContentSigner do
  @moduledoc false

  alias BoundedAuthorityProtocol.ActionApproval.V1, as: Approval
  alias BoundedAuthorityProtocol.ContentAssertion.ES256.V1, as: ES256
  alias BoundedAuthorityProtocol.ContentAssertion.V1, as: Ed25519
  alias BoundedAuthorityProtocol.V1.HistoricalPublicKey
  alias BoundedAuthorityReportAdapter.Options

  @approval_profile "bap-action-approval/1"
  @binary_fields [:jti, :iss, :aud, :sub, :profile, :profile_digest, :content_digest, :prev]
  @integer_fields [:gen, :iat, :nbf, :exp]

  @doc false
  def produce(input, {key_id, public_key}, bounds, suite, sign) do
    {protocol, assertion_type, expected_type} = profile(suite)

    with {:ok, assertion} <- assertion(input, key_id, assertion_type),
         {:ok, signing_input} <- producer(protocol.assertion_signing_input(assertion, bounds)),
         {:ok, signature} <- sign.(signing_input.message),
         {:ok, compact} <- producer(protocol.assemble_compact(signing_input, signature, bounds)),
         :ok <- verify(protocol, compact, assertion, public_key, bounds, expected_type) do
      {:ok, %{content_assertion: compact}}
    end
  end

  @doc false
  def approval(input, opts, sign) do
    with {:ok, opts} <- approval_options(opts),
         {:ok, record, claims} <- approval_input(input),
         bounds = Map.get(opts, :bounds, %{}),
         record_bounds = Map.get(opts, :record_bounds, %{}),
         canonicalize? = Map.get(opts, :canonicalize_resources, false),
         {:ok, bytes} <-
           producer(Approval.encode_record(record, bounds, record_bounds, canonicalize?)),
         {:ok, digest} <- producer(Ed25519.content_digest(bytes, bounds)),
         {:ok, %{content_assertion: compact}} <-
           sign.(approval_assertion(claims, record, digest), bounds) do
      {:ok, %{record: bytes, content_assertion: compact}}
    end
  end

  @doc false
  def snapshot({module, handle}, accept_key, callback) when is_atom(module) do
    case callback.(module, :key_snapshot, [handle]) do
      {:ok, {key_id, public_key, reference}} when is_binary(key_id) and byte_size(key_id) > 0 ->
        with {:ok, key} <- accept_key.(public_key) do
          {:ok, {{key_id, key}, {module, reference}}}
        end

      _invalid ->
        {:error, :invalid_key_handle}
    end
  end

  def snapshot(_handle, _accept_key, _callback), do: {:error, :invalid_key_handle}

  defp profile(:eddsa), do: {Ed25519, Ed25519.ContentAssertion, Ed25519.ExpectedContentAssertion}
  defp profile(:es256), do: {ES256, ES256.ContentAssertion, ES256.ExpectedContentAssertion}

  defp assertion(input, key_id, type) when is_map(input) do
    if Enum.all?(@binary_fields, &is_binary(Map.get(input, &1))) and
         Enum.all?(@integer_fields, &is_integer(Map.get(input, &1))) do
      fields =
        input |> Map.take(@binary_fields ++ @integer_fields) |> Map.put(:attestor_key_id, key_id)

      {:ok, struct!(type, fields)}
    else
      {:error, :invalid_content_assertion}
    end
  end

  defp assertion(_input, _key_id, _type), do: {:error, :invalid_content_assertion}

  defp verify(protocol, compact, assertion, public_key, bounds, expected_type) do
    # Use the signed window and the captured key to check the returned bytes.
    # The relying party supplies its own trusted time and key window.
    expected =
      struct!(expected_type,
        attestor: %HistoricalPublicKey{
          key_id: assertion.attestor_key_id,
          public_key: public_key,
          valid_from: assertion.iat,
          valid_before: assertion.exp
        },
        issuer: assertion.iss,
        audience: assertion.aud,
        subject: assertion.sub,
        profile: assertion.profile,
        profile_digest: assertion.profile_digest,
        content_digest: assertion.content_digest,
        now: assertion.nbf,
        bounds: bounds
      )

    case protocol.verify_assertion(compact, expected) do
      {:ok, _facts} -> :ok
      {:error, :invalid} -> {:error, :signing_failed}
    end
  end

  defp approval_options(opts) do
    case Options.normalize(opts, Options.schema(:action_approval)) do
      {:ok, opts} -> {:ok, opts}
      {:error, _key} -> {:error, :invalid_action_approval}
    end
  end

  defp approval_input(
         %{
           record: %Approval.Record{} = record,
           jti: jti,
           iss: iss,
           aud: aud,
           iat: iat,
           nbf: nbf,
           exp: exp
         } = input
       )
       when map_size(input) == 7 and is_binary(jti) and is_binary(iss) and is_binary(aud) and
              is_integer(iat) and is_integer(nbf) and is_integer(exp) do
    {:ok, record, Map.delete(input, :record)}
  end

  defp approval_input(_input), do: {:error, :invalid_action_approval}

  defp approval_assertion(claims, record, digest) do
    Map.merge(claims, %{
      sub: record.request_id,
      profile: @approval_profile,
      profile_digest: Approval.profile_digest(),
      content_digest: digest,
      gen: 1,
      prev: <<0::256>>
    })
  end

  defp producer({:ok, value}), do: {:ok, value}
  defp producer({:error, :invalid}), do: {:error, {:producer_error, :invalid}}
end
