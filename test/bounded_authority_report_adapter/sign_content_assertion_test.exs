defmodule BoundedAuthorityReportAdapter.SignContentAssertionTest do
  use ExUnit.Case, async: false

  alias BoundedAuthorityProtocol.ContentAssertion.V1, as: Content
  alias BoundedAuthorityProtocol.V1.{Bounds, HistoricalPublicKey}
  alias BoundedAuthorityReportAdapter, as: Adapter

  defmodule KeyHandle do
    @moduledoc false
    @behaviour BoundedAuthorityReportAdapter

    alias BoundedAuthorityProtocol.V1.Jwk

    @impl true
    def key_identity(pid) do
      Agent.get_and_update(pid, fn s ->
        next = %{s | snapshots: s.snapshots + 1, private: s.rotate_to || s.private}
        {{:ok, {s.kid, s.public}}, next}
      end)
    end

    @impl true
    def sign(message, pid) do
      Agent.get_and_update(pid, fn s ->
        signature = :crypto.sign(:eddsa, :none, message, [s.private, :ed25519])
        {{:ok, signature}, %{s | signs: s.signs + 1, message: message}}
      end)
    end

    @impl true
    def public_key(pid), do: Agent.get(pid, &{:ok, &1.public})

    @impl true
    def thumbprint(pid) do
      {:ok, public} = public_key(pid)
      Jwk.public_key_thumbprint_raw(public, %{})
    end
  end

  setup do
    {public, private} = :crypto.generate_key(:eddsa, :ed25519)

    {:ok, pid} =
      Agent.start_link(fn ->
        %{
          kid: "assertion-attestor",
          public: public,
          private: private,
          rotate_to: nil,
          snapshots: 0,
          signs: 0,
          message: nil
        }
      end)

    on_exit(fn -> if Process.alive?(pid), do: Agent.stop(pid) end)
    {:ok, content_digest} = Content.content_digest("exact external bytes", %{})

    input = %{
      jti: "urn:example:assertion:1",
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
    }

    expected = %Content.ExpectedContentAssertion{
      attestor: %HistoricalPublicKey{
        key_id: "assertion-attestor",
        public_key: public,
        valid_from: 90,
        valid_before: 210
      },
      issuer: input.iss,
      audience: input.aud,
      subject: input.sub,
      profile: input.profile,
      profile_digest: input.profile_digest,
      content_digest: input.content_digest,
      now: 150,
      bounds: Bounds.maximum()
    }

    %{input: input, expected: expected, pid: pid, handle: {KeyHandle, pid}}
  end

  test "typed signer returns a compact accepted by the public BAP verifier", c do
    assert {:ok, %{content_assertion: compact}} =
             Adapter.sign_content_assertion(c.input, c.handle, %{})

    assert {:ok, facts} = Content.verify_assertion(compact, c.expected)
    assert facts.verification == :signature_and_window
    assert facts.trust == :not_evaluated
    assert facts.content_digest == c.input.content_digest
    assert Agent.get(c.pid, &{&1.snapshots, &1.signs}) == {1, 1}

    assertion =
      struct!(Content.ContentAssertion, Map.put(c.input, :attestor_key_id, "assertion-attestor"))

    assert {:ok, signing} = Content.assertion_signing_input(assertion, %{})
    assert Agent.get(c.pid, & &1.message) == signing.message
  end

  test "signer owns kid; input and opts cannot substitute identity or fixed version", c do
    input =
      Map.merge(c.input, %{attestor_key_id: "forged", kid: "forged", public_key: <<0::256>>, v: 9})

    assert {:ok, %{content_assertion: compact}} =
             Adapter.sign_content_assertion(input, c.handle, %{
               attestor_key_id: "forged",
               role_attestation: :irrelevant
             })

    assert {:ok, decoded} = Content.decode_assertion(compact, %{})
    assert decoded.attestor_key_id == "assertion-attestor"
    assert decoded.version == 1
    assert {:ok, _} = Content.verify_assertion(compact, c.expected)
  end

  test "a real alternate signing key is rejected by the shared wrong-key guard", c do
    {_public, private} = :crypto.generate_key(:eddsa, :ed25519)
    Agent.update(c.pid, &%{&1 | private: private})
    assert {:error, :signing_failed} = Adapter.sign_content_assertion(c.input, c.handle, %{})
  end

  test "a real post-snapshot key rotation is rejected before compact return", c do
    {_public, private} = :crypto.generate_key(:eddsa, :ed25519)
    Agent.update(c.pid, &%{&1 | rotate_to: private})
    assert {:error, :signing_failed} = Adapter.sign_content_assertion(c.input, c.handle, %{})
    assert Agent.get(c.pid, &{&1.snapshots, &1.signs}) == {1, 1}
  end

  test "each required payload member must be present with its scalar shape", c do
    for {key, value} <- c.input do
      assert {:error, :invalid_content_assertion} =
               Adapter.sign_content_assertion(Map.delete(c.input, key), c.handle, %{})

      invalid = if is_binary(value), do: 123, else: "123"

      assert {:error, :invalid_content_assertion} =
               Adapter.sign_content_assertion(Map.put(c.input, key, invalid), c.handle, %{})
    end

    assert {:error, :invalid_content_assertion} =
             Adapter.sign_content_assertion(:invalid, c.handle, %{})

    assert Agent.get(c.pid, & &1.signs) == 0
  end

  test "BAP rejects digest, time, generation and bounds semantics before signing", c do
    for change <- [
          %{profile_digest: <<0>>},
          %{content_digest: <<0>>},
          %{prev: <<0>>},
          %{gen: 0},
          %{gen: 2},
          %{iat: 111},
          %{exp: 110},
          %{aud: ""}
        ] do
      assert {:error, {:producer_error, :invalid}} =
               Adapter.sign_content_assertion(Map.merge(c.input, change), c.handle, %{})
    end

    assert {:error, {:producer_error, :invalid}} =
             Adapter.sign_content_assertion(c.input, c.handle, %{bounds: %{compact_bytes: 1}})

    assert {:error, {:producer_error, :invalid}} =
             Adapter.sign_content_assertion(c.input, c.handle, %{bounds: %{content_bytes: 65_537}})

    assert Agent.get(c.pid, & &1.signs) == 0
  end

  test "invalid handles and malformed options fail closed without signing", c do
    assert {:error, :invalid_key_handle} = Adapter.sign_content_assertion(c.input, :invalid, %{})

    for opts <- [:defaults, nil, [bounds: %{compact_bytes: 1}], %URI{}] do
      assert {:error, :invalid_content_assertion} =
               Adapter.sign_content_assertion(c.input, c.handle, opts)
    end

    assert Agent.get(c.pid, & &1.signs) == 0
  end

  test "signature-byte tampering is rejected by the public verifier", c do
    assert {:ok, %{content_assertion: compact}} =
             Adapter.sign_content_assertion(c.input, c.handle, %{})

    [h, p, sig] = String.split(compact, ".")
    <<first, rest::binary>> = Base.url_decode64!(sig, padding: false)

    tampered =
      Enum.join(
        [h, p, Base.url_encode64(<<Bitwise.bxor(first, 1), rest::binary>>, padding: false)],
        "."
      )

    assert {:error, :invalid} = Content.verify_assertion(tampered, c.expected)
  end

  test "telemetry emits only closed object and result axes", c do
    id = {__MODULE__, make_ref()}
    events = for phase <- [:start, :stop], do: [:bounded_authority_report_adapter, :sign, phase]
    :ok = :telemetry.attach_many(id, events, &__MODULE__.capture/4, self())
    on_exit(fn -> :telemetry.detach(id) end)

    assert {:error, :invalid_content_assertion} =
             Adapter.sign_content_assertion(%{}, c.handle, %{})

    assert_receive {:event, [:bounded_authority_report_adapter, :sign, :start], %{count: 1},
                    %{object: :content_assertion} = metadata}

    assert map_size(metadata) == 1

    assert_receive {:event, [:bounded_authority_report_adapter, :sign, :stop],
                    %{duration: duration},
                    %{object: :content_assertion, result_class: :invalid_input} = metadata}

    assert map_size(metadata) == 2
    assert is_integer(duration) and duration >= 0
  end

  def capture(event, measurements, metadata, pid),
    do: send(pid, {:event, event, measurements, metadata})
end
