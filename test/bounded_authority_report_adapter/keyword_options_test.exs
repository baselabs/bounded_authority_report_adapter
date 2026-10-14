defmodule BoundedAuthorityReportAdapter.KeywordOptionsHandle do
  @moduledoc false
  # Test-only real-key handle. The term carries the key pair. P-256 signatures are memoized
  # per key and message in the calling process, so two calls that produce the same signing
  # input return byte-identical compacts (ECDSA is randomized; Ed25519 is not).
  @behaviour BoundedAuthorityReportAdapter

  @impl true
  def sign(message, %{suite: :ed25519, private: private}),
    do: {:ok, :crypto.sign(:eddsa, :none, message, [private, :ed25519])}

  def sign(message, %{suite: :p256, private: private}) do
    key = {__MODULE__, :crypto.hash(:sha256, private <> message)}

    signature =
      Process.get(key) ||
        (
          der = :crypto.sign(:ecdsa, :sha256, message, [private, :prime256v1])

          <<0x30, _length, 0x02, r_size, r::binary-size(r_size), 0x02, s_size,
            s::binary-size(s_size)>> = der

          raw =
            <<:binary.decode_unsigned(r)::unsigned-big-256,
              :binary.decode_unsigned(s)::unsigned-big-256>>

          Process.put(key, raw)
          raw
        )

    {:ok, signature}
  end

  @impl true
  def public_key(%{public: public}), do: {:ok, public}

  @impl true
  def thumbprint(%{suite: suite, public: public}) do
    jwk_module =
      if suite == :ed25519,
        do: BoundedAuthorityProtocol.V1.Jwk,
        else: BoundedAuthorityProtocol.V3.EcJwk

    with {:ok, jwk} <- jwk_module.encode_public(public, %{}),
         {:ok, thumbprint} <- jwk_module.thumbprint(jwk, %{}) do
      {:ok, Base.url_decode64!(thumbprint, padding: false)}
    end
  end

  @impl true
  def key_identity(%{key_id: key_id, public: public}), do: {:ok, {key_id, public}}

  @impl true
  def signing_identity(%{role: role, key_id: key_id, public: public}),
    do: {:ok, {role, key_id, public}}
end

defmodule BoundedAuthorityReportAdapter.KeywordOptionsTest do
  @moduledoc """
  Every `sign_*/3` takes its options as a map or as a keyword list, and the two forms are the
  same call: a keyword list is normalized to the equivalent map at the boundary. A list that
  is not a keyword list with unique atom keys is refused with the entry point's closed input
  error, before any key is resolved or anything is signed.
  """

  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.ContentAssertion
  alias BoundedAuthorityProtocol.RoleAttestation
  alias BoundedAuthorityProtocol.V1
  alias BoundedAuthorityProtocol.V3, as: ProtocolV3
  alias BoundedAuthorityReportAdapter, as: Adapter
  alias BoundedAuthorityReportAdapter.KeywordOptionsHandle, as: Handle
  alias BoundedAuthorityReportAdapter.V3

  @now 1_750_000_000
  @iterations 30

  setup_all do
    key = fn suite, key_id, role, seed ->
      {public, private} =
        case suite do
          :ed25519 -> :crypto.generate_key(:eddsa, :ed25519, :crypto.hash(:sha256, seed))
          :p256 -> :crypto.generate_key(:ecdh, :prime256v1, :crypto.hash(:sha256, seed))
        end

      %{suite: suite, key_id: key_id, role: role, public: public, private: private}
    end

    keys = %{
      issuer: key.(:ed25519, "issuer-key-1", :issuer, "issuer"),
      holder: key.(:ed25519, "holder-key-1", :holder, "holder"),
      next: key.(:ed25519, "next-key-1", :holder, "next"),
      attestor: key.(:ed25519, "attestor-key-1", :holder, "attestor"),
      ec_issuer: key.(:p256, "ec-issuer-key-1", :issuer, "ec-issuer"),
      ec_holder: key.(:p256, "ec-holder-key-1", :holder, "ec-holder"),
      ec_next: key.(:p256, "ec-next-key-1", :holder, "ec-next")
    }

    {:ok, %{grant: grant}} =
      Adapter.sign_grant(grant_input(keys.holder, V1.Operation), {Handle, keys.issuer})

    {:ok, %{grant: ec_grant}} =
      V3.sign_grant(grant_input(keys.ec_holder, ProtocolV3.Operation), {Handle, keys.ec_issuer})

    %{keys: keys, grant: grant, ec_grant: ec_grant}
  end

  test "a keyword :issued_at sets the proof's issued-at time", %{keys: keys, grant: grant} do
    issued_at = @now - 42

    assert {:ok, %{proof: proof}} =
             Adapter.sign_report(report(grant, "https://api.example/x"), {Handle, keys.holder},
               issued_at: issued_at
             )

    assert {:ok, %{issued_at: ^issued_at}} = V1.decode_proof(proof, %{})
  end

  test "a keyword :role_attestation runs the gate exactly as the map form does", %{keys: keys} do
    attestation = attestation(keys, "holder")
    input = grant_input(keys.holder, V1.Operation)

    for opts <- [%{role_attestation: attestation}, [role_attestation: attestation]] do
      assert Adapter.sign_grant(input, {Handle, keys.issuer}, opts) ==
               {:error, :invalid_role_attestation}
    end
  end

  test "a list that is not a keyword list with unique atom keys is the closed input error",
       context do
    malformed = [
      [:bounds],
      [{"bounds", %{}}],
      [{:bounds, %{}}, {:bounds, %{}}],
      [{:bounds, %{}} | :improper_tail],
      [{:bounds, %{}, :extra}]
    ]

    for {name, call, input_error} <- entry_points(context), opts <- malformed do
      assert call.(opts) == {:error, input_error},
             "#{name} with #{inspect(opts)} did not return {:error, #{inspect(input_error)}}"
    end
  end

  test "map and keyword options produce byte-identical results (property)", context do
    :rand.seed(:exsss, {1, 2, 3})

    for {name, call, _input_error} <- entry_points(context) do
      results =
        for iteration <- 1..@iterations do
          options = random_options(name, iteration, context)
          keyword = Enum.shuffle(options)
          result = call.(Map.new(options))

          assert result == call.(keyword),
                 "#{name}: the map and keyword forms of #{inspect(options)} differ"

          result
        end

      # Non-vacuity: the comparison covered signed output, not only errors.
      assert Enum.any?(results, &match?({:ok, _}, &1)), "#{name}: no iteration signed"
    end
  end

  ## entry points and options

  defp entry_points(%{keys: keys, grant: grant, ec_grant: ec_grant}) do
    {:ok, content_digest} = ContentAssertion.V1.content_digest("survey data", %{})

    assertion = %{
      jti: "urn:example:assertion:1",
      iss: "urn:example:issuer",
      aud: "urn:example:audience",
      sub: "urn:example:subject",
      profile: "urn:example:profile/1",
      profile_digest: :crypto.hash(:sha256, "profile"),
      content_digest: content_digest,
      gen: 1,
      prev: <<0::256>>,
      iat: @now,
      nbf: @now,
      exp: @now + 3600
    }

    holder = {Handle, keys.holder}
    ec_holder = {Handle, keys.ec_holder}

    [
      {"sign_report", &Adapter.sign_report(report(grant, "https://api.example/x"), holder, &1),
       :invalid_report},
      {"sign_local_loopback_report",
       &Adapter.sign_local_loopback_report(report(grant, "http://127.0.0.1:4000/x"), holder, &1),
       :invalid_report},
      {"sign_grant",
       &Adapter.sign_grant(grant_input(keys.holder, V1.Operation), {Handle, keys.issuer}, &1),
       :invalid_grant},
      {"sign_anchor", &Adapter.sign_anchor(anchor_input(), holder, &1), :invalid_anchor},
      {"sign_key_transition",
       &Adapter.sign_key_transition(transition_input(keys.next), holder, &1),
       :invalid_transition},
      {"sign_content_assertion", &Adapter.sign_content_assertion(assertion, holder, &1),
       :invalid_content_assertion},
      {"V3.sign_report",
       &V3.sign_report(report(ec_grant, "https://api.example/x"), ec_holder, &1),
       :invalid_report},
      {"V3.sign_grant",
       &V3.sign_grant(
         grant_input(keys.ec_holder, ProtocolV3.Operation),
         {Handle, keys.ec_issuer},
         &1
       ), :invalid_grant},
      {"V3.sign_anchor", &V3.sign_anchor(anchor_input(), ec_holder, &1), :invalid_anchor},
      {"V3.sign_key_transition",
       &V3.sign_key_transition(transition_input(keys.ec_next), ec_holder, &1),
       :invalid_transition}
    ]
  end

  # A random option set for one entry point. Options that default to a fresh value (the
  # proof's id and time, the anchor's time) are always given, so that two calls can agree;
  # every other option is present or absent at random, with random values.
  defp random_options(name, iteration, %{keys: keys}) do
    bounds = Enum.random([%{}, V1.Bounds.maximum(), %{compact_bytes: 64}])
    maybe = fn option -> if :rand.uniform(2) == 1, do: [option], else: [] end

    case name do
      report when report in ["sign_report", "sign_local_loopback_report", "V3.sign_report"] ->
        [
          issued_at: @now - :rand.uniform(200),
          proof_id: "urn:example:proof:#{iteration}-#{:rand.uniform(1_000_000)}"
        ] ++ maybe.({:bounds, bounds})

      anchor when anchor in ["sign_anchor", "V3.sign_anchor"] ->
        [anchored_at: @now - :rand.uniform(200)] ++ maybe.({:bounds, bounds})

      "sign_grant" ->
        role = Enum.random(["issuer", "holder"])
        maybe.({:bounds, bounds}) ++ maybe.({:role_attestation, attestation(keys, role)})

      "V3.sign_grant" ->
        maybe.({:bounds, bounds}) ++ maybe.({:role_attestation, :anything})

      _bounds_only ->
        maybe.({:bounds, bounds})
    end
  end

  ## fixtures

  defp grant_input(holder, operation_module) do
    {:ok, holder_thumbprint} = Handle.thumbprint(holder)

    %{
      issuer: "https://issuer.example",
      grant_id: "urn:example:grant:1",
      audiences: ["https://api.example"],
      issued_at: @now - 600,
      not_before: @now - 600,
      expires_at: @now + 3600,
      holder_thumbprint: holder_thumbprint,
      operations: [struct(operation_module, name: "run_job", selectors: [:all])]
    }
  end

  defp report(grant, target_uri) do
    %{
      grant_compact: grant,
      operation: "run_job",
      method: "POST",
      target_uri: target_uri,
      invocation_id: "2b3c4d5e-6f70-4a8b-9c0d-1e2f3a4b5c6d",
      cast_arguments: {:object, [{"job", {:string, "nightly-backup"}}]},
      nonce: "nonce-1"
    }
  end

  defp anchor_input do
    %{
      anchor_id: "urn:example:anchor:1",
      chain_id: "urn:example:chain:jobs",
      sequence: 1,
      chain_hash: :crypto.hash(:sha256, "job log entry 1")
    }
  end

  defp transition_input(next) do
    %{
      transition_id: "urn:example:transition:1",
      chain_id: "urn:example:chain:jobs",
      effective_at: @now,
      next_key_id: next.key_id,
      next_public_key: next.public
    }
  end

  # A role attestation for the issuer key, signed by the attestor with the protocol
  # package's documented producer and assembler.
  defp attestation(keys, role) do
    {:ok, input} =
      RoleAttestation.V1.attestation_signing_input(
        %RoleAttestation.V1.RoleAttestation{
          attestor_key_id: keys.attestor.key_id,
          jti: "urn:example:attestation:#{role}",
          key_id: keys.issuer.key_id,
          public_key: keys.issuer.public,
          role: role,
          nbf: @now - 600,
          exp: @now + 3600
        },
        %{}
      )

    signature = :crypto.sign(:eddsa, :none, input.message, [keys.attestor.private, :ed25519])
    {:ok, compact} = RoleAttestation.V1.assemble_compact(input, signature)

    %{
      compact: compact,
      attestor: %V1.HistoricalPublicKey{
        key_id: keys.attestor.key_id,
        public_key: keys.attestor.public,
        valid_from: @now - 3600,
        valid_before: @now + 3600
      },
      now: @now
    }
  end
end
