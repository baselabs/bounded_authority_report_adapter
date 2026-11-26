defmodule BoundedAuthorityReportAdapter.ContentSignerParityTest do
  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.ActionApproval.V1, as: Approval
  alias BoundedAuthorityProtocol.Conformance.Cli
  alias BoundedAuthorityProtocol.ContentAssertion.ES256.V1, as: ES256
  alias BoundedAuthorityProtocol.ContentAssertion.V1, as: Ed25519
  alias BoundedAuthorityProtocol.V1.HistoricalPublicKey
  alias BoundedAuthorityReportAdapter, as: Adapter
  alias BoundedAuthorityReportAdapter.TestKeys

  @kid "approver-key"
  @approval_root "content-profiles/action-approval/v1"
  @es256_root "attestation-profiles/content-assertion-es256/v1"
  @ed25519_root "attestation-profiles/content-assertion/v1"
  @indexes %{
    @approval_root => "5384b8680fb6757360696c6889c5d6b3b706e8728edccae6dd0c5c468a819a64",
    @es256_root => "2bb41b8fbc9fbdc0267f72976d56280be0541420e4c14241ca622f1dd071d0cb",
    @ed25519_root => "14b7436ccf7cc91fece52a1578c3760df6720a93494d147ee5ab523e2ce21876"
  }
  @order TestKeys.ec_n()

  defmodule Custody do
    @moduledoc false
    @behaviour BoundedAuthorityReportAdapter

    alias BoundedAuthorityReportAdapter.TestKeys

    @order TestKeys.ec_n()

    @impl true
    def key_snapshot({pid, :current}) do
      Agent.get_and_update(pid, fn state ->
        result = {:ok, {state.kid, state.first.public, {pid, :first}}}
        {result, %{state | snapshots: state.snapshots + 1, active: :second}}
      end)
    end

    @impl true
    def key_identity(pid), do: {:ok, {Agent.get(pid, & &1.kid), public(pid)}}

    @impl true
    def public_key(pid), do: {:ok, public(pid)}

    @impl true
    def thumbprint(pid), do: BoundedAuthorityReportAdapter.public_key_thumbprint(public(pid))

    @impl true
    def sign(message, pid) when is_pid(pid), do: sign(message, {pid, :first})

    def sign(message, {pid, version}) do
      {suite, key, mode} =
        Agent.get_and_update(pid, fn state ->
          selected = if state.mode == :wrong_key, do: :second, else: version

          {{state.suite,
            Map.fetch!(state, if(selected == :current, do: state.active, else: selected)),
            state.mode}, %{state | calls: [{version, message} | state.calls]}}
        end)

      case mode do
        :failure ->
          {:error, :provider_failure}

        :raise ->
          raise "provider failure"

        :throw ->
          throw(:provider_failure)

        :exit ->
          exit(:provider_failure)

        :der ->
          {:ok, :crypto.sign(:ecdsa, :sha256, message, [key.private, :prime256v1])}

        {:raw, signature} ->
          {:ok, signature}

        :double_hash ->
          {:ok, TestKeys.ec_sign_raw_low_s(:crypto.hash(:sha256, message), key.private)}

        _ ->
          {:ok, signature(suite, message, key.private)}
      end
    end

    defp signature(:eddsa, message, private),
      do: :crypto.sign(:eddsa, :none, message, [private, :ed25519])

    defp signature(:es256, message, private) do
      <<r::256, s::256>> = TestKeys.ec_sign_raw_low_s(message, private)
      <<r::256, @order - s::256>>
    end

    defp public(pid), do: Agent.get(pid, & &1.first.public)
  end

  setup do
    %{
      eddsa: start_custody(:eddsa),
      es256: start_custody(:es256)
    }
  end

  test "candidate profile indexes and every indexed file match the immutable corpus" do
    for {root, expected} <- @indexes do
      bytes = fixture_bytes(root, "index.json")
      assert sha256_hex(bytes) == expected, root

      for %{"path" => file, "sha256" => expected} <- :json.decode(bytes)["files"] do
        assert sha256_hex(fixture_bytes(root, file)) == expected, file
      end
    end
  end

  @tag :tmp_dir
  test "the reference verifier executes every frozen Ed25519 content-assertion verdict", %{
    tmp_dir: tmp_dir
  } do
    report = Path.join(tmp_dir, "legacy.json")

    assert Cli.run(["--corpus", fixture_dir(@ed25519_root), "--report", report]) == 0

    assert %{
             "agreement" => true,
             "agreed" => 154,
             "disagreed" => 0,
             "total" => 154,
             "index_sha256_base64url" => "FLdDbM98yR_s5SoVeMN2DfZyCpNJTRR-5atSPiziGHY"
           } = report |> File.read!() |> :json.decode()
  end

  test "ES256 signs exact corpus JWS input, pins one version and emits low-S", %{es256: pid} do
    vector = fixture(@es256_root, "profile.json")["signing"]
    input = assertion_input(vector["payload"])

    assert {:ok, %{content_assertion: compact}} =
             Adapter.V3.sign_content_assertion(input, handle(pid))

    [protected, payload, signature] = String.split(compact, ".")
    assert protected == vector["expected"]["protected_segment"]
    assert payload == vector["expected"]["payload_segment"]

    assert Agent.get(pid, &{&1.snapshots, &1.active, &1.calls}) ==
             {1, :second, [{:first, vector["expected"]["message"]}]}

    assert <<r::256, s::256>> = raw(signature)
    assert r > 0 and r < @order
    assert s > 0 and s <= div(@order, 2)
    assert {:ok, _} = ES256.verify_assertion(compact, expected(:es256, input, pid))
    assert_independent(compact, :es256, key(pid), input)
  end

  test "Ed25519 standalone bytes match the frozen signing input and original raw assembly", %{
    eddsa: pid
  } do
    vector = approval_vector("eddsa-verified")
    [header, payload, _signature] = String.split(vector["compact"], ".")
    input = payload |> raw() |> :json.decode() |> assertion_input()
    message = header <> "." <> payload
    private = Agent.get(pid, & &1.first.private)
    signature = :crypto.sign(:eddsa, :none, message, [private, :ed25519])
    previous_compact = message <> "." <> Base.url_encode64(signature, padding: false)

    assert {:ok, %{content_assertion: ^previous_compact}} =
             Adapter.sign_content_assertion(input, {Custody, pid})

    assert {:ok, _} = Ed25519.verify_assertion(previous_compact, expected(:eddsa, input, pid))
    assert_independent(previous_compact, :eddsa, key(pid), input)
  end

  test "both approval producers bind the same exact record and refuse foreign suites", state do
    signed =
      for suite <- [:eddsa, :es256], into: %{} do
        vector = approval_vector(Atom.to_string(suite) <> "-verified")
        bytes = raw(vector["record"])
        assert {:ok, record} = Approval.decode_record(bytes)
        pid = Map.fetch!(state, suite)
        signer = signer(suite)
        verifier = verifier(suite)
        input = approval_input(record)

        assert {:ok, %{record: ^bytes, content_assertion: compact}} =
                 signer.sign_action_approval(input, handle(pid))

        assert Enum.take(String.split(compact, "."), 2) ==
                 Enum.take(String.split(vector["compact"], "."), 2)

        context = context(suite, pid, record)
        assert {:ok, facts} = verifier.(bytes, compact, context)
        assert facts.record == record
        assert facts.assertion.sub == record.request_id
        assert facts.assertion.profile_digest == Approval.profile_digest()
        assert facts.trust == :not_evaluated
        assert_independent(compact, suite, key(pid), approval_claims(input, bytes))

        assert {:error, :malformed} = verifier.(bytes <> "\n", compact, context)
        assert {:error, :bad_signature} = verifier.(bytes, flip_signature(compact), context)

        assert {:error, :request_mismatch} =
                 verifier.(bytes, compact, %{context | revision_digest: <<9::256>>})

        assert {:error, :scope_mismatch} =
                 verifier.(bytes, compact, %{
                   context
                   | resources: ["different" | record.resources]
                 })

        assert {:error, :role_not_permitted} =
                 verifier.(bytes, compact, %{context | roles: ["other"]})

        {suite, {bytes, compact, context}}
      end

    {bytes, eddsa, ed_context} = signed.eddsa
    {^bytes, es256, ec_context} = signed.es256
    assert {:error, :unsupported_algorithm} = Approval.verify_eddsa(bytes, es256, ed_context)
    assert {:error, :unsupported_algorithm} = Approval.verify_es256(bytes, eddsa, ec_context)

    [_, payload, _] = String.split(eddsa, ".")
    input = payload |> raw() |> :json.decode() |> assertion_input()

    assert {:error, :invalid} =
             Ed25519.verify_assertion(es256, expected(:eddsa, input, state.eddsa))

    assert {:error, :invalid} =
             ES256.verify_assertion(eddsa, expected(:es256, input, state.es256))
  end

  test "record corpus checks explicit authoring, byte order, exact digests and tightened bounds",
       %{
         eddsa: pid
       } do
    for vector <- fixture(@approval_root, "record-cases.json") do
      opts = %{
        bounds: atom_keys(vector["ca_bounds"]),
        record_bounds: atom_keys(vector["bounds"]),
        canonicalize_resources: vector["canonicalize"]
      }

      case {vector, vector["expected"]} do
        {%{"wire" => wire}, "invalid"} ->
          assert {:error, :invalid} =
                   Approval.decode_record(raw(wire), opts.bounds, opts.record_bounds),
                 vector["id"]

        {%{"wire" => wire}, success} ->
          assert {:ok, record} =
                   Approval.decode_record(raw(wire), opts.bounds, opts.record_bounds)

          assert_record(pid, record, opts, success, vector["id"])

        {%{"author" => author}, result} ->
          record =
            author
            |> Map.delete("v")
            |> Map.update!("revision_digest", &raw/1)
            |> atom_keys()
            |> then(&struct!(Approval.Record, &1))

          assert_record(pid, record, opts, result, vector["id"])
      end
    end
  end

  test "signature mutants cannot escape assembly and captured-key verification", %{es256: pid} do
    input = fixture(@es256_root, "profile.json")["signing"]["payload"] |> assertion_input()

    assert {:ok, %{content_assertion: compact}} =
             Adapter.V3.sign_content_assertion(input, handle(pid))

    assert_independent(compact, :es256, key(pid), input)

    for mode <- [:wrong_key, :double_hash, :der, :failure, :raise, :throw, :exit] do
      Agent.update(pid, &%{&1 | mode: mode})

      assert {:error, :signing_failed} = Adapter.V3.sign_content_assertion(input, handle(pid)),
             inspect(mode)
    end

    for vector <- fixture(@es256_root, "assembly-cases.json"),
        vector["id"] in ~w(assembly-r-zero assembly-s-zero assembly-r-order assembly-s-order) do
      Agent.update(pid, &%{&1 | mode: {:raw, raw(vector["signature"])}})

      assert {:error, :signing_failed} = Adapter.V3.sign_content_assertion(input, handle(pid)),
             vector["id"]
    end
  end

  test "invalid approval input, version snapshot and assertion bounds fail closed", state do
    vector = approval_vector("es256-verified")
    assert {:ok, record} = Approval.decode_record(raw(vector["record"]))
    input = approval_input(record)

    for {signer, pid, other} <- [
          {Adapter, state.eddsa, state.es256},
          {Adapter.V3, state.es256, state.eddsa}
        ] do
      assert {:error, :invalid_key_handle} = signer.sign_action_approval(input, handle(other))

      assert {:error, :invalid_key_handle} =
               signer.sign_action_approval(input, {NoSuchHandle, :ref})

      assert {:error, :invalid_action_approval} =
               signer.sign_action_approval(Map.put(input, :sub, "different"), handle(pid))

      assert {:error, :invalid_action_approval} =
               signer.sign_action_approval(input, handle(pid), canonicalize_resources: :yes)

      assert {:error, {:producer_error, :invalid}} =
               signer.sign_action_approval(input, handle(pid), bounds: %{compact_bytes: 1})

      assert Agent.get(pid, & &1.calls) == []
      Agent.update(pid, &%{&1 | mode: :wrong_key})
      assert {:error, :signing_failed} = signer.sign_action_approval(input, handle(pid))
    end
  end

  test "invalid raw signatures produce the closed signing failure and custody telemetry", state do
    vector = approval_vector("es256-verified")
    assert {:ok, record} = Approval.decode_record(raw(vector["record"]))
    input = approval_input(record)
    id = {__MODULE__, make_ref()}
    parent = self()
    event = [:bounded_authority_report_adapter, :sign, :stop]
    :ok = :telemetry.attach(id, event, &__MODULE__.capture/4, parent)
    on_exit(fn -> :telemetry.detach(id) end)

    for {suite, signature} <- [eddsa: <<1, 0::504>>, es256: <<1::256, 1::256>>] do
      pid = Map.fetch!(state, suite)
      Agent.update(pid, &%{&1 | mode: {:raw, signature}})
      signer = signer(suite)

      assert {:error, :signing_failed} = signer.sign_action_approval(input, handle(pid))
      assert_receive {:result, ^event, %{object: :action_approval, result_class: :signing_failed}}
    end
  end

  def capture(event, _measurements, metadata, parent) when parent == self(),
    do: send(parent, {:result, event, metadata})

  def capture(_event, _measurements, _metadata, _parent), do: :ok

  defp assert_independent(compact, suite, key, input) do
    [header, payload, signature] = String.split(compact, ".")
    {alg, typ} = header_fields(suite)
    assert :json.decode(raw(header)) == %{"alg" => alg, "typ" => typ, "kid" => key.key_id}

    claims =
      Map.new(input, fn {field, value} -> {Atom.to_string(field), claim(field, value)} end)

    assert :json.decode(raw(payload)) == Map.put(claims, "v", 1)

    for segment <- [header, payload, signature] do
      assert Base.url_encode64(raw(segment), padding: false) == segment
    end

    message = header <> "." <> payload
    assert otp_verifies?(suite, message, raw(signature), key.public_key)
    refute otp_verifies?(suite, message <> "x", raw(signature), key.public_key)
  end

  defp header_fields(:eddsa), do: {"EdDSA", "ba+content-assertion"}
  defp header_fields(:es256), do: {"ES256", "ba+content-assertion-es256"}

  defp claim(field, value) when field in [:profile_digest, :content_digest, :prev],
    do: Base.url_encode64(value, padding: false)

  defp claim(_field, value), do: value

  defp approval_claims(%{record: record} = input, bytes) do
    profile = fixture(@approval_root, "profile.json")
    preimage = Base.decode16!(profile["profile_preimage_hex"], case: :lower)

    input
    |> Map.delete(:record)
    |> Map.merge(%{
      sub: record.request_id,
      profile: "bap-action-approval/1",
      profile_digest: :crypto.hash(:sha256, preimage),
      content_digest: :crypto.hash(:sha256, ["BAP1-CONTENT", <<0>>, bytes]),
      gen: 1,
      prev: <<0::256>>
    })
  end

  defp otp_verifies?(:eddsa, message, signature, key),
    do: :crypto.verify(:eddsa, :none, message, signature, [key, :ed25519])

  defp otp_verifies?(:es256, message, <<r::256, s::256>>, key) do
    assert r > 0 and r < @order
    assert s > 0 and s <= div(@order, 2)
    body = der_positive_integer(r) <> der_positive_integer(s)
    der = <<0x30, byte_size(body), body::binary>>
    :crypto.verify(:ecdsa, :sha256, message, der, [key, :prime256v1])
  end

  defp der_positive_integer(value) do
    bytes = :binary.encode_unsigned(value)
    bytes = if :binary.first(bytes) >= 128, do: <<0, bytes::binary>>, else: bytes
    <<0x02, byte_size(bytes), bytes::binary>>
  end

  defp assert_record(pid, record, opts, "invalid", id) do
    before = Agent.get(pid, & &1.calls)

    assert {:error, {:producer_error, :invalid}} =
             Adapter.sign_action_approval(approval_input(record), handle(pid), opts),
           id

    assert Agent.get(pid, & &1.calls) == before, id
  end

  defp assert_record(pid, record, opts, success, "request-ca-tightening-exact") do
    # The record's exact boundary permits the request ID. The same limit also
    # applies to the longer assertion profile ID, so the complete artifact fails.
    assert {:ok, bytes} = Approval.encode_record(record, opts.bounds, opts.record_bounds)
    assert bytes == raw(success["wire"])
    assert_record(pid, record, opts, "invalid", "request-ca-tightening-exact")
  end

  defp assert_record(pid, record, opts, %{"wire" => wire, "content_digest" => digest}, id) do
    bytes = raw(wire)
    input = approval_input(record)

    assert {:ok, %{record: ^bytes, content_assertion: compact}} =
             Adapter.sign_action_approval(input, handle(pid), opts),
           id

    assert {:ok, canonical} = Approval.decode_record(bytes, opts.bounds, opts.record_bounds)
    context = context(:eddsa, pid, canonical)
    context = %{context | bounds: opts.bounds, record_bounds: opts.record_bounds}
    assert {:ok, facts} = Approval.verify_eddsa(bytes, compact, context), id
    assert facts.assertion.content_digest == raw(digest), id
    assert facts.record == canonical, id
    assert_independent(compact, :eddsa, key(pid), approval_claims(input, bytes))
  end

  defp context(suite, pid, record) do
    %{
      trust_domain: "release-domain",
      audience: "executor",
      request_id: record.request_id,
      revision_digest: record.revision_digest,
      subject: record.subject,
      action: record.action,
      resources: record.resources,
      roles: [record.approver_role],
      now: 20,
      max_staleness: 5,
      max_lifetime: 30,
      bounds: %{},
      record_bounds: %{},
      snapshot: %{
        trust_domain: "release-domain",
        suite: suite,
        provenance: "configured-snapshot",
        as_of: 15,
        entries: [%{issuer: "issuer", key: key(pid), roles: [record.approver_role]}]
      }
    }
  end

  defp key(pid) do
    %HistoricalPublicKey{
      key_id: Agent.get(pid, & &1.kid),
      public_key: Agent.get(pid, & &1.first.public),
      valid_from: 10,
      valid_before: 40
    }
  end

  defp expected(suite, input, pid) do
    type = %{eddsa: Ed25519.ExpectedContentAssertion, es256: ES256.ExpectedContentAssertion}

    struct!(Map.fetch!(type, suite),
      attestor: key(pid),
      issuer: input.iss,
      audience: input.aud,
      subject: input.sub,
      profile: input.profile,
      profile_digest: input.profile_digest,
      content_digest: input.content_digest,
      now: 20,
      bounds: %{}
    )
  end

  defp start_custody(suite) do
    start_supervised!(
      Supervisor.child_spec(
        {Agent,
         fn ->
           %{
             first: key_pair(suite),
             second: key_pair(suite),
             suite: suite,
             kid: @kid,
             active: :first,
             mode: :normal,
             snapshots: 0,
             calls: []
           }
         end},
        id: suite
      )
    )
  end

  defp key_pair(:eddsa), do: key_pair(:eddsa, :ed25519)
  defp key_pair(:es256), do: key_pair(:ecdh, :prime256v1)

  defp key_pair(type, curve) do
    {public, private} = :crypto.generate_key(type, curve)
    %{public: public, private: private}
  end

  defp handle(pid), do: {Custody, {pid, :current}}
  defp signer(:eddsa), do: Adapter
  defp signer(:es256), do: Adapter.V3
  defp verifier(:eddsa), do: &Approval.verify_eddsa/3
  defp verifier(:es256), do: &Approval.verify_es256/3

  defp approval_input(record),
    do: %{record: record, jti: "event", iss: "issuer", aud: "executor", iat: 10, nbf: 15, exp: 40}

  defp assertion_input(payload) do
    payload
    |> Map.delete("v")
    |> atom_keys()
    |> Map.update!(:content_digest, &raw/1)
    |> Map.update!(:profile_digest, &raw/1)
    |> Map.update!(:prev, &raw/1)
  end

  defp flip_signature(compact) do
    [header, payload, encoded] = String.split(compact, ".")
    <<first, rest::binary>> = raw(encoded)
    altered = Base.url_encode64(<<Bitwise.bxor(first, 1), rest::binary>>, padding: false)
    Enum.join([header, payload, altered], ".")
  end

  defp approval_vector(id),
    do: Enum.find(fixture(@approval_root, "approval-cases.json"), &(&1["id"] == id))

  defp fixture(root, name), do: root |> fixture_bytes(name) |> :json.decode()

  defp fixture_bytes(root, name) do
    root |> fixture_dir() |> Path.join(name) |> File.read!()
  end

  defp fixture_dir(root),
    do: Path.join([:code.priv_dir(:bounded_authority_protocol), "conformance", root])

  defp atom_keys(map),
    do: Map.new(map, fn {key, value} -> {String.to_existing_atom(key), value} end)

  defp raw(value), do: Base.url_decode64!(value, padding: false)
  defp sha256_hex(value), do: Base.encode16(:crypto.hash(:sha256, value), case: :lower)
end
