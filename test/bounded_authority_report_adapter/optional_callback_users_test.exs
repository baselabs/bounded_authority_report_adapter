defmodule BoundedAuthorityReportAdapter.RecordingHandle do
  @moduledoc false
  # A real-key handle that records which callbacks an entry point calls. The term carries the
  # key pair (test-only). sign/2 returns raw r || s for P-256 keys.
  @behaviour BoundedAuthorityReportAdapter

  @calls {__MODULE__, :calls}

  def calls, do: Process.get(@calls, []) |> Enum.reverse() |> Enum.uniq()
  def reset, do: Process.delete(@calls)

  defp record(callback), do: Process.put(@calls, [callback | Process.get(@calls, [])])

  @impl true
  def sign(message, %{suite: :ed25519, private: private}) do
    record(:sign)
    {:ok, :crypto.sign(:eddsa, :none, message, [private, :ed25519])}
  end

  def sign(message, %{suite: :p256, private: private}) do
    record(:sign)
    der = :crypto.sign(:ecdsa, :sha256, message, [private, :prime256v1])

    <<0x30, _length, 0x02, r_size, r::binary-size(r_size), 0x02, s_size, s::binary-size(s_size)>> =
      der

    {:ok,
     <<:binary.decode_unsigned(r)::unsigned-big-256,
       :binary.decode_unsigned(s)::unsigned-big-256>>}
  end

  @impl true
  def public_key(%{public: public}) do
    record(:public_key)
    {:ok, public}
  end

  @impl true
  def thumbprint(%{suite: suite, public: public}) do
    record(:thumbprint)

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
  def key_identity(%{key_id: key_id, public: public}) do
    record(:key_identity)
    {:ok, {key_id, public}}
  end

  @impl true
  def signing_identity(%{role: role, key_id: key_id, public: public}) do
    record(:signing_identity)
    {:ok, {role, key_id, public}}
  end
end

defmodule BoundedAuthorityReportAdapter.OptionalCallbackUsersTest do
  @moduledoc """
  `BoundedAuthorityReportAdapter.__optional_callback_users__/0` says which entry points call
  each optional callback; the doctor's advisories are built from it. This test derives the
  same map from behavior: it calls every public `sign_*/3` of both surfaces with valid input
  and a handle that records its callbacks, and requires the declaration to match. A new entry
  point, or one that starts or stops calling an optional callback, fails here until the
  declaration (and so the doctor) says so.
  """

  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.ContentAssertion
  alias BoundedAuthorityProtocol.V1
  alias BoundedAuthorityProtocol.V3, as: ProtocolV3
  alias BoundedAuthorityReportAdapter, as: Adapter
  alias BoundedAuthorityReportAdapter.RecordingHandle
  alias BoundedAuthorityReportAdapter.V3

  @optional [:key_identity, :signing_identity]
  @now 1_750_000_000

  test "the declared users of each optional callback are exactly the entry points that call it" do
    probes = probes()

    exported =
      for module <- [Adapter, V3],
          {name, 3} <- module.__info__(:functions),
          String.starts_with?(Atom.to_string(name), "sign_"),
          do: {module, name}

    assert Enum.sort(Map.keys(probes)) == Enum.sort(exported),
           "every public sign_*/3 needs a probe here, and every probe a public sign_*/3"

    derived =
      Map.new(@optional, fn callback ->
        users =
          for {entry_point, probe} <- probes,
              callback in record(entry_point, probe),
              do: entry_point

        {callback, Enum.sort(users)}
      end)

    declared =
      Map.new(Adapter.__optional_callback_users__(), fn {callback, users} ->
        {callback, Enum.sort(users)}
      end)

    assert declared == derived
  end

  defp record(entry_point, probe) do
    RecordingHandle.reset()
    assert {:ok, _signed} = probe.(), "#{inspect(entry_point)} did not sign its probe input"
    RecordingHandle.calls()
  end

  defp key(suite, key_id, role) do
    {public, private} =
      case suite do
        :ed25519 -> :crypto.generate_key(:eddsa, :ed25519)
        :p256 -> :crypto.generate_key(:ecdh, :prime256v1)
      end

    %{suite: suite, key_id: key_id, role: role, public: public, private: private}
  end

  defp handle(key), do: {RecordingHandle, key}

  defp grant_input(holder, operation_module) do
    {:ok, holder_thumbprint} = RecordingHandle.thumbprint(holder)

    %{
      issuer: "https://issuer.example",
      grant_id: "urn:example:grant:probe",
      audiences: ["https://api.example"],
      issued_at: @now,
      not_before: @now,
      expires_at: @now + 3600,
      holder_thumbprint: holder_thumbprint,
      operations: [struct(operation_module, name: "probe", selectors: [:all])]
    }
  end

  defp report(grant, target_uri) do
    %{
      grant_compact: grant,
      operation: "probe",
      method: "POST",
      target_uri: target_uri,
      invocation_id: "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d",
      cast_arguments: {:object, []},
      nonce: "probe-nonce"
    }
  end

  defp anchor_input do
    %{
      anchor_id: "urn:example:anchor:probe",
      chain_id: "urn:example:chain:probe",
      sequence: 1,
      chain_hash: :crypto.hash(:sha256, "probe")
    }
  end

  defp transition_input(next) do
    %{
      transition_id: "urn:example:transition:probe",
      chain_id: "urn:example:chain:probe",
      effective_at: @now,
      next_key_id: next.key_id,
      next_public_key: next.public
    }
  end

  defp probes do
    issuer = key(:ed25519, "issuer", :issuer)
    holder = key(:ed25519, "holder", :holder)
    next = key(:ed25519, "next", :holder)
    ec_issuer = key(:p256, "ec-issuer", :issuer)
    ec_holder = key(:p256, "ec-holder", :holder)
    ec_next = key(:p256, "ec-next", :holder)

    {:ok, %{grant: grant}} =
      Adapter.sign_grant(grant_input(holder, V1.Operation), handle(issuer))

    {:ok, %{grant: ec_grant}} =
      V3.sign_grant(grant_input(ec_holder, ProtocolV3.Operation), handle(ec_issuer))

    {:ok, content_digest} = ContentAssertion.V1.content_digest("probe", %{})

    assertion = %{
      jti: "urn:example:assertion:probe",
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

    opts = %{issued_at: @now}

    %{
      {Adapter, :sign_report} => fn ->
        Adapter.sign_report(report(grant, "https://api.example/probe"), handle(holder), opts)
      end,
      {Adapter, :sign_local_loopback_report} => fn ->
        Adapter.sign_local_loopback_report(
          report(grant, "http://127.0.0.1:4000/probe"),
          handle(holder),
          opts
        )
      end,
      {Adapter, :sign_grant} => fn ->
        Adapter.sign_grant(grant_input(holder, V1.Operation), handle(issuer))
      end,
      {Adapter, :sign_anchor} => fn -> Adapter.sign_anchor(anchor_input(), handle(holder)) end,
      {Adapter, :sign_key_transition} => fn ->
        Adapter.sign_key_transition(transition_input(next), handle(holder))
      end,
      {Adapter, :sign_content_assertion} => fn ->
        Adapter.sign_content_assertion(assertion, handle(holder))
      end,
      {V3, :sign_report} => fn ->
        V3.sign_report(report(ec_grant, "https://api.example/probe"), handle(ec_holder), opts)
      end,
      {V3, :sign_grant} => fn ->
        V3.sign_grant(grant_input(ec_holder, ProtocolV3.Operation), handle(ec_issuer))
      end,
      {V3, :sign_anchor} => fn -> V3.sign_anchor(anchor_input(), handle(ec_holder)) end,
      {V3, :sign_key_transition} => fn ->
        V3.sign_key_transition(transition_input(ec_next), handle(ec_holder))
      end
    }
  end
end
