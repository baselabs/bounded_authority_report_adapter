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
  `BoundedAuthorityReportAdapter.OptionalCallbacks.users/0` says which entry points call each
  optional callback; the doctor's advisories are built from it. This test derives the same
  map from behavior. The entry points are every public `sign_*/3` of every module the
  application ships (compiled from `lib/`). Each is called with valid input and a handle
  that records its callbacks: once without options, and once with each option it accepts
  (`BoundedAuthorityReportAdapter.Options.schema/1`), so a callback reached only through an
  option counts. The declaration must equal the derived map. A new entry point, a new
  option, or a change in which callbacks an entry point reaches fails here until the probes
  and the declaration (and so the doctor) say so.
  """

  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.ContentAssertion
  alias BoundedAuthorityProtocol.RoleAttestation
  alias BoundedAuthorityProtocol.V1
  alias BoundedAuthorityProtocol.V3, as: ProtocolV3
  alias BoundedAuthorityReportAdapter, as: Adapter
  alias BoundedAuthorityReportAdapter.OptionalCallbacks
  alias BoundedAuthorityReportAdapter.Options
  alias BoundedAuthorityReportAdapter.RecordingHandle
  alias BoundedAuthorityReportAdapter.V3

  @optional [:key_identity, :signing_identity]
  @now 1_750_000_000

  # The options schema each entry point uses, by function name.
  @object %{
    sign_report: :report,
    sign_local_loopback_report: :report,
    sign_anchor: :anchor,
    sign_grant: :grant,
    sign_key_transition: :key_transition,
    sign_content_assertion: :content_assertion
  }

  test "the declared users of each optional callback are exactly the entry points that call it" do
    probes = probes()
    exported = shipped_signers()

    assert length(exported) >= 10, "the module scan found too few signers; it is broken"

    assert Enum.sort(Map.keys(probes)) == Enum.sort(exported),
           "every shipped sign_*/3 needs a probe here, and every probe a shipped sign_*/3"

    calls =
      Map.new(probes, fn {entry_point, probe} -> {entry_point, record(entry_point, probe)} end)

    derived =
      Map.new(@optional, fn callback ->
        {callback,
         for({entry_point, called} <- calls, callback in called, do: entry_point) |> Enum.sort()}
      end)

    declared =
      Map.new(OptionalCallbacks.users(), fn {callback, users} -> {callback, Enum.sort(users)} end)

    assert declared == derived
  end

  test "the docs state exactly which callbacks each major-1 entry point calls" do
    calls =
      Map.new(probes(), fn {entry_point, probe} -> {entry_point, record(entry_point, probe)} end)

    callbacks = [:sign, :public_key, :thumbprint, :key_identity, :signing_identity]

    callers =
      Map.new(callbacks, fn callback ->
        names =
          for {{Adapter, function}, called} <- calls, callback in called, do: "#{function}/3"

        {callback, Enum.sort(names)}
      end)

    # The moduledoc's key-handle bullets: each names the major-1 entry points that call it.
    {:docs_v1, _anno, :elixir, _format, %{"en" => moduledoc}, _meta, _docs} =
      Code.fetch_docs(Adapter)

    [_before, section] = String.split(moduledoc, "## The key-handle behavior", parts: 2)
    [section, _after] = String.split(section, "\nKey and signature shapes", parts: 2)

    bullets =
      section
      |> String.split(~r/\n\s*\* /)
      |> Enum.drop(1)
      |> Map.new(fn bullet ->
        [_, callback] = Regex.run(~r/\A`(\w+)\/\d`/, bullet)
        {String.to_existing_atom(callback), signer_names(bullet)}
      end)

    for callback <- callbacks do
      assert Map.fetch!(bullets, callback) == callers[callback],
             "the moduledoc bullet for #{callback} names #{inspect(bullets[callback])}, " <>
               "but the entry points that call it are #{inspect(callers[callback])}"
    end

    # The entry-point tables in the moduledoc, the README and the getting-started guide.
    tables = [
      {"moduledoc", moduledoc},
      {"README.md", File.read!("README.md")},
      {"docs/getting-started.md", File.read!("docs/getting-started.md")}
    ]

    for {source, text} <- tables,
        row <- String.split(text, "\n"),
        String.starts_with?(row, "| `sign_"),
        [first | rest] = row |> String.split("|", trim: true),
        function <- signer_names(first) do
      listed = rest |> Enum.join("|") |> callback_names()

      actual =
        for callback <- callbacks,
            callback != :thumbprint,
            "#{function}" in callers[callback],
            do: callback

      assert Enum.sort(listed) == Enum.sort(actual),
             "#{source}: the row for #{function} lists #{inspect(listed)}, " <>
               "but it calls #{inspect(actual)}"
    end
  end

  defp signer_names(text) do
    ~r/(?<![\w.])`(sign_\w+\/3)`/
    |> Regex.scan(text)
    |> Enum.map(fn [_, name] -> name end)
    |> Enum.uniq()
    |> Enum.sort()
  end

  defp callback_names(text) do
    ~r/`(sign|public_key|thumbprint|key_identity|signing_identity)\/\d`/
    |> Regex.scan(text)
    |> Enum.map(fn [_, name] -> String.to_existing_atom(name) end)
    |> Enum.uniq()
  end

  # Every public sign_*/3 of the application's modules compiled from lib/ (under :test the
  # application also compiles test/support, which does not ship).
  defp shipped_signers do
    {:ok, modules} = :application.get_key(:bounded_authority_report_adapter, :modules)
    lib_root = Path.expand("../../lib", __DIR__) <> "/"

    for module <- modules,
        {:module, ^module} = Code.ensure_loaded(module),
        String.starts_with?(to_string(module.module_info(:compile)[:source]), lib_root),
        {name, 3} <- module.__info__(:functions),
        String.starts_with?(Atom.to_string(name), "sign_"),
        do: {module, name}
  end

  # Calls the entry point without options (it must sign), then once per accepted option
  # with a valid value, and returns every callback any of the calls reached.
  defp record({_module, function} = entry_point, {call, option_values}) do
    accepted = Map.keys(Options.schema(Map.fetch!(@object, function)))

    assert Enum.sort(Map.keys(option_values)) == Enum.sort(accepted),
           "#{inspect(entry_point)}: probe every accepted option #{inspect(accepted)}"

    RecordingHandle.reset()
    assert {:ok, _signed} = call.(%{}), "#{inspect(entry_point)} did not sign its probe input"
    base = RecordingHandle.calls()

    with_options =
      for {option, value} <- option_values do
        RecordingHandle.reset()
        _result = call.(%{option => value})
        RecordingHandle.calls()
      end

    Enum.uniq(base ++ List.flatten(with_options))
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

  defp role_attestation(attestor, issuer) do
    {:ok, input} =
      RoleAttestation.V1.attestation_signing_input(
        %RoleAttestation.V1.RoleAttestation{
          attestor_key_id: attestor.key_id,
          jti: "urn:example:attestation:probe",
          key_id: issuer.key_id,
          public_key: issuer.public,
          role: "issuer",
          nbf: @now - 60,
          exp: @now + 3600
        },
        %{}
      )

    signature = :crypto.sign(:eddsa, :none, input.message, [attestor.private, :ed25519])
    {:ok, compact} = RoleAttestation.V1.assemble_compact(input, signature)

    %{
      compact: compact,
      attestor: %V1.HistoricalPublicKey{
        key_id: attestor.key_id,
        public_key: attestor.public,
        valid_from: @now - 3600,
        valid_before: @now + 3600
      },
      now: @now
    }
  end

  # {entry point => {call taking the options, %{accepted option => a valid value}}}
  defp probes do
    issuer = key(:ed25519, "issuer", :issuer)
    holder = key(:ed25519, "holder", :holder)
    next = key(:ed25519, "next", :holder)
    attestor = key(:ed25519, "attestor", :holder)
    ec_issuer = key(:p256, "ec-issuer", :issuer)
    ec_holder = key(:p256, "ec-holder", :holder)
    ec_next = key(:p256, "ec-next", :holder)

    {:ok, %{grant: grant}} =
      Adapter.sign_grant(grant_input(holder, V1.Operation), handle(issuer))

    {:ok, %{grant: ec_grant}} =
      V3.sign_grant(grant_input(ec_holder, ProtocolV3.Operation), handle(ec_issuer))

    # Built outside the probes: grant_input/2 calls the handle's thumbprint/1 itself, which
    # must not count as the entry point's call.
    grant_in = grant_input(holder, V1.Operation)
    ec_grant_in = grant_input(ec_holder, ProtocolV3.Operation)

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

    bounds = V1.Bounds.maximum()
    report_options = %{bounds: bounds, issued_at: @now, proof_id: "urn:example:proof:probe"}
    anchor_options = %{bounds: bounds, anchored_at: @now}
    grant_options = %{bounds: bounds, role_attestation: role_attestation(attestor, issuer)}
    # On V3 the role-attestation option is refused; the probe still records what it reached.
    ec_grant_options = grant_options
    bounds_only = %{bounds: bounds}
    # Report probes pin the proof time, so the base call is comparable with the others.
    with_time = fn opts -> Map.merge(%{issued_at: @now}, opts) end

    %{
      {Adapter, :sign_report} =>
        {&Adapter.sign_report(
           report(grant, "https://api.example/probe"),
           handle(holder),
           with_time.(&1)
         ), report_options},
      {Adapter, :sign_local_loopback_report} =>
        {&Adapter.sign_local_loopback_report(
           report(grant, "http://127.0.0.1:4000/probe"),
           handle(holder),
           with_time.(&1)
         ), report_options},
      {Adapter, :sign_grant} =>
        {&Adapter.sign_grant(grant_in, handle(issuer), &1), grant_options},
      {Adapter, :sign_anchor} =>
        {&Adapter.sign_anchor(anchor_input(), handle(holder), &1), anchor_options},
      {Adapter, :sign_key_transition} =>
        {&Adapter.sign_key_transition(transition_input(next), handle(holder), &1), bounds_only},
      {Adapter, :sign_content_assertion} =>
        {&Adapter.sign_content_assertion(assertion, handle(holder), &1), bounds_only},
      {V3, :sign_report} =>
        {&V3.sign_report(
           report(ec_grant, "https://api.example/probe"),
           handle(ec_holder),
           with_time.(&1)
         ), report_options},
      {V3, :sign_grant} => {&V3.sign_grant(ec_grant_in, handle(ec_issuer), &1), ec_grant_options},
      {V3, :sign_anchor} =>
        {&V3.sign_anchor(anchor_input(), handle(ec_holder), &1), anchor_options},
      {V3, :sign_key_transition} =>
        {&V3.sign_key_transition(transition_input(ec_next), handle(ec_holder), &1), bounds_only}
    }
  end
end
