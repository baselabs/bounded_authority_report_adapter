defmodule BoundedAuthorityReportAdapter.TelemetryTest do
  @moduledoc """
  The telemetry surface suite: the closed event pair, the value-free metadata
  invariant (exact-key assertions + the shape validator's refusal), the
  full class × object coverage driven through the REAL signing entry points,
  and the docs/telemetry.md table parity (the acceptance tie).

  The value-free tripwire (the ticket's named mutation) is a SLICE red-proof,
  quoted in the closeout rather than shipped: planting a value-carrying key
  into the emitter's metadata makes the validator refuse the emission — the
  stop event vanishes and every shape assertion here reds. What ships is the
  mechanical half: exact-key assertions on real emissions + the validator's
  refusal tests below.
  """

  # async: false — the capture handler observes EVERY emission in the VM, so
  # concurrent suites' sign calls would land in the capture (indistinguishable
  # by design: the surface is value-free). Serializing the module scopes the
  # capture to this suite's own calls.
  use ExUnit.Case, async: false

  alias BoundedAuthorityProtocol.V1
  alias BoundedAuthorityReportAdapter.Keys.RawKey
  alias BoundedAuthorityReportAdapter.Telemetry
  alias BoundedAuthorityReportAdapter.TestKeys

  @prefix [:bounded_authority_report_adapter, :sign]
  @now 1_750_000_000
  @cast_arguments {:object, [{"record", {:object, [{"region", {:string, "us-east"}}]}}]}
  @operation "report_external_materialization"

  # --- capture handler ---------------------------------------------------------

  defp capture_events(fun) do
    handler_id = "telemetry-test-#{System.unique_integer([:positive])}"
    me = self()

    :ok =
      :telemetry.attach_many(
        handler_id,
        [@prefix ++ [:start], @prefix ++ [:stop]],
        fn event, measurements, metadata, _config ->
          send(me, {:telemetry_event, event, measurements, metadata})
        end,
        nil
      )

    try do
      result = fun.()
      {result, drain_events([])}
    after
      :telemetry.detach(handler_id)
    end
  end

  # Handlers run inline in the calling process, so every emission is already in
  # the mailbox when fun.() returns; the small timeout only bounds the drain.
  defp drain_events(acc) do
    receive do
      {:telemetry_event, event, measurements, metadata} ->
        drain_events([{event, measurements, metadata} | acc])
    after
      20 ->
        Enum.reverse(acc)
    end
  end

  # --- fixtures (the four suites' happy-path shapes) ---------------------------

  defp build_report do
    {holder_pub, _} = TestKeys.holder_keypair()
    thumb = TestKeys.holder_thumbprint_raw(holder_pub)

    {grant_compact, _} =
      TestKeys.issuer_signed_grant_compact(thumb,
        issued_at: @now - 100,
        not_before: @now - 100,
        expires_at: @now + 3600
      )

    %{
      grant_compact: grant_compact,
      operation: @operation,
      method: "POST",
      target_uri: "https://api.example.test/invoke",
      invocation_id: "123e4567-e89b-42d3-a456-426614174000",
      cast_arguments: @cast_arguments,
      nonce: "challenge-001"
    }
  end

  # The local-loopback variant of the report: a canonical literal-loopback
  # target and a REQUIRED nonce (the profile's admission is BAP's).
  defp build_local_loopback_report do
    %{build_report() | target_uri: "http://127.0.0.1:4000/invoke", nonce: "challenge-001"}
  end

  defp holder_handle, do: {RawKey, TestKeys.holder_keypair()}

  defp anchor_input do
    %{
      anchor_id: "urn:example:anchor:telemetry-001",
      chain_id: "urn:example:chain:ra4",
      sequence: 1,
      chain_hash: :crypto.hash(:sha256, "ra4-test-chain")
    }
  end

  defp grant_input do
    {holder_pub, _} = TestKeys.holder_keypair()

    %{
      issuer: "https://issuer.example.test",
      grant_id: "urn:example:grant:telemetry-001",
      audiences: ["https://verifier.example.test"],
      issued_at: @now - 100,
      not_before: @now - 100,
      expires_at: @now + 3600,
      holder_thumbprint: TestKeys.holder_thumbprint_raw(holder_pub),
      operations: [%V1.Operation{name: @operation, selectors: [:all]}]
    }
  end

  defp issuer_handle, do: {GrantIssuerHandle, TestKeys.issuer_keypair()}

  defp transition_input do
    {_next_pub, _} = :crypto.generate_key(:eddsa, :ed25519, <<3::256>>)
    next_pub = elem(:crypto.generate_key(:eddsa, :ed25519, <<3::256>>), 0)

    %{
      transition_id: "urn:test:transition:telemetry-001",
      chain_id: "urn:test:chain:1",
      effective_at: @now,
      next_key_id: "next-key-2026-08",
      next_public_key: next_pub
    }
  end

  # --- the happy path: exact closed shapes --------------------------------------

  test "sign_report emits start + stop with :ok and exactly the closed metadata" do
    {result, events} =
      capture_events(fn ->
        BoundedAuthorityReportAdapter.sign_report(build_report(), holder_handle(), %{
          issued_at: @now - 50
        })
      end)

    assert {:ok, _} = result

    assert [
             {@prefix ++ [:start], start_measurements, start_metadata},
             {@prefix ++ [:stop], stop_measurements, stop_metadata}
           ] = events

    assert start_measurements == %{count: 1}
    # EXACT key sets — the value-free invariant is an exact-shape property.
    assert Map.keys(start_metadata) == [:object]
    assert start_metadata.object == :report

    assert Map.keys(stop_measurements) == [:duration]
    assert is_integer(stop_measurements.duration) and stop_measurements.duration >= 0
    assert Map.keys(stop_metadata) |> Enum.sort() == [:object, :result_class]
    assert stop_metadata.object == :report
    assert stop_metadata.result_class == :ok
  end

  # --- every failure class is emitted through the real entry point --------------

  @failure_drivers [
    {:invalid_input, :empty_report, {:error, :invalid_report}},
    {:invalid_key_handle, :not_a_tuple, {:error, :invalid_key_handle}},
    {:signing_failed, :wrong_key, {:error, :signing_failed}},
    {:producer_error, :raw_map_cast_arguments, {:error, {:producer_error, :invalid}}}
  ]

  for {class, driver, expected_return} <- @failure_drivers do
    test "sign_report failure class #{class} is emitted, value-free" do
      {report, handle} = failure_driver(unquote(driver))

      {result, events} =
        capture_events(fn ->
          BoundedAuthorityReportAdapter.sign_report(report, handle, %{issued_at: @now - 50})
        end)

      # The return is EXACTLY the pre-telemetry contract — the emission never
      # alters the signing result.
      assert result == unquote(Macro.escape(expected_return))

      {_stop, _stop_m, stop_md} = List.last(events)

      assert stop_md.object == :report
      assert stop_md.result_class == unquote(class)
      assert Map.keys(stop_md) |> Enum.sort() == [:object, :result_class]
    end
  end

  defp failure_driver(:empty_report), do: {%{}, holder_handle()}
  defp failure_driver(:not_a_tuple), do: {build_report(), :not_a_tuple}

  defp failure_driver(:wrong_key),
    do: {build_report(), {WrongKeyHandle, TestKeys.holder_keypair()}}

  defp failure_driver(:raw_map_cast_arguments),
    do: {%{build_report() | cast_arguments: %{"record" => 1}}, holder_handle()}

  # --- every object emits --------------------------------------------------------

  test "every entry point emits its object atom" do
    objects_with_calls = [
      {:report,
       fn ->
         BoundedAuthorityReportAdapter.sign_report(build_report(), holder_handle(), %{
           issued_at: @now - 50
         })
       end},
      {:anchor,
       fn ->
         BoundedAuthorityReportAdapter.sign_anchor(anchor_input(), holder_handle(), %{
           anchored_at: @now
         })
       end},
      {:grant,
       fn -> BoundedAuthorityReportAdapter.sign_grant(grant_input(), issuer_handle(), %{}) end},
      {:key_transition,
       fn ->
         BoundedAuthorityReportAdapter.sign_key_transition(
           transition_input(),
           holder_handle(),
           %{}
         )
       end},
      {:local_loopback_report,
       fn ->
         BoundedAuthorityReportAdapter.sign_local_loopback_report(
           build_local_loopback_report(),
           holder_handle(),
           %{issued_at: @now - 50}
         )
       end}
    ]

    for {object, call} <- objects_with_calls do
      {result, events} = capture_events(call)
      assert match?({:ok, _}, result), "#{object} happy path must succeed for the emission test"

      assert Enum.any?(events, fn
               {@prefix ++ [:start], _, %{object: ^object}} -> true
               _ -> false
             end),
             "no :start emission for #{object}"

      assert Enum.any?(events, fn
               {@prefix ++ [:stop], _, %{object: ^object, result_class: :ok}} -> true
               _ -> false
             end),
             "no :ok :stop emission for #{object}"
    end
  end

  # --- sign_span never alters the signer's return ---------------------------------

  test "sign_span returns the wrapped value unchanged (ok and error shapes)" do
    assert Telemetry.sign_span(:report, fn -> {:ok, :envelope} end) == {:ok, :envelope}

    assert Telemetry.sign_span(:anchor, fn -> {:error, :signing_failed} end) ==
             {:error, :signing_failed}
  end

  # --- the shape validator refuses everything outside the closed surface ------------

  test "the emitters refuse unknown objects, unknown classes, and bad durations — emitting nothing" do
    # The refusal calls run INSIDE the captured fun: a mutation that makes a
    # refused emission both return the error tuple AND emit would be caught
    # here (the capture would see the event), not vacuously green.
    {results, events} =
      capture_events(fn ->
        {
          Telemetry.emit_start(:bogus),
          Telemetry.emit_stop(:report, -1, :ok),
          Telemetry.emit_stop(:report, 1, :bogus_class)
        }
      end)

    assert results ==
             {{:error, :telemetry_invalid}, {:error, :telemetry_invalid},
              {:error, :telemetry_invalid}}

    assert events == []
  end

  # --- the value-free invariant is mechanical -----------------------------------

  # The value-free TRIPWIRE is a slice red-proof, not a shipped test: planting a
  # value-carrying key (e.g. key_id) INSIDE the emitter makes the validator
  # refuse the emission — the :stop event vanishes and every shape assertion
  # above reds. The demonstration is quoted in the slice's closeout. What ships
  # is the mechanical half: the module's own API cannot express an off-shape
  # emission (covered by the exact-key assertions above + the refusals above).

  # --- docs parity (the acceptance tie) ---------------------------------------------

  test "docs/telemetry.md enumerates exactly the emitter's classes and objects" do
    doc = File.read!("docs/telemetry.md")

    for class <- Telemetry.classes() do
      assert doc =~ "| `:#{class}`",
             "docs/telemetry.md must enumerate the class :#{class}"
    end

    for object <- Telemetry.objects() do
      assert doc =~ "| `:#{object}`",
             "docs/telemetry.md must enumerate the object :#{object}"
    end

    # Vice versa, BOTH tables, phantom-capable: the reverse scans enumerate
    # EVERY `` | `:atom` | `` row in each table (not just the known atoms), so
    # a documented phantom row reds here instead of passing silent.
    doc_classes = section_atoms(doc, "Result classes (the classified outcome of a span):")
    doc_objects = section_atoms(doc, "Objects (one per signing entry point):")

    assert Enum.sort(doc_classes) == Enum.sort(Telemetry.classes()),
           "phantom or missing classes in docs/telemetry.md: #{inspect(doc_classes)}"

    assert Enum.sort(doc_objects) == Enum.sort(Telemetry.objects()),
           "phantom or missing objects in docs/telemetry.md: #{inspect(doc_objects)}"
  end

  # The doc segment from `marker` to the next paragraph break — one table's
  # scope. (Both tables live under a single heading, so the split anchors on
  # each table's lead-in sentence; the first \n\n is the gap between lead-in
  # and table, the second ends the table.)
  defp section_atoms(doc, marker) do
    [_, rest] = String.split(doc, marker <> "\n\n", parts: 2)
    [table, _rest] = String.split(rest, "\n\n", parts: 2)

    Regex.scan(~r/^\|\s*`:(\w+)`\s*\|/m, table)
    |> Enum.map(fn [_, atom] -> String.to_atom(atom) end)
    |> Enum.uniq()
  end
end
