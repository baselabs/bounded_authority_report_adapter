defmodule BoundedAuthorityReportAdapter.TelemetryClassificationTest do
  @moduledoc """
  Every error an entry point can return must have its own place on the telemetry result-class
  axis. `:signing_failed` is the custody alarm, so only `{:error, :signing_failed}` may be
  classified as it. The errors are read from the error types of both suite surfaces (every
  `*_sign_error` type), so a new error atom fails here until it is classified.

  `async: false`: the handler observes every emission in the VM.
  """

  use ExUnit.Case, async: false

  alias BoundedAuthorityReportAdapter.Telemetry

  @modules [BoundedAuthorityReportAdapter, BoundedAuthorityReportAdapter.V3]

  test "every declared error is classified, and only :signing_failed as the custody alarm" do
    errors = declared_errors()
    assert :invalid_role_attestation in errors, "the type scan is broken"
    assert {:producer_error, :invalid} in errors

    me = self()
    handler = "classification-#{System.unique_integer([:positive])}"

    :ok =
      :telemetry.attach(
        handler,
        [:bounded_authority_report_adapter, :sign, :stop],
        fn _event, _measurements, metadata, _config ->
          send(me, {:class, metadata.result_class})
        end,
        nil
      )

    try do
      for error <- errors do
        Telemetry.sign_span(:grant, fn -> {:error, error} end)
        assert_received {:class, class}

        assert class in Telemetry.classes()

        if error == :signing_failed do
          assert class == :signing_failed
        else
          refute class == :signing_failed,
                 "#{inspect(error)} is classified as :signing_failed, the custody alarm"
        end
      end
    after
      :telemetry.detach(handler)
    end
  end

  # Every member of every *_sign_error type on both surfaces.
  defp declared_errors do
    for module <- @modules,
        {:ok, types} = Code.Typespec.fetch_types(module),
        {:type, {name, ast, []}} <- types,
        String.ends_with?(Atom.to_string(name), "sign_error"),
        member <- union_members(ast),
        uniq: true,
        do: to_term(member)
  end

  defp union_members({:type, _line, :union, members}), do: members
  defp union_members(single), do: [single]

  defp to_term({:atom, _line, atom}), do: atom

  defp to_term({:type, _line, :tuple, elements}),
    do: elements |> Enum.map(&to_term/1) |> List.to_tuple()
end
