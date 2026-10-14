defmodule BoundedAuthorityReportAdapter.DurableIdentifierProbeTest do
  # Not async: this test writes a transient probe file into the owned tree. ExUnit runs
  # async: false modules only after every async module has finished, so no tree-scanning
  # test (protocol_private_api_test, scratch_git_maintenance_test, ...) can list the file
  # while it exists or race its removal.
  use ExUnit.Case, async: false

  alias BoundedAuthorityReportAdapter.DurableIdentifierPolicy

  test "the owned tree observes a foreign external major outside the facade" do
    probe_path = "test/durable_identifier_external_major_probe.exs"

    File.write!(
      probe_path,
      "defmodule DurableIdentifierExternalMajorProbe do\n" <>
        "  alias BoundedAuthorityProtocol.V2\n" <>
        "end\n"
    )

    try do
      assert Enum.any?(DurableIdentifierPolicy.owned_tree_findings(), fn finding ->
               finding.path == probe_path and finding.kind == :external_wire_module and
                 finding.name == "BoundedAuthorityProtocol.V2"
             end)
    after
      File.rm!(probe_path)
    end
  end
end
