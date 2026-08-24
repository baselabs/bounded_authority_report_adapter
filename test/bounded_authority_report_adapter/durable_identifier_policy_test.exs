defmodule BoundedAuthorityReportAdapter.DurableIdentifierPolicyTest do
  use ExUnit.Case, async: true

  alias BoundedAuthorityReportAdapter.DurableIdentifierPolicy

  test "enumerated package and wire identities are accepted" do
    for fixture <- [
          %{
            path: "mix.exs",
            kind: :package_source_ref,
            name: ~s(source_ref: "v\#{@version}")
          },
          %{
            path: "lib/bounded_authority_report_adapter.ex",
            kind: :external_wire_module,
            name: "BoundedAuthorityProtocol.V1"
          },
          %{
            path: "docs/consumer-integration.md",
            kind: :wire_scheme,
            name: "ba_protocol_v1"
          }
        ] do
      assert :ok = DurableIdentifierPolicy.check(fixture)
    end
  end

  test "implementation-lifecycle names and contract lookalikes are rejected" do
    for fixture <- [
          %{path: "lib/bounded_authority_report_adapter/v2.ex", kind: :path, name: "v2"},
          %{path: "lib/bounded_authority_report_adapter.ex", kind: :module, name: "SignerV2"},
          %{
            path: "lib/bounded_authority_report_adapter.ex",
            kind: :function,
            name: "sign_report_v2"
          },
          %{
            path: "docs/example.md",
            kind: :package_source_ref,
            name: ~s(source_ref: "v\#{@version}")
          },
          %{
            path: "lib/bounded_authority_report_adapter.ex",
            kind: :external_wire_module,
            name: "BoundedAuthorityProtocol.V2"
          },
          %{
            path: "lib/example.ex",
            kind: :external_wire_module,
            name: "BoundedAuthorityProtocol.V1"
          },
          %{
            path: "lib/bounded_authority_report_adapter.ex",
            kind: :wire_scheme,
            name: "ba_adapter_v1"
          }
        ] do
      assert {:error, :implementation_version_identifier} =
               DurableIdentifierPolicy.check(fixture)
    end
  end

  test "the owned library tree contains no lifecycle-derived identifiers" do
    assert DurableIdentifierPolicy.owned_tree_findings() == []
  end

  test "the tracked scanner observes each real contract boundary and quoted atoms" do
    observations = DurableIdentifierPolicy.contract_observations()

    assert Enum.any?(observations, &(&1.kind == :package_source_ref))
    assert Enum.any?(observations, &(&1.kind == :external_wire_module))
    assert Enum.any?(observations, &(&1.kind == :wire_scheme))

    assert {:error, :implementation_version_identifier} =
             DurableIdentifierPolicy.check_source(
               "config/runtime.exs",
               ~S(config :app, :"queue-v2")
             )
  end

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
