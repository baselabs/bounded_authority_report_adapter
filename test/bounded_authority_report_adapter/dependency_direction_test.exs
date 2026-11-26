Code.require_file("../../scripts/protocol_dependency.exs", __DIR__)

defmodule BoundedAuthorityReportAdapter.DependencyDirectionTest do
  # Mix.SCM.Git.lock_status/1 changes the VM-wide working directory while it reads the
  # checkout, so this module runs after the async modules that read relative paths.
  use ExUnit.Case, async: false

  alias BoundedAuthorityReportAdapter.ProtocolDependency
  alias Mix.Dep.Lock

  @protocol :bounded_authority_protocol
  @release "~> 1.5"
  @direct ~w(bounded_authority_protocol telemetry igniter credo dialyxir ex_doc earmark_parser mix_audit sbom)a

  # Dependency additions, including transitive additions, update the locked app boundary.
  @locked ~w(
    bounded_authority_protocol bunt credo dialyxir earmark_parser erlex ex_ast
    ex_doc file_system finch glob_ex hex_core hpax igniter
    jason makeup makeup_elixir makeup_erlang mime mint mix_audit
    nimble_options nimble_parsec nimble_pool optimus owl protobuf purl
    req rewrite sbom sourceror spitfire telemetry text_diff
    yamerl yaml_elixir
  )a

  @sources ~w(lib test/support)
  @authority_family ~r/\bBounded[A-Z][A-Za-z0-9_]*\b/
  @public_namespaces ~w(BoundedAuthorityProtocol BoundedAuthorityReportAdapter)

  test "the staged release requirement starts at 1.5 and stays within major 1" do
    assert {@protocol, @release} == Mix.Project.config()[:protocol_release]
    assert release_range?(@release)

    for mutated <- ["~> 1.0", "~> 1.5.0", "== 1.5.0", ">= 1.5.0"] do
      refute release_range?(mutated)
    end
  end

  test "the active lock identifies the dependency compiled by Mix" do
    identity = ProtocolDependency.identity!()
    version = to_string(Application.spec(@protocol, :vsn))
    lock = Map.fetch!(Lock.read(), @protocol)

    case lock do
      {:git, _, ref, [ref: ref]} ->
        assert identity == "git:#{ref}"
        assert version == "1.1.0"

      {:hex, @protocol, locked_version, _, _, _, "hexpm", outer} ->
        assert version == locked_version
        assert identity == "hex:#{version}:#{outer}"
        assert Version.match?(version, @release)
    end
  end

  test "direct and locked dependencies stay inside the adapter package boundary" do
    direct = Enum.map(Mix.Project.config()[:deps], &elem(&1, 0))
    locked = Map.keys(Lock.read())

    assert direct_dependencies?(direct)
    assert locked_dependencies?(locked)

    refute direct_dependencies?(List.delete(direct, @protocol))
    refute direct_dependencies?([:extra_dependency | direct])
    refute locked_dependencies?([:extra_dependency | locked])
  end

  test "library and compiled test support reference only public authority namespaces" do
    sources = Enum.flat_map(@sources, &Path.wildcard(Path.join(&1, "**/*.{ex,exs}")))
    witnesses = ~w(lib/bounded_authority_report_adapter.ex test/support/test_keys.ex)

    for path <- witnesses, do: assert(path in sources)

    for path <- sources do
      source = File.read!(path)
      assert foreign_authority_namespaces(source) == [], path

      if path in witnesses do
        mutant = source <> "\nalias BoundedAuthorityExample.Internal\n"
        assert foreign_authority_namespaces(mutant) == ["BoundedAuthorityExample"], path
      end
    end
  end

  defp release_range?(requirement) do
    Version.match?("1.5.0", requirement) and Version.match?("1.6.0", requirement) and
      not Version.match?("1.4.999", requirement) and not Version.match?("2.0.0", requirement)
  end

  defp direct_dependencies?(apps), do: Enum.sort(apps) == Enum.sort(@direct)
  defp locked_dependencies?(apps), do: @protocol in apps and apps -- @locked == []

  defp foreign_authority_namespaces(source) do
    for [namespace] <- Regex.scan(@authority_family, source),
        namespace not in @public_namespaces,
        uniq: true,
        do: namespace
  end
end
