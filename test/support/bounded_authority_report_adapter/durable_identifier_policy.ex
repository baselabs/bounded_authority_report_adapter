defmodule BoundedAuthorityReportAdapter.DurableIdentifierPolicy do
  @moduledoc false

  @owned_roots ["lib", "test", "scripts", "config", "examples"]
  @contract_identities MapSet.new([
                         {"mix.exs", :package_source_ref, ~S(source_ref: "v#{@version}")},
                         {"lib/bounded_authority_report_adapter.ex", :external_wire_module,
                          "BoundedAuthorityProtocol.V1"},
                         {"docs/consumer-integration.md", :wire_scheme, "ba_protocol_v1"}
                       ])
  @external_v1_paths MapSet.new([
                       "examples/edge_agent/lib/edge_agent.ex",
                       "examples/edge_agent/lib/edge_agent/demo_issuer.ex",
                       "examples/edge_agent/lib/edge_agent/handle.ex",
                       "examples/edge_agent/lib/edge_agent/receiver.ex",
                       "examples/edge_agent/lib/edge_agent/receiver/nonce_ledger.ex",
                       "examples/edge_agent/test/edge_agent_test.exs",
                       "lib/bounded_authority_report_adapter.ex",
                       "scripts/check_package.exs",
                       "test/bounded_authority_report_adapter/bounds_aware_assembly_test.exs",
                       "test/bounded_authority_report_adapter/conformance/tag_test.exs",
                       "test/bounded_authority_report_adapter/conformance_roundtrip_test.exs",
                       "test/bounded_authority_report_adapter/dependency_direction_test.exs",
                       "test/bounded_authority_report_adapter/durable_identifier_policy_test.exs",
                       "test/bounded_authority_report_adapter/sign_anchor_test.exs",
                       "test/bounded_authority_report_adapter/sign_grant_test.exs",
                       "test/bounded_authority_report_adapter/sign_key_transition_test.exs",
                       "test/bounded_authority_report_adapter/sign_report_test.exs",
                       "test/bounded_authority_report_adapter/telemetry_test.exs",
                       "test/bounded_authority_report_adapter_test.exs",
                       "test/support/bounded_authority_report_adapter/conformance/vector_case.ex",
                       "test/support/bounded_authority_report_adapter/durable_identifier_policy.ex",
                       "test/support/bounded_authority_report_adapter/keys/raw_key.ex",
                       "test/support/bounded_authority_report_adapter/test_handles.ex",
                       "test/support/test_keys.ex"
                     ])
  @non_version_hump_stems ["Base", "Ed", "IPV", "IPv", "Ipv"]

  def check(%{path: path, kind: kind, name: name}) do
    cond do
      MapSet.member?(@contract_identities, {path, kind, name}) ->
        :ok

      kind == :external_wire_module and name == "BoundedAuthorityProtocol.V1" and
          MapSet.member?(@external_v1_paths, path) ->
        :ok

      version_bearing?(name) ->
        {:error, :implementation_version_identifier}

      true ->
        :ok
    end
  end

  def owned_tree_findings do
    tracked = tracked_files()

    path_findings =
      for path <- tracked,
          Enum.any?(@owned_roots, &under_root?(path, &1)),
          segment <- Path.split(path),
          name = Path.rootname(segment),
          {:error, :implementation_version_identifier} <- [
            check(%{path: path, kind: :path, name: name})
          ],
          do: %{path: path, kind: :path, name: name}

    source_findings =
      for path <- tracked,
          Enum.any?(@owned_roots, &under_root?(path, &1)),
          Path.extname(path) in [".ex", ".exs"],
          {kind, name} <- identifiers(path),
          {:error, :implementation_version_identifier} <- [
            check(%{path: path, kind: kind, name: name})
          ],
          do: %{path: path, kind: kind, name: name}

    contract_findings =
      for observation <- contract_observations(),
          {:error, :implementation_version_identifier} <- [check(observation)],
          do: observation

    Enum.uniq(path_findings ++ source_findings ++ contract_findings)
  end

  def contract_observations do
    package =
      "mix.exs"
      |> File.read!()
      |> then(&Regex.scan(~r/source_ref:\s*"v(?:#\{@version\}|\d+)"/, &1))
      |> Enum.map(fn [name] -> %{path: "mix.exs", kind: :package_source_ref, name: name} end)

    wire_modules =
      "lib/bounded_authority_report_adapter.ex"
      |> identifiers()
      |> Enum.filter(fn {kind, _name} -> kind == :external_wire_module end)
      |> Enum.map(fn {kind, name} ->
        %{path: "lib/bounded_authority_report_adapter.ex", kind: kind, name: name}
      end)

    schemes =
      "docs/consumer-integration.md"
      |> File.read!()
      |> then(&Regex.scan(~r/\bba_protocol_v\d+\b/, &1))
      |> Enum.map(fn [name] ->
        %{path: "docs/consumer-integration.md", kind: :wire_scheme, name: name}
      end)

    Enum.uniq(package ++ wire_modules ++ schemes)
  end

  def check_source(path, source) do
    source
    |> identifiers_from_source(path)
    |> Enum.find_value(:ok, fn {kind, name} ->
      case check(%{path: path, kind: kind, name: name}) do
        :ok -> false
        error -> error
      end
    end)
  end

  defp identifiers(path) do
    source = File.read!(path)
    identifiers_from_source(source, path)
  end

  defp identifiers_from_source(source, path) do
    ast = Code.string_to_quoted!(source, file: path)

    {_ast, acc} =
      ast
      |> strip_docs()
      |> Macro.prewalk([], &collect/2)

    {_ast, atoms} =
      ast
      |> strip_docs()
      |> strip_aliases()
      |> Macro.prewalk([], fn
        atom, names when is_atom(atom) and not is_boolean(atom) and not is_nil(atom) ->
          {atom, [{:atom, Atom.to_string(atom)} | names]}

        node, names ->
          {node, names}
      end)

    Enum.uniq(Enum.reverse(acc) ++ Enum.reverse(atoms))
  end

  defp tracked_files do
    {output, 0} =
      System.cmd("git", ["ls-files", "-z", "--cached", "--others", "--exclude-standard"])

    String.split(output, <<0>>, trim: true)
  end

  defp under_root?(path, root), do: path == root or String.starts_with?(path, root <> "/")

  defp strip_docs(ast) do
    Macro.prewalk(ast, fn
      {:@, _, [{doc, _, [_body]}]} when doc in [:moduledoc, :doc, :typedoc, :shortdoc] ->
        {:@, [], [{doc, [], [true]}]}

      other ->
        other
    end)
  end

  defp strip_aliases(ast) do
    Macro.prewalk(ast, fn
      {:__aliases__, _, _} -> {:alias_reference, [], []}
      other -> other
    end)
  end

  defp collect({:defmodule, _, [{:__aliases__, _, segments} | _]} = node, acc)
       when is_list(segments) do
    {node, [{:module, Enum.map_join(segments, ".", &Atom.to_string/1)} | acc]}
  end

  defp collect({kind, _, [{name, _, _} | _]} = node, acc)
       when kind in [:def, :defp, :defmacro, :defmacrop] and is_atom(name) do
    {node, [{:function, Atom.to_string(name)} | acc]}
  end

  defp collect({:__aliases__, _, segments} = node, acc)
       when is_list(segments) do
    if Enum.all?(segments, &is_atom/1) do
      collect_external_alias(node, segments, acc)
    else
      {node, acc}
    end
  end

  defp collect(node, acc), do: {node, acc}

  defp collect_external_alias(node, segments, acc) do
    name = Enum.map_join(segments, ".", &Atom.to_string/1)

    case Regex.run(~r/\A(BoundedAuthorityProtocol\.V\d+)(?:\.|\z)/, name) do
      [_, namespace] -> {node, [{:external_wire_module, namespace} | acc]}
      _ -> {node, acc}
    end
  end

  defp version_bearing?(name) do
    Regex.match?(~r/(^|[._\/-])v\d/i, name) or
      Regex.match?(~r/[a-z0-9]V\d/, name) or
      Regex.match?(~r/\bsource_ref\b.*\bv(?:#\{@version\}|\d)/i, name) or
      version_hump_digit?(name)
  end

  defp version_hump_digit?(name) do
    ~r/[A-Z]+[a-z]*\d+/
    |> Regex.scan(name)
    |> Enum.map(fn [word] -> Regex.replace(~r/\d+\z/, word, "") end)
    |> Enum.any?(&(&1 not in @non_version_hump_stems))
  end
end
