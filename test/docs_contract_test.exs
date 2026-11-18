defmodule BoundedAuthorityReportAdapter.DocsContractTest do
  use ExUnit.Case, async: true

  alias BoundedAuthorityReportAdapter.DocsChunk

  @signers [BoundedAuthorityReportAdapter, BoundedAuthorityReportAdapter.V3]

  test "every public type in every documented library module has a typedoc" do
    {:ok, modules} = :application.get_key(:bounded_authority_report_adapter, :modules)
    filter = Mix.Project.config()[:docs][:filter_modules]

    types =
      for module <- modules,
          Code.ensure_loaded!(module),
          filter.(module, %{}),
          %{module_doc: module_doc, entries: entries} = DocsChunk.fetch!(module),
          module_doc not in [false, :hidden],
          {{kind, name, arity}, _, _, doc, _} <- entries,
          kind in [:type, :opaque],
          do: {module, name, arity, doc}

    assert length(types) >= 39, "public type discovery must include both signer surfaces"

    for {module, name, arity, doc} <- types do
      assert match?(%{"en" => text} when is_binary(text) and byte_size(text) > 0, doc),
             "#{inspect(module)}.#{name}/#{arity} needs @typedoc"
    end
  end

  test "the errors reference covers every public signer function and its typespec result" do
    reference = File.read!("docs/guides/errors.md")

    matches = Regex.scan(~r/^\| `([^`]+\/\d+)` \| `([^`]+)` \| `([^`]+)` \|$/m, reference)

    rows =
      for [_, function, success, failure] <- matches,
          into: %{},
          do: {function, {success, failure}}

    assert map_size(rows) == length(matches), "result contracts must not have duplicate rows"

    documented =
      for module <- @signers,
          %{entries: entries} = DocsChunk.fetch!(module),
          {{:function, name, arity}, _, _, %{"en" => _}, metadata} <- entries,
          do: {module, name, arity, Map.get(metadata, :defaults, 0)}

    expected =
      MapSet.new(documented, fn {module, name, arity, _} ->
        "#{inspect(module)}.#{name}/#{arity}"
      end)

    assert MapSet.new(Map.keys(rows)) == expected,
           "errors.md must list every public function on both signer surfaces exactly once"

    for {module, name, arity, _} <- documented do
      {:ok, specs} = Code.Typespec.fetch_specs(module)
      [spec] = Map.fetch!(Map.new(specs), {name, arity})
      {:"::", _, [_head, {:|, _, [success, failure]}]} = Code.Typespec.spec_to_quoted(name, spec)
      function = "#{inspect(module)}.#{name}/#{arity}"

      assert rows[function] == {Macro.to_string(success), Macro.to_string(failure)},
             "#{function}'s documented result differs from its typespec"
    end

    for module <- @signers do
      covered =
        for {^module, name, arity, defaults} <- documented,
            actual_arity <- (arity - defaults)..arity,
            into: MapSet.new(),
            do: {name, actual_arity}

      assert MapSet.new(module.__info__(:functions)) == covered,
             "a public export has no documented result contract"
    end
  end

  test "the errors reference covers every other documented public helper result" do
    reference = File.read!("docs/guides/errors.md")

    rows =
      for [_, function, result] <-
            Regex.scan(~r/^\| `([^`]+\/\d+)` \| `([^`]+)` \|$/m, reference),
          into: %{},
          do: {function, result}

    {:ok, modules} = :application.get_key(:bounded_authority_report_adapter, :modules)
    filter = Mix.Project.config()[:docs][:filter_modules]

    helpers =
      for module <- modules,
          module not in @signers,
          Code.ensure_loaded!(module),
          filter.(module, %{}),
          %{module_doc: module_doc, entries: entries} = DocsChunk.fetch!(module),
          module_doc not in [false, :hidden],
          {{:function, name, arity}, _, _, %{"en" => _}, _} <- entries,
          do: {module, name, arity}

    expected =
      MapSet.new(helpers, fn {module, name, arity} ->
        "#{inspect(module)}.#{name}/#{arity}"
      end)

    assert MapSet.new(Map.keys(rows)) == expected

    for {module, name, arity} <- helpers do
      {:ok, specs} = Code.Typespec.fetch_specs(module)
      [spec] = Map.fetch!(Map.new(specs), {name, arity})
      {:"::", _, [_head, result]} = Code.Typespec.spec_to_quoted(name, spec)
      assert rows["#{inspect(module)}.#{name}/#{arity}"] == Macro.to_string(result)
    end
  end
end
