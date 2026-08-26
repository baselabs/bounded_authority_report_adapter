defmodule BoundedAuthorityReportAdapter.DocsCurrencyTest do
  @moduledoc """
  Doc-currency tripwires: the guides cannot drift from the code they describe.

    * every error atom in docs/errors.md exists in a lib @type error set and
      vice versa;
    * every backticked `fun/arity` identifier in usage-rules.md resolves
      against the adapter's exported functions, its behaviour callbacks, or a
      named module;
    * the README's Documentation index matches the ex_doc extras list;
    * the dep requirement shown in getting-started is satisfied by the current
      package version.

  Mutation-proven: deleting an atom row from errors.md and renaming a function
  in usage-rules.md each red the suite (demonstrated in the slice's red log).
  """

  use ExUnit.Case, async: true

  @adapter BoundedAuthorityReportAdapter
  @error_types [:sign_error, :anchor_sign_error, :grant_sign_error, :transition_sign_error]

  test "every docs/errors.md table atom exists in a lib error @type and vice versa" do
    lib_source = File.read!("lib/bounded_authority_report_adapter.ex")
    doc = File.read!("docs/errors.md")

    lib_atoms =
      for type <- @error_types,
          atom <- type_atoms(lib_source, type),
          into: MapSet.new(),
          do: atom

    doc_atoms =
      Regex.scan(~r/^\|\s*`:(\w+)`\s*\|/m, doc)
      |> Enum.map(fn [_, atom] -> String.to_atom(atom) end)
      |> MapSet.new()

    # The error TABLE atoms are the per-set union the doc must cover.
    assert MapSet.subset?(doc_atoms, lib_atoms),
           "errors.md documents atoms absent from the lib @types: " <>
             "#{inspect(MapSet.difference(doc_atoms, lib_atoms) |> MapSet.to_list())}"

    missing = MapSet.difference(lib_atoms, doc_atoms)

    # :invalid_key_handle / :signing_failed / :producer_error appear once in the
    # shared table (not per-set), and the producer tuple is documented as
    # `{:producer_error, :invalid}` — special-shaped, not a bare row atom.
    assert Enum.sort(MapSet.to_list(missing)) == [:producer_error],
           "lib error atoms missing from errors.md: #{inspect(MapSet.to_list(missing))}"

    assert doc =~ "{:producer_error, :invalid}",
           "the producer tuple's fixed shape must be documented verbatim"
  end

  test "every backticked fun/arity in usage-rules.md resolves" do
    doc = File.read!("usage-rules.md")

    # `Module.Sub.fun/arity` or bare `fun/arity` in backticks.
    identifiers =
      Regex.scan(~r/`([A-Za-z_][\w.]*\.)?([a-z_]\w*)\/(\d+)`/, doc)
      |> Enum.map(fn [_, module_prefix, fun, arity] ->
        {case module_prefix do
           "" -> nil
           p -> p && String.trim_trailing(p, ".")
         end, String.to_atom(fun), String.to_integer(arity)}
      end)

    assert identifiers != [], "no identifiers found — the scan itself is broken"

    # Arity-exact: {fun, arity} pairs, not bare names.
    callbacks = @adapter.behaviour_info(:callbacks)

    for {module_prefix, fun, arity} <- identifiers do
      module = resolve_module(module_prefix, fun)
      # function_exported?/3 does not autoload — load the target first.
      Code.ensure_loaded!(module)

      cond do
        module == @adapter and {fun, arity} in callbacks ->
          # A behaviour callback (the handle's contract), declared not defined.
          :ok

        function_exported?(module, fun, arity) ->
          :ok

        true ->
          flunk(
            "usage-rules.md references #{module}.#{fun}/#{arity} but it is neither an " <>
              "exported function nor a behaviour callback — the doc drifted from the code"
          )
      end
    end
  end

  test "the README Documentation index matches the ex_doc extras, both directions" do
    readme = File.read!("README.md")
    mix_exs = File.read!("mix.exs")

    # Scoped to the docs extras block — the package files: list carries the
    # same .md paths for a different purpose.
    [_, extras_block] = String.split(mix_exs, "extras: [", parts: 2)
    [extras_block, _] = String.split(extras_block, "]\n", parts: 2)

    extras =
      Regex.scan(~r/"([\w\/.-]+\.md)"/, extras_block)
      |> Enum.map(fn [_, path] -> path end)
      |> MapSet.new()

    # Scoped to the README's Documentation SECTION (index entries only), and
    # bidirectional: an extras entry absent from the index reds, AND an index
    # entry that is not an extra reds (a broken-on-hexdocs link).
    [_, index_section] = String.split(readme, "## Documentation", parts: 2)
    [index_section, _] = String.split(index_section, "\n## ", parts: 2)

    index_links =
      Regex.scan(~r/\]\(([\w\/.-]+\.md)\)/, index_section)
      |> Enum.map(fn [_, path] -> path end)
      |> MapSet.new()

    # Two directions, honestly scoped: every INDEX link must be an extra (an
    # index-only link is broken on hexdocs), and every extra must be linked
    # SOMEWHERE in the README (boilerplate extras like SECURITY.md legitimately
    # live under their own sections, not the index).
    readme_links =
      Regex.scan(~r/\]\(([\w\/.-]+\.md)\)/, readme)
      |> Enum.map(fn [_, path] -> path end)
      |> MapSet.new()

    index_only = MapSet.difference(index_links, extras)

    assert MapSet.to_list(index_only) == [],
           "README Documentation index links that are not ex_doc extras " <>
             "(broken on hexdocs): #{inspect(MapSet.to_list(index_only))}"

    unlinked =
      for extra <- MapSet.to_list(extras),
          extra != "README.md",
          extra not in readme_links,
          do: extra

    assert unlinked == [],
           "ex_doc extras not linked anywhere in the README: #{inspect(unlinked)}"
  end

  test "the dep requirement in getting-started accepts the current version" do
    doc = File.read!("docs/getting-started.md")
    version = Mix.Project.config()[:version]

    [_, requirement] = Regex.run(~r/\{:bounded_authority_report_adapter, "~> ([\d.]+)"\}/, doc)

    assert Version.match?(version, "~> #{requirement}"),
           "getting-started shows ~> #{requirement} but the package version is #{version}"
  end

  ## helpers

  # The atoms of one @type error set, from the lib source (the source of
  # truth). GENERIC — every :atom in the body is extracted, so a future error
  # atom the docs don't cover reds (an allowlisted scan would pass it silent).
  # :invalid is excluded: it is the shape tag of the fixed
  # {:producer_error, :invalid} tuple, not an error atom of its own.
  defp type_atoms(source, type) do
    case Regex.run(~r/@type #{type} ::(.*?)\n\s*\n/s, source) do
      [_, body] ->
        Regex.scan(~r/:([a-z_]\w*)/i, body)
        |> Enum.map(fn [_, atom] -> String.to_atom(atom) end)
        |> Enum.reject(&(&1 == :invalid))

      nil ->
        flunk("could not locate @type #{type} in the lib source — the scan is broken")
    end
  end

  defp resolve_module(prefix, _fun) do
    case prefix do
      nil -> @adapter
      "" -> @adapter
      dotted -> dotted |> String.split(".") |> Module.concat()
    end
  end
end
