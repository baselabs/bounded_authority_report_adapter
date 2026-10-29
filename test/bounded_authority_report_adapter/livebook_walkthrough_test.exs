defmodule BoundedAuthorityReportAdapter.LivebookWalkthroughTest do
  @moduledoc """
  Runs the Livebook (`examples/report_envelope_roundtrip.livemd`) against this repository's
  source. A notebook that no longer runs is worse than none, so the notebook's own Elixir cells
  are the code under test: nothing here restates them.

  Every fenced `elixir` block is a cell, with or without attributes after the language tag. The
  cells are evaluated in order, sharing bindings and aliases the way a Livebook session does. The
  one `Mix.install/1` setup cell is skipped (this test already runs inside the adapter project,
  compiled from source). Every other cell must carry a pinned output block, the number of
  evaluated cells must equal the number of output blocks in the file, and the value each cell
  returns, formatted with `inspect(value, pretty: true, width: 100)`, must equal its block byte
  for byte.

  That format is Livebook's own. Livebook's `Livebook.Runtime.Evaluator.Formatter.inspect_opts/0`
  is `pretty: true, width: 100` (plus colors, which an export strips). This was checked once, by
  hand, on October 14, 2026, against the installed Livebook escript (version 0.20.0-dev): its
  formatter formatted every cell's value, its LiveMarkdown exporter wrote the notebook with
  those outputs, and the result was byte-identical to this file. That check is not automated
  here, so a later Livebook release that changes its saved format would not be caught.

  The notebook must also call every public signing entry point, `sign_*/3`, exported by any
  module of the compiled application that ships (compiled from `lib/`). Calls are read from each cell's quoted code, with aliases
  expanded, so a mention in a comment or a string does not count. Finally, the notebook must
  state the source's version and protocol requirement from `mix.exs`, and whether that
  requirement is released, as the CHANGELOG records it.
  """

  use ExUnit.Case, async: true

  @notebook_path Path.expand("../../examples/report_envelope_roundtrip.livemd", __DIR__)
  @changelog_path Path.expand("../../CHANGELOG.md", __DIR__)
  @external_resource @notebook_path
  @external_resource @changelog_path

  @output_marker ~s(<!-- livebook:{"output":true} -->)

  # sign_* exports that are not signing entry points: the telemetry span wrapper.
  @non_signer_exports [{BoundedAuthorityReportAdapter.Telemetry, :sign_span, 2}]

  setup_all do
    source = File.read!(@notebook_path)

    {setup_cells, cells} =
      source
      |> parse_cells()
      |> Enum.split_with(&String.contains?(&1.code, "Mix.install("))

    {results, called} = evaluate(cells)

    %{
      source: source,
      setup_cells: setup_cells,
      cells: cells,
      results: results,
      called: called
    }
  end

  test "every notebook cell runs against the repository source and returns its pinned output",
       context do
    assert [setup] = context.setup_cells,
           "the notebook must have exactly one Mix.install setup cell"

    assert setup.code =~ "{:bounded_authority_report_adapter, path:",
           "the setup cell must install the adapter from this repository by path"

    output_blocks = count_occurrences(context.source, @output_marker)
    assert output_blocks > 0

    assert length(context.cells) == output_blocks,
           "the notebook has #{length(context.cells)} evaluated cells but #{output_blocks} " <>
             "output blocks; every cell needs exactly one pinned output"

    assert length(context.results) == length(context.cells)

    for {cell, result} <- Enum.zip(context.cells, context.results) do
      location = "#{@notebook_path}:#{cell.line}"

      case result do
        {:raised, formatted} ->
          flunk("the cell at #{location} raised:\n#{formatted}")

        {:ok, actual} ->
          assert is_binary(cell.output), "the cell at #{location} has no pinned output block"

          assert actual == cell.output, """
          the cell at #{location} returned a value that differs from its pinned output.
          returned:
          #{actual}
          pinned:
          #{cell.output}
          """
      end
    end
  end

  test "the notebook calls every public signing entry point the application exports", context do
    {:ok, modules} = :application.get_key(:bounded_authority_report_adapter, :modules)
    lib_root = Path.expand("../../lib", __DIR__) <> "/"

    # Under :test the application also compiles test/support; only lib/ modules ship.
    exports =
      for module <- modules,
          {:module, ^module} = Code.ensure_loaded(module),
          String.starts_with?(to_string(module.module_info(:compile)[:source]), lib_root),
          {name, arity} <- module.__info__(:functions),
          String.starts_with?(Atom.to_string(name), "sign_"),
          do: {module, name, arity}

    signers = for {module, name, 3} <- exports, do: {module, name}

    # The known surface at the time of writing: six major-1 signers and four major-3 signers.
    assert length(signers) >= 10

    # Any other sign_* export is a default-argument head of a signer or a named non-signer, so a
    # new entry point cannot dodge this check by its arity.
    for {module, name, arity} = export <- exports, arity != 3 do
      assert {module, name} in signers or export in @non_signer_exports,
             "#{inspect(module)}.#{name}/#{arity} is an unclassified sign_* export"
    end

    for {module, name} <- signers do
      assert MapSet.member?(context.called, {module, name}),
             "the notebook never calls #{inspect(module)}.#{name}/3 in code"
    end
  end

  test "every notebook cell is formatted the way mix format formats it", context do
    for cell <- context.setup_cells ++ context.cells do
      assert IO.iodata_to_binary(Code.format_string!(cell.code)) == cell.code,
             "the cell at #{@notebook_path}:#{cell.line} is not formatted"
    end
  end

  test "the notebook states the source version, the protocol requirement and its release state",
       context do
    notebook = normalize_space(context.source)
    version = Mix.Project.config()[:version]
    requirement = protocol_requirement()
    {unreleased, latest_version, latest_section} = changelog_sections()

    expected_statements =
      if String.contains?(unreleased, "`#{requirement}`") do
        [_match, released_pin] = Regex.run(~r/pin moves `[^`]+` → `([^`]+)`/, latest_section)

        [
          "version #{version} in `mix.exs`, which declares " <>
            "`bounded_authority_protocol` `#{requirement}`.",
          "That range is unreleased; the published #{latest_version} release pins " <>
            "`#{released_pin}`"
        ]
      else
        [
          "version #{version} in `mix.exs`, which declares " <>
            "`bounded_authority_protocol` `#{requirement}`.",
          "The published #{latest_version} release declares the same requirement."
        ]
      end

    for statement <- expected_statements do
      assert String.contains?(notebook, statement),
             "the notebook does not state #{inspect(statement)}; mix.exs or the CHANGELOG " <>
               "moved and the notebook did not"
    end
  end

  # Evaluates cells in order with a shared binding and environment, the way a Livebook session
  # does. Records each cell's formatted value, or the exception it raised (and stops there), and
  # the {module, function} pairs each cell calls in code, with aliases expanded against the
  # environment the cell runs in.
  defp evaluate(cells) do
    initial = {[], MapSet.new(), [], Code.env_for_eval(file: @notebook_path)}

    {results, called, _binding, _env} =
      Enum.reduce_while(cells, initial, fn cell, {results, called, binding, env} ->
        quoted = Code.string_to_quoted!(cell.code, file: @notebook_path, line: cell.line)
        called = MapSet.union(called, remote_calls(quoted, env))

        try do
          {value, binding, env} = Code.eval_quoted_with_env(quoted, binding, env)
          formatted = inspect(value, pretty: true, width: 100)
          {:cont, {[{:ok, formatted} | results], called, binding, env}}
        rescue
          exception ->
            formatted = Exception.format(:error, exception, __STACKTRACE__)
            {:halt, {[{:raised, formatted} | results], called, binding, env}}
        end
      end)

    {Enum.reverse(results), called}
  end

  defp remote_calls(quoted, env) do
    {_quoted, calls} =
      Macro.prewalk(quoted, MapSet.new(), fn
        {{:., _, [{:__aliases__, _, _} = alias_ast, function]}, _, args} = node, calls
        when is_atom(function) and is_list(args) ->
          {node, MapSet.put(calls, {Macro.expand(alias_ast, env), function})}

        node, calls ->
          {node, calls}
      end)

    calls
  end

  defp protocol_requirement do
    requirement =
      Enum.find_value(Mix.Project.config()[:deps], fn
        {:bounded_authority_protocol, requirement} when is_binary(requirement) ->
          requirement

        {:bounded_authority_protocol, requirement, _opts} when is_binary(requirement) ->
          requirement

        _other ->
          nil
      end)

    assert is_binary(requirement)
    requirement
  end

  # The CHANGELOG's Unreleased section ("" between a release cut and the next cycle's
  # section), and the version and section of the latest release.
  defp changelog_sections do
    [_preamble | sections] = String.split(File.read!(@changelog_path), ~r/^## /m)

    {unreleased, released} =
      case sections do
        ["[Unreleased]" <> _ = unreleased | released] -> {unreleased, released}
        released -> {"", released}
      end

    assert [latest | _older] = released
    assert [_match, latest_version] = Regex.run(~r/\A\[(\d+\.\d+\.\d+)\]/, latest)
    {unreleased, latest_version, latest}
  end

  defp normalize_space(text), do: String.replace(text, ~r/\s+/, " ")

  defp count_occurrences(text, pattern), do: length(String.split(text, pattern)) - 1

  # Splits a .livemd file into its Elixir cells. A cell is a fenced elixir block, with or without
  # attributes after the language tag; its pinned output is the next fenced block when only blank
  # lines and the Livebook output marker sit between them.
  defp parse_cells(source) do
    source
    |> String.split("\n")
    |> Enum.with_index(1)
    |> collect_cells([])
  end

  defp collect_cells([], cells), do: Enum.reverse(cells)

  defp collect_cells([{text, line} | rest], cells) do
    if Regex.match?(~r/\A```elixir(\s.*)?\z/, text) do
      {code_lines, rest} = take_fence(rest, [])
      {output, rest} = take_output(rest)
      cell = %{line: line + 1, code: Enum.join(code_lines, "\n"), output: output}
      collect_cells(rest, [cell | cells])
    else
      collect_cells(rest, cells)
    end
  end

  defp take_fence([{"```", _line} | rest], acc), do: {Enum.reverse(acc), rest}
  defp take_fence([{text, _line} | rest], acc), do: take_fence(rest, [text | acc])

  defp take_output(lines) do
    case drop_blank(lines) do
      [{@output_marker, _line} | rest] -> take_output_fence(drop_blank(rest))
      _no_output -> {nil, lines}
    end
  end

  defp take_output_fence([{"```", _line} | rest]) do
    {output_lines, rest} = take_fence(rest, [])
    {Enum.join(output_lines, "\n"), rest}
  end

  defp take_output_fence(rest), do: {nil, rest}

  defp drop_blank(lines), do: Enum.drop_while(lines, fn {text, _line} -> text == "" end)
end
