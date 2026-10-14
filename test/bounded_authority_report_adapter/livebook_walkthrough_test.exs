defmodule BoundedAuthorityReportAdapter.LivebookWalkthroughTest do
  @moduledoc """
  Runs the Livebook (`examples/report_envelope_roundtrip.livemd`) against this repository's
  source. A notebook that no longer runs is worse than none, so the notebook's own Elixir cells
  are the code under test: nothing here restates them.

  The cells are parsed from the file and evaluated in order, sharing bindings and aliases the way
  a Livebook session does. The one `Mix.install/1` setup cell is skipped (this test already runs
  inside the adapter project, compiled from source). Every other cell must carry a pinned output
  block, and the value the cell returns, formatted with `inspect(value, pretty: true, width: 100)`,
  must equal that block byte for byte. A cell that raises, returns a different verdict, or loses
  its pinned output fails this test.

  The notebook must also cover every public `sign_*/3` entry point the library exports, read from
  the compiled modules, so a new signer reds here until the notebook demonstrates it, and it must
  state the package version and the protocol requirement that `mix.exs` declares.
  """

  use ExUnit.Case, async: true

  @notebook_path Path.expand("../../examples/report_envelope_roundtrip.livemd", __DIR__)
  @external_resource @notebook_path

  @output_marker ~s(<!-- livebook:{"output":true} -->)

  test "every notebook cell runs against the repository source and returns its pinned output" do
    {setup_cells, cells} =
      @notebook_path
      |> File.read!()
      |> parse_cells()
      |> Enum.split_with(&String.contains?(&1.code, "Mix.install("))

    assert [setup] = setup_cells, "the notebook must have exactly one Mix.install setup cell"

    assert setup.code =~ "{:bounded_authority_report_adapter, path:",
           "the setup cell must install the adapter from this repository by path"

    # A floor on the cell count, so a parser that silently finds nothing cannot pass.
    assert length(cells) >= 15, "expected the notebook's cells, found #{length(cells)}"

    Enum.reduce(cells, {[], Code.env_for_eval(file: @notebook_path)}, fn cell, {binding, env} ->
      assert is_binary(cell.output),
             "the cell at #{@notebook_path}:#{cell.line} has no pinned output block"

      quoted = Code.string_to_quoted!(cell.code, file: @notebook_path, line: cell.line)
      {value, binding, env} = Code.eval_quoted_with_env(quoted, binding, env)
      actual = inspect(value, pretty: true, width: 100)

      assert actual == cell.output, """
      the cell at #{@notebook_path}:#{cell.line} returned a value that differs from its pinned output.
      returned:
      #{actual}
      pinned:
      #{cell.output}
      """

      {binding, env}
    end)
  end

  test "the notebook demonstrates every public signing entry point" do
    code =
      @notebook_path
      |> File.read!()
      |> parse_cells()
      |> Enum.map_join("\n", & &1.code)

    calls =
      for {module, prefix} <- [
            {BoundedAuthorityReportAdapter, "Adapter."},
            {BoundedAuthorityReportAdapter.V3, "Adapter.V3."}
          ],
          {name, 3} <- module.__info__(:functions),
          String.starts_with?(Atom.to_string(name), "sign_") do
        prefix <> Atom.to_string(name) <> "("
      end

    # The known surface at the time of writing: six major-1 signers and four major-3 signers.
    assert length(calls) >= 10

    for call <- calls do
      assert String.contains?(code, call), "the notebook never calls #{call}...)"
    end
  end

  test "every notebook cell is formatted the way mix format formats it" do
    for cell <- parse_cells(File.read!(@notebook_path)) do
      assert IO.iodata_to_binary(Code.format_string!(cell.code)) == cell.code,
             "the cell at #{@notebook_path}:#{cell.line} is not formatted"
    end
  end

  test "the notebook states the package version and the protocol requirement in mix.exs" do
    notebook = File.read!(@notebook_path)
    version = Mix.Project.config()[:version]

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

    for statement <- [
          "release #{version} of `bounded_authority_report_adapter`",
          "`bounded_authority_protocol` `#{requirement}`"
        ] do
      assert String.contains?(notebook, statement),
             "the notebook does not state #{inspect(statement)}; mix.exs moved and the notebook did not"
    end
  end

  # Splits a .livemd file into its Elixir cells. A cell is a fenced elixir block; its pinned
  # output is the next fenced block when only blank lines and the Livebook output marker sit
  # between them.
  defp parse_cells(source) do
    source
    |> String.split("\n")
    |> Enum.with_index(1)
    |> collect_cells([])
  end

  defp collect_cells([], cells), do: Enum.reverse(cells)

  defp collect_cells([{"```elixir", line} | rest], cells) do
    {code_lines, rest} = take_fence(rest, [])
    {output, rest} = take_output(rest)
    cell = %{line: line + 1, code: Enum.join(code_lines, "\n"), output: output}
    collect_cells(rest, [cell | cells])
  end

  defp collect_cells([_line | rest], cells), do: collect_cells(rest, cells)

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
