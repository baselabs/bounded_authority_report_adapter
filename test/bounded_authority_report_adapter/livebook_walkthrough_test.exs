Code.require_file("../../scripts/notebook_support.exs", __DIR__)

defmodule BoundedAuthorityReportAdapter.LivebookWalkthroughTest do
  @moduledoc "The standalone CI runner executes these notebooks in fresh runtimes."
  use ExUnit.Case, async: true

  alias BoundedAuthorityReportAdapter.NotebookSupport

  test "registered notebooks pin the current release and call every signer in executable code" do
    root = Path.expand("../..", __DIR__)
    version = Mix.Project.config()[:version]
    paths = NotebookSupport.registry!(root)
    assert length(paths) == 7

    calls =
      for path <- paths,
          cell <- NotebookSupport.cells!(File.read!(path)),
          reduce: MapSet.new() do
        calls ->
          quoted = Code.string_to_quoted!(cell.code)

          {_quoted, calls} =
            Macro.prewalk(quoted, calls, fn
              {{:., _, [{:__aliases__, _, parts}, function]}, _, args} = node, calls
              when is_list(args) ->
                module =
                  case parts do
                    [:Adapter | tail] -> Module.concat([BoundedAuthorityReportAdapter | tail])
                    parts -> Module.concat(parts)
                  end

                {node, MapSet.put(calls, {module, function})}

              node, calls ->
                {node, calls}
            end)

          calls
      end

    for path <- paths do
      source = File.read!(path)
      [install | cells] = NotebookSupport.cells!(source)
      assert install.code =~ ~s({:bounded_authority_report_adapter, "== #{version}"})
      assert install.code =~ ~s("#{version}" = to_string(Application.spec)
      assert length(cells) > 1
      assert source =~ "Run all"
      assert source =~ "GenServer.stop(custody)"
      assert source =~ ":clean"
    end

    for module <- [BoundedAuthorityReportAdapter, BoundedAuthorityReportAdapter.V3],
        {function, 3} <- module.__info__(:functions),
        String.starts_with?(Atom.to_string(function), "sign_") do
      assert MapSet.member?(calls, {module, function}),
             "no notebook calls #{inspect(module)}.#{function}/3"
    end
  end

  test "every cell is formatted plain code with its own persisted output" do
    root = Path.expand("../..", __DIR__)

    for path <- NotebookSupport.registry!(root),
        cell <- NotebookSupport.cells!(File.read!(path)) do
      location = "#{path}:#{cell.line}"
      assert cell.code == IO.iodata_to_binary(Code.format_string!(cell.code)), location
      quoted = Code.string_to_quoted!(cell.code)

      expressions =
        case quoted do
          {:__block__, _, expressions} -> expressions
          expression -> [expression]
        end

      for expression <- expressions do
        refute match?({:=, _, [_, {:__block__, _, _}]}, expression),
               "#{location}: put the calls at the top level"

        refute match?({:=, _, [true, {:==, _, _}]}, expression),
               "#{location}: match the call result instead of restating its output"
      end

      refute cell.output == ""
    end
  end

  test "qualification requires local Livebooks under the shared job name" do
    workflow = File.read!(".github/workflows/ci.yml")
    [_header, definitions] = String.split(workflow, "\njobs:\n", parts: 2)
    jobs = Regex.scan(~r/^  ([\w-]+):$/m, definitions) |> Enum.map(&Enum.at(&1, 1))

    assert jobs ==
             ~w(toolchain gate example livebooks-local hex-qualification package attest qualified)

    [_before, qualification] = String.split(definitions, "  qualified:\n", parts: 2)
    assert qualification =~ "    if: always()\n"
    [_, needs] = Regex.run(~r/    needs: \[([^\]]+)\]/, qualification)
    assert String.split(needs, ", ") == List.delete(jobs, "qualified")
    assert workflow =~ "elixir scripts/check_livebooks.exs --local"
    refute workflow =~ "elixir scripts/check_livebooks.exs --published"
  end

  test "the notebook parser rejects missing outputs, mismatched fences and no code" do
    assert_raise RuntimeError, fn -> NotebookSupport.cells!("# Empty") end
    assert_raise RuntimeError, fn -> NotebookSupport.cells!("```elixir\n:ok\n```") end
    assert_raise RuntimeError, fn -> NotebookSupport.cells!("````elixir\n:ok\n```") end

    source = """
    ~~~~elixir
    :ok
    ~~~~
    <!-- livebook:{"output":true} -->
    ```
    :ok
    ```
    """

    assert [%{code: ":ok", output: ":ok"}] =
             Enum.map(NotebookSupport.cells!(source), &Map.take(&1, [:code, :output]))
  end
end
