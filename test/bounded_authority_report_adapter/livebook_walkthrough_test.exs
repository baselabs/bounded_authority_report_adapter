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
