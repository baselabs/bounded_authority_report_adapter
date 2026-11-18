defmodule BoundedAuthorityReportAdapter.Documentation do
  @moduledoc false

  def files do
    {paths, 0} =
      System.cmd("git", ["ls-files", "--cached", "--others", "--exclude-standard", "-z"])

    paths
    |> String.split(<<0>>, trim: true)
    |> Enum.uniq()
    |> Enum.filter(&(File.regular?(&1) and Path.extname(&1) in [".md", ".livemd", ".cheatmd"]))
    |> Enum.sort()
  end

  def blocks(markdown) do
    case EarmarkParser.as_ast(markdown) do
      {:ok, ast, _messages} -> walk(ast)
      {:error, _ast, messages} -> raise "invalid Markdown: #{inspect(messages)}"
    end
  end

  defp walk(nodes) when is_list(nodes), do: Enum.flat_map(nodes, &walk/1)

  defp walk({"pre", _, [{"code", attrs, [code], _}], _}) do
    language =
      attrs
      |> List.keyfind("class", 0, {"class", ""})
      |> elem(1)
      |> String.split()
      |> List.first()

    if language == "elixir" do
      [%{code: code, line: 1, fragment?: false}]
    else
      if language in ["ex", "exs", "iex"], do: raise("unsupported Elixir fence alias")
      []
    end
  end

  defp walk({_tag, _attrs, children, _meta}), do: walk(children)
  defp walk(_text), do: []
end
