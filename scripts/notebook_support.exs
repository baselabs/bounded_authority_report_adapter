defmodule BoundedAuthorityReportAdapter.NotebookSupport do
  @moduledoc false

  @marker ~s(<!-- livebook:{"output":true} -->)

  def registry!(root) do
    directory = Path.join(root, "docs/notebooks")

    entries =
      directory
      |> Path.join("registry.txt")
      |> File.read!()
      |> String.split("\n", trim: true)

    files =
      Path.wildcard(Path.join(directory, "**/*.livemd"))
      |> Enum.map(&Path.relative_to(&1, directory))

    unless entries != [] and length(entries) == length(Enum.uniq(entries)) and
             Enum.sort(entries) == Enum.sort(files) do
      raise "notebook registry differs from files"
    end

    Enum.map(entries, &Path.join(directory, &1))
  end

  # LiveMarkdown notebooks use top-level CommonMark fences. A fence's closing delimiter
  # must have the same character and at least the opening length; nested examples are text.
  def cells!(source) do
    source |> String.split("\n") |> Enum.with_index(1) |> collect([])
  end

  defp collect([], cells) do
    if cells == [], do: raise("notebook has no code cells")
    Enum.reverse(cells)
  end

  defp collect([{text, line} | rest], cells) do
    case opening(text) do
      nil ->
        collect(rest, cells)

      {fence, language} ->
        {code, rest} = fenced!(rest, fence, [])

        if language == "elixir" do
          {output, rest} = output!(rest)
          collect(rest, [%{code: code, output: output, line: line + 1} | cells])
        else
          collect(rest, cells)
        end
    end
  end

  defp opening(text) do
    case Regex.run(~r/^ {0,3}(`{3,}|~{3,})([^\n]*)$/, text) do
      [_, "`" <> _ = fence, info] ->
        if String.contains?(info, "`"), do: nil, else: {fence, language(info)}

      [_, fence, info] ->
        {fence, language(info)}

      nil ->
        nil
    end
  end

  defp language(info), do: info |> String.split() |> List.first()

  defp fenced!([], _fence, _lines), do: raise("unclosed notebook fence")

  defp fenced!([{text, _line} | rest], fence, lines) do
    trimmed = String.trim(text)
    delimiter = String.first(fence)

    if String.length(trimmed) >= String.length(fence) and
         String.trim(trimmed, delimiter) == "" do
      {lines |> Enum.reverse() |> Enum.join("\n"), rest}
    else
      fenced!(rest, fence, [text | lines])
    end
  end

  defp output!(lines) do
    case blanks(lines) do
      [{@marker, _} | rest] ->
        case blanks(rest) do
          [{text, _} | rest] ->
            case opening(text) do
              {fence, nil} -> fenced!(rest, fence, [])
              _ -> raise "output marker needs a plain fenced output"
            end

          [] ->
            raise "missing persisted output"
        end

      _ ->
        raise "every notebook cell needs a persisted semantic output"
    end
  end

  defp blanks(lines), do: Enum.drop_while(lines, fn {text, _} -> String.trim(text) == "" end)
end
