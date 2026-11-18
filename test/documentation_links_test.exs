defmodule BoundedAuthorityReportAdapter.DocumentationLinksTest do
  use ExUnit.Case, async: true

  alias BoundedAuthorityReportAdapter.Documentation

  test "every relative source link and anchor in recursively discovered documentation resolves" do
    for path <- Documentation.files(),
        {attribute, link} <- attributes(ast!(File.read!(path))),
        attribute in ["href", "src"],
        uri = URI.parse(link),
        is_nil(uri.scheme) and is_nil(uri.host) do
      target =
        case uri.path do
          nil -> path
          "" -> path
          relative -> Path.expand(URI.decode(relative), Path.dirname(path))
        end

      assert File.regular?(target), "#{path}: missing link #{link}"

      if uri.fragment && Path.extname(target) in [".md", ".livemd", ".cheatmd"] do
        ids = target |> File.read!() |> ast!() |> anchors()
        assert URI.decode(uri.fragment) in ids, "#{path}: missing anchor #{link}"
      end
    end
  end

  defp ast!(markdown) do
    {:ok, ast, _messages} = EarmarkParser.as_ast(markdown)
    ast
  end

  defp attributes(nodes) when is_list(nodes), do: Enum.flat_map(nodes, &attributes/1)
  defp attributes({_tag, attrs, children, _}), do: attrs ++ attributes(children)
  defp attributes(_text), do: []

  defp anchors(nodes) when is_list(nodes), do: Enum.flat_map(nodes, &anchors/1)

  defp anchors({tag, attrs, children, _}) do
    explicit = for {"id", id} <- attrs, do: id
    heading = if tag in ~w(h1 h2 h3 h4 h5 h6), do: [slug(text(children))], else: []
    explicit ++ heading ++ anchors(children)
  end

  defp anchors(_text), do: []
  defp text(nodes) when is_list(nodes), do: Enum.map_join(nodes, &text/1)
  defp text({_tag, _attrs, children, _}), do: text(children)
  defp text(value) when is_binary(value), do: value

  defp slug(heading) do
    heading
    |> String.downcase()
    |> String.replace(~r/[^\p{L}\p{N}_\s-]/u, "")
    |> String.replace(~r/\s+/u, "-")
  end
end
