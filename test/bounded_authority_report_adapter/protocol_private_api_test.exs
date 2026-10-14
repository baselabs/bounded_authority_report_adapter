defmodule BoundedAuthorityReportAdapter.ProtocolPrivateApiTest do
  @moduledoc """
  Fails if any file under `lib/`, `scripts/`, `examples/` or `test/` calls a function of the
  `bounded_authority_protocol` dependency that the dependency does not document.

  The private set is read from the dependency's compiled docs chunks (`Code.fetch_docs/1`), never
  from a list kept here: a function whose docs entry is `:hidden` (`@doc false`), and every
  function of a module whose module docs are `:hidden` (`@moduledoc false`). Default arguments
  are expanded, so a call with fewer arguments maps to its hidden definition.

  Calls are read from the parsed code of every tracked or untracked-but-not-ignored `.ex`, `.exs`
  and `.livemd` file under those roots (Livebook files contribute their `elixir` cells):
  remote calls (`Mod.fun(...)`), the right-hand side of a pipe (one argument more), and
  captures (`&Mod.fun/n`). Aliases are resolved from the file's `alias` directives. A call
  made with `apply/3` or through a variable module is not seen.
  """

  use ExUnit.Case, async: true

  @roots ["lib", "scripts", "examples", "test"]
  @protocol_app :bounded_authority_protocol

  test "no file calls an undocumented bounded_authority_protocol function" do
    private = private_functions()
    calls = Enum.flat_map(scanned_files(), &protocol_calls/1)

    findings =
      for {path, line, {module, name, arity}} <- calls,
          MapSet.member?(private, {module, name, arity}),
          do: "#{path}:#{line}: #{inspect(module)}.#{name}/#{arity}"

    assert findings == [],
           "calls to undocumented bounded_authority_protocol functions:\n" <>
             Enum.join(findings, "\n")
  end

  test "the guard sees the dependency's private functions and this repo's protocol calls" do
    # Known positives for the instrument: the docs chunks yield a non-empty private set, and the
    # scanner finds protocol calls in lib/ (the adapter calls the protocol package throughout).
    assert MapSet.size(private_functions()) > 0

    lib_calls =
      for path <- scanned_files(),
          String.starts_with?(path, "lib/"),
          call <- protocol_calls(path),
          do: call

    assert length(lib_calls) > 10
  end

  defp private_functions do
    {:ok, modules} = :application.get_key(@protocol_app, :modules)

    for module <- modules,
        {:docs_v1, _anno, _language, _format, module_doc, _meta, docs} <-
          [Code.fetch_docs(module)],
        {{kind, name, arity}, _anno, _signature, doc, meta} <- docs,
        kind in [:function, :macro],
        module_doc == :hidden or doc == :hidden,
        callable <- (arity - Map.get(meta, :defaults, 0))..arity//1,
        into: MapSet.new(),
        do: {module, name, callable}
  end

  defp scanned_files do
    {output, 0} =
      System.cmd(
        "git",
        ["ls-files", "-z", "--cached", "--others", "--exclude-standard", "--"] ++ @roots
      )

    output
    |> String.split(<<0>>, trim: true)
    |> Enum.filter(&(Path.extname(&1) in [".ex", ".exs", ".livemd"] and File.regular?(&1)))
  end

  defp protocol_calls(path) do
    path
    |> sources()
    |> Enum.flat_map(fn {source, first_line} ->
      ast = Code.string_to_quoted!(source, file: path, line: first_line, columns: false)
      aliases = aliases(ast)

      for {alias_ast, name, arity, line} <- remote_calls(ast),
          module = resolve(alias_ast, aliases),
          protocol_module?(module),
          do: {path, line, {module, name, arity}}
    end)
  end

  # A .livemd file contributes each elixir cell, with the line it starts on.
  defp sources(path) do
    content = File.read!(path)

    if Path.extname(path) == ".livemd" do
      content
      |> String.split("\n")
      |> Enum.with_index(1)
      |> livemd_cells([])
    else
      [{content, 1}]
    end
  end

  defp livemd_cells([], cells), do: Enum.reverse(cells)

  defp livemd_cells([{text, line} | rest], cells) do
    if Regex.match?(~r/\A```elixir(\s.*)?\z/, text) do
      {code, rest} = Enum.split_while(rest, fn {code_line, _line} -> code_line != "```" end)
      source = Enum.map_join(code, "\n", fn {code_line, _line} -> code_line end)
      livemd_cells(Enum.drop(rest, 1), [{source, line + 1} | cells])
    else
      livemd_cells(rest, cells)
    end
  end

  # alias A.B / alias A.B, as: C / alias A.{B, C} anywhere in the file.
  defp aliases(ast) do
    {_ast, aliases} =
      Macro.prewalk(ast, %{}, fn
        {:alias, _, [target | opts]} = node, acc ->
          {node, Map.merge(acc, alias_entries(target, List.first(opts) || []))}

        node, acc ->
          {node, acc}
      end)

    aliases
  end

  defp alias_entries({:__aliases__, _, segments}, opts) when is_list(opts) do
    if Enum.all?(segments, &is_atom/1) do
      module = Module.concat(segments)

      short =
        case Keyword.get(opts, :as) do
          {:__aliases__, _, [as]} -> as
          _default -> List.last(segments)
        end

      %{short => module}
    else
      %{}
    end
  end

  defp alias_entries({{:., _, [{:__aliases__, _, base}, :{}]}, _, children}, _opts) do
    for {:__aliases__, _, child} <- children, into: %{} do
      {List.last(child), Module.concat(base ++ child)}
    end
  end

  defp alias_entries(_target, _opts), do: %{}

  defp resolve({:__aliases__, _, [head | tail]}, aliases) when is_atom(head) do
    case Map.fetch(aliases, head) do
      {:ok, module} -> Module.concat([module | tail])
      :error -> Module.concat([head | tail])
    end
  end

  defp resolve(_alias_ast, _aliases), do: nil

  defp protocol_module?(module) when is_atom(module) and not is_nil(module) do
    String.starts_with?(Atom.to_string(module), "Elixir.BoundedAuthorityProtocol")
  end

  defp protocol_module?(_module), do: false

  defp remote_calls(ast) do
    {_ast, calls} =
      Macro.prewalk(ast, [], fn
        # Mod.fun(...) on the right of a pipe: one more argument than written.
        {:|>, meta, [left, {{:., dot_meta, [{:__aliases__, _, _} = mod, name]}, call_meta, args}]},
        acc
        when is_atom(name) and is_list(args) ->
          call = {mod, name, length(args) + 1, line(call_meta)}
          {{:|>, meta, [left, {:__seen__, dot_meta, args}]}, [call | acc]}

        # &Mod.fun/arity
        {:/, meta, [{{:., _, [{:__aliases__, _, _} = mod, name]}, call_meta, []}, arity]}, acc
        when is_atom(name) and is_integer(arity) ->
          {{:/, meta, [:__seen__, arity]}, [{mod, name, arity, line(call_meta)} | acc]}

        {{:., _, [{:__aliases__, _, _} = mod, name]}, call_meta, args} = node, acc
        when is_atom(name) and is_list(args) ->
          {node, [{mod, name, length(args), line(call_meta)} | acc]}

        node, acc ->
          {node, acc}
      end)

    Enum.reverse(calls)
  end

  defp line(meta), do: Keyword.get(meta, :line, 0)
end
