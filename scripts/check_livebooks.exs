# Standalone only: elixir scripts/check_livebooks.exs --local | --published.
Code.require_file("notebook_support.exs", __DIR__)

defmodule BoundedAuthorityReportAdapter.NotebookRunner do
  @moduledoc false
  alias BoundedAuthorityReportAdapter.NotebookSupport

  @app :bounded_authority_report_adapter

  def run!([mode]) when mode in ["--local", "--published"] do
    root = Path.expand("..", __DIR__)
    notebooks = NotebookSupport.registry!(root)
    temporary = Path.join(System.tmp_dir!(), "bara-notebooks-#{System.pid()}")
    File.mkdir!(temporary)

    try do
      Enum.each(notebooks, &run_notebook!(&1, mode, temporary))
      IO.puts("#{length(notebooks)} notebooks passed #{mode}")
    after
      File.rm_rf!(temporary)
    end
  end

  def run!(["--child", path, mode, cache]) when mode in ["--local", "--published"] do
    root = Path.expand("..", __DIR__)
    [_, version] = Regex.run(~r/@version "([^"]+)"/, File.read!(Path.join(root, "mix.exs")))
    cells = path |> File.read!() |> NotebookSupport.cells!()
    [install | rest] = cells
    quoted = Code.string_to_quoted!(install.code)
    exact = {@app, "== #{version}"}

    {_, occurrences} =
      Macro.prewalk(quoted, 0, fn node, n ->
        {node, n + if(node == exact, do: 1, else: 0)}
      end)

    unless occurrences == 1, do: raise("install cell must pin the exact package version")

    quoted =
      if mode == "--local" do
        Macro.prewalk(quoted, fn
          ^exact -> {@app, [path: root]}
          node -> node
        end)
      else
        quoted
      end

    {value, binding, env} = Code.eval_quoted_with_env(quoted, [], Code.env_for_eval(file: path))
    compare!(install, value, path)
    assert_origin!(root, version, mode, cache)
    processes = MapSet.new(Process.list())
    tables = MapSet.new(:ets.all())

    Enum.reduce(rest, {binding, env}, fn cell, {binding, env} ->
      quoted = Code.string_to_quoted!(cell.code, file: path, line: cell.line)
      {value, binding, env} = Code.eval_quoted_with_env(quoted, binding, env)
      compare!(cell, value, path)
      {binding, env}
    end)

    new_processes = MapSet.difference(MapSet.new(Process.list()), processes)
    new_tables = MapSet.difference(MapSet.new(:ets.all()), tables)

    unless MapSet.size(new_processes) == 0 and MapSet.size(new_tables) == 0 and
             File.ls!() == [] do
      raise "notebook left processes, ETS tables or files behind"
    end
  end

  def run!(_args), do: raise("usage: elixir scripts/check_livebooks.exs --local | --published")

  # A persisted output is the inspected value. Elixir releases lay out the same term
  # differently, so both sides are compared as parsed terms, not as text.
  defp compare!(cell, value, path) do
    actual =
      inspect(value, pretty: true, width: 100, limit: :infinity, printable_limit: :infinity)

    unless term!(actual, path, cell.line) == term!(cell.output, path, cell.line) do
      raise "#{path}:#{cell.line}: output differs:\n#{actual}\n!=\n#{cell.output}"
    end
  end

  defp term!(text, path, line) do
    case Code.string_to_quoted(text) do
      {:ok, quoted} ->
        Macro.prewalk(quoted, &Macro.update_meta(&1, fn _meta -> [] end))

      {:error, _} ->
        raise "#{path}:#{line}: output is not a deterministic Elixir term:\n#{text}"
    end
  end

  defp run_notebook!(path, mode, temporary) do
    name = Path.basename(path, ".livemd")
    work = Path.join(temporary, name)
    cache = Path.join(temporary, "#{name}-install")
    File.mkdir!(work)

    {_output, status} =
      System.cmd(System.find_executable("elixir"), [__ENV__.file, "--child", path, mode, cache],
        cd: work,
        env: [
          {"MIX_INSTALL_DIR", cache},
          {"MIX_ENV", "dev"},
          {"MIX_BUILD_PATH", nil},
          {"MIX_DEPS_PATH", nil},
          {"ERL_LIBS", nil}
        ],
        into: IO.stream(),
        stderr_to_stdout: true
      )

    unless status == 0, do: raise("#{name} failed #{mode}: exit #{status}")
    unless File.ls!(work) == [], do: raise("#{name} left files behind")
    File.rm_rf!(work)
    File.rm_rf!(cache)
  end

  defp assert_origin!(root, version, mode, cache) do
    unless to_string(Application.spec(@app, :vsn)) == version,
      do: raise("resolved package version differs")

    source = BoundedAuthorityReportAdapter.module_info(:compile)[:source] |> to_string()

    case mode do
      "--local" ->
        unless source == Path.join(root, "lib/bounded_authority_report_adapter.ex"),
          do: raise("local mode did not load the checkout")

      "--published" ->
        expected_suffix =
          "/deps/bounded_authority_report_adapter/lib/bounded_authority_report_adapter.ex"

        unless String.starts_with?(source, cache <> "/") and
                 String.ends_with?(source, expected_suffix) do
          raise "published mode did not load a registry dependency"
        end

        locks = Path.wildcard(Path.join(cache, "**/mix.lock"))

        found =
          Enum.any?(locks, fn path ->
            {lock, _} = Code.eval_file(path)

            case Map.get(lock, @app) do
              {:hex, @app, ^version, _, _, _, "hexpm", _} -> true
              _ -> false
            end
          end)

        unless found, do: raise("published mode needs the exact hexpm lock origin")
    end
  end
end

BoundedAuthorityReportAdapter.NotebookRunner.run!(System.argv())
