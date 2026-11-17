# Run outside a Mix project: elixir scripts/check_livebook.exs.
# Executes the notebook's Hex install cell and checks every saved output with real crypto.
# The separate ExUnit walkthrough checks the working source instead of the registry release.
notebook = Path.expand("../examples/report_envelope_roundtrip.livemd", __DIR__)

cache =
  Path.join(
    System.tmp_dir!(),
    "bara-notebook-#{System.pid()}-#{System.unique_integer([:positive])}"
  )

previous_cache = System.get_env("MIX_INSTALL_DIR")
File.mkdir!(cache)
System.put_env("MIX_INSTALL_DIR", cache)

try do
  source = File.read!(notebook)

  cells =
    Regex.scan(
      ~r/^```elixir[^\n]*\n(.*?)\n```(?:\s*<!-- livebook:\{"output":true\} -->\s*```\n(.*?)\n```)?/ms,
      source
    )

  unless length(cells) > 1 and length(cells) == length(Regex.scan(~r/^```elixir\b/m, source)),
    do: raise("not every notebook Elixir cell was selected")

  unless String.contains?(Enum.at(hd(cells), 1), "Mix.install("),
    do: raise("the first cell must be the install cell")

  {checked, _binding, _env} =
    Enum.reduce(cells, {0, [], Code.env_for_eval(file: notebook)}, fn cell,
                                                                      {checked, binding, env} ->
      [_, code | output] = cell
      quoted = Code.string_to_quoted!(code, file: notebook)
      {value, binding, env} = Code.eval_quoted_with_env(quoted, binding, env)

      case output do
        missing when missing in [[], [""]] ->
          unless checked == 0 and String.contains?(code, "Mix.install("),
            do: raise("only the install cell may omit a pinned output")

          {checked, binding, env}

        [expected] ->
          actual = inspect(value, pretty: true, width: 100)
          unless actual == expected, do: raise("notebook cell #{checked + 1} output differs")
          {checked + 1, binding, env}
      end
    end)

  IO.puts("Hex install and #{checked} notebook outputs passed")
after
  if previous_cache,
    do: System.put_env("MIX_INSTALL_DIR", previous_cache),
    else: System.delete_env("MIX_INSTALL_DIR")

  File.rm_rf!(cache)
end
