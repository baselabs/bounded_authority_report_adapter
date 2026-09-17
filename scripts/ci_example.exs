# `mix ci`'s example-job section — reproduces the workflow's example job
# step-for-step (deps · currency · advisory audit · the four build steps)
# from examples/edge_agent, aborting at the first red step like a failed CI
# job. Runs as one .exs because the old `mix cmd --cd ... env MIX_ENV=test
# mix ...` shape needed POSIX env(1) AND spawned a bare `mix` (a .cmd shim on
# Windows) — this runner keeps every step individually spawned, in the
# workflow's order, through the portable shim
# (feedback_cross_platform_capability_is_required).

defmodule BoundedAuthorityReportAdapter.CiExample do
  @moduledoc false

  @edge_dir "examples/edge_agent"

  # The example job's steps, in the workflow's order.
  @steps [
    {"install deps", ["deps.get"]},
    {"check dependency currency (latest-first)",
     ["run", "--no-start", "../../scripts/check_deps_currency.exs"]},
    {"audit dependencies", ["hex.audit"]},
    {"check formatting", ["format", "--check-formatted"]},
    {"compile (warnings as errors)", ["compile", "--warnings-as-errors"]},
    {"lint (credo)", ["credo", "--strict"]},
    {"test", ["test"]}
  ]

  def run! do
    edge = Path.expand(@edge_dir, File.cwd!())

    unless File.dir?(Path.join(edge, "mix.exs")) do
      raise "ci example runner: #{edge} is not the edge-agent project"
    end

    Enum.each(@steps, fn {name, args} ->
      IO.puts("[example] #{name}: mix #{Enum.join(args, " ")}")

      unless step!(args, edge) == 0 do
        raise "ci example runner: step #{inspect(name)} failed (mix #{Enum.join(args, " ")})"
      end
    end)

    IO.puts("[example] all steps green")
  end

  # `mix` is a .cmd shim on Windows and cannot be spawned directly — route
  # through cmd /c there. MIX_ENV rides the environment so every child boots
  # :test exactly as the workflow's job-level env does.
  defp step!(args, dir) do
    {command, args} =
      case :os.type() do
        {:win32, _} -> {"cmd", ["/c", "mix" | args]}
        _ -> {"mix", args}
      end

    {_output, status} =
      System.cmd(command, args,
        cd: dir,
        env: [{"MIX_ENV", "test"}],
        into: IO.stream(:stdio, :line),
        stderr_to_stdout: true
      )

    status
  end
end

BoundedAuthorityReportAdapter.CiExample.run!()
