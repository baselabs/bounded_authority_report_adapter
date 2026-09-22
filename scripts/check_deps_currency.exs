# Dependency currency check — the latest-first policy gate (ADR-0020).
#
# Cross-platform (.exs, run via `mix run --no-start`): the caller-cwd
# contract is preserved — `mix run` executes in the caller's working
# directory, so CI invokes it once per project job from that job's working
# directory and `mix ci` runs it against the library, then the example
# runner does the same from examples/edge_agent. (The .sh predecessor died
# with the Windows pickup — feedback_cross_platform_capability_is_required.)
#
# Classification is on the RENDERED table, never on the exit code (mix
# hex.outdated exits nonzero BOTH on drift and on lookup failure):
#   - "Update possible"        -> resolvable drift  -> exit 1, packages named
#   - "Update not possible"    -> resolver-rejected -> reported with each
#                                  package's requirement chain (mix hex.outdated
#                                  <pkg>); a parent's requirement is a pin, so
#                                  it does not fail the gate
#   - no table rendered        -> currency state UNVERIFIED -> exit 1
# Rows are padded with trailing whitespace, so status matches are anchored on
# \s*$ — a hard-$ pattern would fail open on the padded rows.
#
# Both the direct-dependency table and `--all` (transitives) are classified:
# a resolvable transitive drift is drift.

defmodule BoundedAuthorityReportAdapter.CheckDepsCurrency do
  @moduledoc false

  @table_header ~r/^Dependency\s+(Only\s+)?Current\s+Latest/m
  @drift_row ~r/^(?<row>.+Update possible[[:space:]]*)$/m
  @rejected_row ~r/^(?<row>.+Update not possible[[:space:]]*)$/m
  @noise ~r/authentication session|hex\.user auth/

  def run!(labels) do
    results = Enum.map(labels, &classify/1)
    failures = Enum.count(results, &(&1 != :ok))

    if failures == 0 do
      IO.puts(
        "check-deps-currency: no resolvable drift (direct or transitive); pins are upstream of this gate"
      )
    end

    # Raise on drift rather than System.halt/1: halt(0) kills the whole mix
    # VM, which ended the `mix ci` alias HERE — every later battery step
    # (format, compile, credo, test, coverage, dialyzer, docs, audits,
    # package, reproducibility, example) was unreachable locally while CI —
    # which runs the steps as separate workflow steps — still executed them
    # (found via the B2 release: local "mix ci green" receipts were partial).
    # A raise is nonzero for the CI workflow step and non-fatal to nothing on
    # the success path, where the alias must CONTINUE.
    if failures > 0 do
      raise "check-deps-currency: #{failures} resolvable drift finding(s) above (latest-first policy, ADR-0020)"
    end

    :ok
  end

  defp classify({label, extra_args}) do
    out = mix_out!(["hex.outdated" | extra_args])

    unless Regex.match?(@table_header, out) do
      IO.puts(
        :stderr,
        "check-deps-currency [#{label}]: no dependency table rendered — currency state unverified:"
      )

      IO.puts(:stderr, out)
      :no_table
    else
      drift = capture_rows(out, @drift_row)
      rejected = capture_rows(out, @rejected_row)

      if drift != [] do
        IO.puts(
          :stderr,
          "check-deps-currency [#{label}]: RESOLVABLE DRIFT (latest-first policy, ADR-0020):"
        )

        Enum.each(drift, &IO.puts(:stderr, &1))
      end

      if rejected != [] do
        IO.puts(
          :stderr,
          "check-deps-currency [#{label}]: resolver-rejected updates (requirement chains):"
        )

        Enum.each(rejected, &IO.puts(:stderr, &1))
        print_requirement_chains!(rejected)
      end

      if drift == [], do: :ok, else: :drift
    end
  end

  defp capture_rows(output, regex) do
    Regex.scan(regex, output, capture: [:row])
    |> List.flatten()
    |> Enum.map(&String.trim_trailing/1)
  end

  defp print_requirement_chains!(rejected_rows) do
    rejected_rows
    |> Enum.map(&(String.split(&1, ~r/\s+/, parts: 2) |> hd()))
    |> Enum.uniq()
    |> Enum.each(fn pkg ->
      if byte_size(pkg) > 0 do
        pkg
        |> then(&mix_out!(["hex.outdated", &1]))
        |> String.split("\n")
        |> Enum.reject(&(Regex.match?(@noise, &1) or &1 == ""))
        |> Enum.each(&IO.puts(:stderr, &1))
      end
    end)
  end

  # `mix` is a .cmd shim on Windows and cannot be spawned directly — route
  # through cmd /c there (feedback_cross_platform_capability_is_required).
  defp mix_out!(args) do
    {command, args} =
      case :os.type() do
        {:win32, _} -> {"cmd", ["/c", "mix" | args]}
        _ -> {"mix", args}
      end

    case System.cmd(command, args, stderr_to_stdout: true, env: [{"MIX_ENV", "test"}]) do
      {output, _status} -> output
    end
  end
end

BoundedAuthorityReportAdapter.CheckDepsCurrency.run!(direct: [], all: ["--all"])
