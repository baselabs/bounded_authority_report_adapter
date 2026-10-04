defmodule BoundedAuthorityReportAdapter.DriftProbeTest do
  use ExUnit.Case, async: true

  # The stub harness intercepts git/curl via POSIX exec of shebang scripts.

  setup do
    base =
      Path.join(
        System.tmp_dir!(),
        "bara-drift-probe-#{System.pid()}-#{System.unique_integer([:positive, :monotonic])}"
      )

    repo = Path.join(base, "bounded_authority_report_adapter")
    bin = Path.join(base, "bin")

    File.mkdir_p!(Path.join(repo, "scripts"))
    File.mkdir_p!(bin)
    File.cp!("scripts/check-bap-drift.sh", Path.join(repo, "scripts/check-bap-drift.sh"))
    File.cp!("mix.exs", Path.join(repo, "mix.exs"))
    File.cp!("mix.lock", Path.join(repo, "mix.lock"))
    write_executable!(Path.join(bin, "git"), "#!/bin/sh\nexit 0\n")

    on_exit(fn -> File.rm_rf!(base) end)

    {:ok, base: base, repo: repo, bin: bin}
  end

  test "a malformed nonempty Hex response withholds every release verdict", context do
    write_executable!(Path.join(context.bin, "curl"), "#!/bin/sh\nprintf 'not-json'\n")

    {output, 0} = run_probe(context)

    assert output =~ "hex.pm:  WITHHELD (malformed API response)"
    refute output =~ "is the latest stable"
  end

  test "the probe reads no consumer repository, even when one is checked out beside it",
       context do
    # ADR-0023: no consumer's pin gates a BARA bump, so the probe never reads one. A
    # sibling checkout carrying a protocol pin must leave no trace in the output.
    write_executable!(Path.join(context.bin, "curl"), "#!/bin/sh\nexit 1\n")

    consumer = Path.join(context.base, "bounded_authority")
    File.mkdir_p!(consumer)
    File.write!(Path.join(consumer, "mix.exs"), ~S|{:bounded_authority_protocol, "== 0.2.0"}|)

    File.write!(
      Path.join(consumer, "mix.lock"),
      ~S|%{"bounded_authority_protocol" => {:hex, :bounded_authority_protocol, "0.2.0"}}|
    )

    {output, 0} = run_probe(context)

    assert output =~ "BARA:    locks bounded_authority_protocol"
    refute output =~ "0.2.0"
    refute output =~ ~r/^BA:/m
    refute output =~ "ALIGNMENT"
  end

  defp run_probe(context) do
    path = context.bin <> ":" <> System.fetch_env!("PATH")

    System.cmd("bash", [Path.join(context.repo, "scripts/check-bap-drift.sh")],
      env: [{"PATH", path}],
      stderr_to_stdout: true
    )
  end

  defp write_executable!(path, contents) do
    File.write!(path, contents)
    File.chmod!(path, 0o755)
  end
end
