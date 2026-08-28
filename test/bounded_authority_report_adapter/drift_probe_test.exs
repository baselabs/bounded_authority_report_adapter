defmodule BoundedAuthorityReportAdapter.DriftProbeTest do
  use ExUnit.Case, async: true

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

  test "the BA pin parser selects bounded_authority_protocol rather than an earlier git ref",
       context do
    write_executable!(Path.join(context.bin, "curl"), "#!/bin/sh\nexit 1\n")

    ba = Path.join(context.base, "bounded_authority")
    File.mkdir_p!(ba)

    File.write!(
      Path.join(ba, "mix.exs"),
      """
      {:unrelated, git: "https://example.invalid/other.git", ref: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
      {:bounded_authority_protocol,
       git: "https://github.com/baselabs/bounded_authority_protocol.git",
       ref: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
      """
    )

    {output, 0} = run_probe(context)

    assert output =~ "BA:      pins bbbbbbbbbbbb"
    refute output =~ "BA:      pins aaaaaaaaaaaa"
  end

  test "the BA pin parser reports an exact Hex protocol dependency", context do
    write_executable!(Path.join(context.bin, "curl"), "#!/bin/sh\nexit 1\n")

    ba = Path.join(context.base, "bounded_authority")
    File.mkdir_p!(ba)

    File.write!(
      Path.join(ba, "mix.exs"),
      ~S|{:bounded_authority_protocol, "== 0.2.0"}|
    )

    File.write!(
      Path.join(ba, "mix.lock"),
      ~S|%{"bounded_authority_protocol" => {:hex, :bounded_authority_protocol, "0.2.0"}}|
    )

    {output, 0} = run_probe(context)

    assert output =~ "BA:      pins bounded_authority_protocol 0.2.0 from Hex"
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
