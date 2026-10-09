defmodule BoundedAuthorityReportAdapter.SbomGenerationTest do
  use ExUnit.Case, async: false

  test "supply-chain CI uses the SBOM alias without starting hex_core or SSH" do
    workflow = File.read!(".github/workflows/supply-chain.yml")

    assert [_, command] =
             Regex.run(~r/- name: Generate CycloneDX SBOM\n\s+run: ([^\n]+)/, workflow)

    assert command == "mix sbom.generate"

    assert workflow =~
             ~r/- name: Generate CycloneDX SBOM\n\s+run: mix sbom.generate\n\s+env:\n\s+MIX_ENV: test/

    assert Mix.Project.config()[:aliases][:"sbom.generate"] ==
             ["run --no-start scripts/generate_release_sbom.exs"]
  end

  @tag timeout: 120_000
  test "the SBOM alias generates production CycloneDX without hex_core or SSH running" do
    directory =
      Path.join(
        System.tmp_dir!(),
        "bara-sbom-#{System.pid()}-#{System.unique_integer([:positive])}"
      )

    File.mkdir_p!(directory)
    on_exit(fn -> File.rm_rf!(directory) end)
    output = Path.join(directory, "release.cdx.json")

    check = """
    Mix.Task.reenable("run")
    Mix.Task.run("sbom.generate", System.argv())
    started = Application.started_applications() |> Enum.map(&elem(&1, 0))
    unless :xmerl in started, do: raise("SBOM's xmerl dependency did not start")
    forbidden = Enum.filter([:hex_core, :ssh], &(&1 in started))
    if forbidden != [], do: raise("unexpected applications: \#{inspect(forbidden)}")
    IO.puts("SBOM generated; hex_core and ssh are not running")
    """

    {result, status} =
      System.cmd("mix", ["run", "--no-start", "-e", check, "--", "--output", output],
        env: [{"MIX_ENV", "test"}],
        stderr_to_stdout: true
      )

    assert status == 0, result
    assert result =~ "SBOM generated; hex_core and ssh are not running"

    document = output |> File.read!() |> :json.decode()
    assert document["bomFormat"] == "CycloneDX"
    assert document["specVersion"] == "1.6"
    assert get_in(document, ["metadata", "component", "type"]) == "library"

    components = Enum.map(document["components"], & &1["name"])
    assert "bounded_authority_protocol" in components
    assert "telemetry" in components
    refute "sbom" in components
    refute "protobuf" in components
    refute "hex_core" in components
  end
end
