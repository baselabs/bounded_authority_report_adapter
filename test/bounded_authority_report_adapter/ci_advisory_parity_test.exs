defmodule BoundedAuthorityReportAdapter.CiAdvisoryParityTest do
  @moduledoc """
  Pins the CI orchestration to the surfaces that must stay in step:

    * the example job audits its OWN lock immediately after resolving its deps
      (the original advisory-parity invariant): in the workflow directly, in
      `mix ci` through scripts/ci_example.exs's internal step order,
    * the env guard is the FIRST `mix ci` step (the RA7 trap's cross-platform
      replacement for the old POSIX env(1) re-exec), and
    * the gate battery (coverage floor, dialyzer, doc warnings, the library's
      own audits) exists as explicit steps in BOTH `mix ci` and the workflow's
      gate job, in the same order: the local/CI parity the `mix ci` alias
      exists to guarantee.

  Mutation-proven (the house rule): each assertion is demonstrated RED by
  dropping/renaming its pinned step in an in-memory copy: a parity test that
  cannot red is a rubber stamp.
  """

  use ExUnit.Case, async: true

  @edge_dir "examples/edge_agent"
  @audit_command "mix hex.audit"
  @advisory_command "mix deps.audit"
  @env_guard_step "run --no-start scripts/ci_env_guard.exs"
  @toolchain_reader ~s(scripts/toolchain.sh >> "$GITHUB_OUTPUT")
  @installed_check ~s(scripts/toolchain.sh --installed "elixir=$EXPECTED_ELIXIR" "erlang=$EXPECTED_OTP")

  # A public repository runs on GitHub-hosted runners only, on a pinned image.
  @runner "ubuntu-24.04"

  @pinned_action ~r/\A[\w.-]+\/[\w.\/-]+@[0-9a-f]{40} # v\d+\.\d+\.\d+\z/

  # The gate battery, in the canonical step order shared by `mix ci` and the
  # workflow's gate job. The workflow spells each command `mix <command>`;
  # the alias carries it as a bare task name (no env(1) re-exec: the
  # cross-platform shape).
  @battery [
    {"coverage floor", "mix test --cover"},
    {"dialyzer", "mix dialyzer"},
    {"docs warnings", "mix docs --warnings-as-errors"},
    {"rendered links", "python3 scripts/check_doc_links.py doc"},
    {"hex retirement audit", "mix hex.audit"},
    {"dependency advisory audit", "mix deps.audit"},
    {"package boundary check", "mix run --no-start scripts/check_package.exs"},
    {"release reproducibility", "mix run --no-start scripts/check_reproducible.exs"}
  ]

  test "mix ci boots through the env guard before any step" do
    root_mix = File.read!("mix.exs") |> strip_comments()

    assert root_mix =~ ~r|"#{@env_guard_step}",\s*"deps\.get --check-locked",|,
           "the env guard must be the FIRST ci step, immediately before locked deps.get. " <>
             "It replaces the old POSIX env(1) re-exec (the RA7 trap stays guarded)"

    mutated = String.replace(root_mix, ~s{"#{@env_guard_step}",}, "", global: false)
    refute mutated == root_mix, "env-guard mutation fixture changed nothing"
    refute mutated =~ ~r|"#{@env_guard_step}",\s*"deps\.get --check-locked",|
  end

  test "mix ci audits the edge example immediately after resolving its dependencies" do
    # In the portable alias the example job lives in scripts/ci_example.exs;
    # the invariant is its INTERNAL step order (deps → audit),
    # plus the alias entry that runs it.
    root_mix = File.read!("mix.exs") |> strip_comments()
    runner = File.read!("scripts/ci_example.exs")

    assert root_mix =~ ~r|"run --no-start scripts/ci_example\.exs"|,
           "mix ci must run the example job's runner as its example section"

    assert runner =~
             ~r|\{"install deps", \["deps\.get", "--check-locked"\]\},\s*\{"audit dependencies", \["hex\.audit"\]\},\s*\{"audit dependency advisories", \["deps\.audit"\]\},|,
           "the example runner must audit the edge example's own lock immediately " <>
             "after resolving its dependencies"
  end

  test "the GitHub example job audits its owner-local lock after dependency resolution" do
    workflow = File.read!(".github/workflows/ci.yml")
    [_gate_job, example_job] = String.split(workflow, "\n  example:", parts: 2)

    parsed = YamlElixir.read_from_file!(".github/workflows/ci.yml")

    assert get_in(parsed, ["jobs", "example", "defaults", "run"]) == %{
             "shell" => "bash",
             "working-directory" => @edge_dir
           },
           "the GitHub example job must bind every mix command to examples/edge_agent, " <>
             "under Bash with pipefail"

    assert example_job =~
             ~r|- name: Install deps\s+run: mix deps\.get --check-locked\s+- name: Audit dependencies\s+run: #{@audit_command}\s+- name: Audit dependency advisories\s+run: #{@advisory_command}|,
           "the GitHub example job must run both audits against examples/edge_agent, not " <>
             "the root library lock"
  end

  test "mix ci runs the gate battery in the canonical order right after credo, with no plain test step" do
    root_mix = File.read!("mix.exs") |> strip_comments()

    assert root_mix =~
             ~r|"credo --strict",\s*#{alias_battery_pattern()}|,
           "mix ci must run the gate battery (coverage floor, dialyzer, docs warnings, " <>
             "the library's own audits) in the canonical order immediately after credo"

    # Mix runs a task once per invocation: a plain "test" before "test --cover" turns the
    # coverage step, and with it the coverage floor, into a silent no-op.
    refute root_mix =~ ~r|"test",|,
           "mix ci must not run a plain \"test\" step: it would skip \"test --cover\""
  end

  test "the GitHub gate job runs the same battery steps in the same order" do
    workflow = File.read!(".github/workflows/ci.yml") |> strip_comments()
    [gate_job, _] = String.split(workflow, "\n  example:", parts: 2)

    assert gate_job =~
             ~r|#{workflow_battery_pattern()}|,
           "the gate job must run every battery step after the test step, in the canonical " <>
             "order shared with mix ci"
  end

  test "each battery step is independently pinned (dropping any one step reds parity)" do
    # Non-vacuity, PATTERN-level: each battery step, dropped from an in-memory
    # copy of EACH orchestration surface, must make that surface's PRODUCTION
    # parity pattern fail to match. Asserting the raw command string absent
    # proves only that the fixture edits text; asserting the pattern reds is
    # what proves the gate (a pattern later loosened into vacuity reds HERE,
    # not just in production).
    workflow = File.read!(".github/workflows/ci.yml") |> strip_comments()
    [gate_job, _example_job] = String.split(workflow, "\n  example:", parts: 2)
    root_mix = File.read!("mix.exs") |> strip_comments()

    for {_name, command} <- @battery do
      # The workflow surface: swap the step's command out, then the production
      # battery pattern must no longer match the gate job.
      mutated_gate =
        String.replace(gate_job, "run: #{command}\n", "run: mix test\n", global: false)

      refute mutated_gate == gate_job,
             "the workflow mutation fixture for #{command} did not change the gate job. " <>
               "The mutation proof is not exercising the red path"

      refute mutated_gate =~ Regex.compile!(workflow_battery_pattern()),
             "the parity pattern still matches the gate job with #{command} dropped. " <>
               "The gate would stay green over a missing step"

      # The mix ci alias surface: drop the quoted alias entry, then the
      # production alias pattern must no longer match mix.exs.
      mutated_alias =
        String.replace(root_mix, ~s{"#{alias_form(command)}",}, "", global: false)

      refute mutated_alias == root_mix,
             "the alias mutation fixture for #{command} did not change mix.exs. " <>
               "The mutation proof is not exercising the red path"

      refute mutated_alias =~ Regex.compile!(alias_battery_pattern()),
             "the alias parity pattern still matches mix.exs with #{command} dropped. " <>
               "The gate would stay green over a missing step"
    end
  end

  test "both jobs consume every declared compatibility lane through the toolchain reader" do
    workflow = File.read!(".github/workflows/ci.yml")
    parsed = YamlElixir.read_from_file!(".github/workflows/ci.yml")
    {output, 0} = System.cmd(Path.expand("scripts/toolchain.sh"), [".tool-versions"])

    for runner <- ["windows-", "macos-"] do
      refute String.contains?(workflow, runner)
      planted = String.replace(workflow, @runner, runner <> "latest", global: false)
      assert String.contains?(planted, runner), "the runner guard fixture changed nothing"
    end

    versions =
      output
      |> String.split("\n", trim: true)
      |> Map.new(fn line ->
        [key, value] = String.split(line, "=", parts: 2)
        {key, value}
      end)

    assert versions["elixir"] == "1.20.2-otp-29"
    assert versions["otp"] == "29.0.3"
    assert versions["erlang"] == versions["otp"]

    assert :json.decode(versions["beam_lanes"]) == [
             %{"elixir" => "1.18.4-otp-27", "otp" => "27.3.4.14"},
             %{"elixir" => "1.19.5-otp-28", "otp" => "28.5.0.3"}
           ]

    [_, reader, matrix_step] = parsed["jobs"]["toolchain"]["steps"]
    assert reader["id"] == "versions"
    assert reader["run"] == @toolchain_reader

    assert parsed["jobs"]["toolchain"]["outputs"] == %{
             "beam_matrix" => "${{ steps.matrix.outputs.beam_matrix }}"
           }

    assert matrix_step["id"] == "matrix"

    assert matrix_step["env"] == %{
             "ELIXIR" => "${{ steps.versions.outputs.elixir }}",
             "OTP" => "${{ steps.versions.outputs.otp }}",
             "BEAM_LANES" => "${{ steps.versions.outputs.beam_lanes }}"
           }

    assert build_beam_matrix(matrix_step, versions) == %{
             "include" => [
               %{"elixir" => "1.18.4-otp-27", "otp" => "27.3.4.14"},
               %{"elixir" => "1.19.5-otp-28", "otp" => "28.5.0.3"},
               %{"elixir" => "1.20.2-otp-29", "otp" => "29.0.3"}
             ]
           }

    primary_only = %{"elixir" => "1.21.0-otp-30", "otp" => "30.0.0", "beam_lanes" => "[]"}

    assert build_beam_matrix(matrix_step, primary_only) == %{
             "include" => [%{"elixir" => "1.21.0-otp-30", "otp" => "30.0.0"}]
           }

    for {job_name, label} <- [{"gate", "Gate battery"}, {"example", @edge_dir}] do
      job = parsed["jobs"][job_name]
      assert job["needs"] == "toolchain"
      assert job["runs-on"] == @runner
      assert job["name"] == "#{label} (Elixir ${{ matrix.elixir }} / OTP ${{ matrix.otp }})"
      assert job["strategy"]["fail-fast"] == false
      matrix = job["strategy"]["matrix"]
      assert_beam_matrix(matrix)

      for invalid <- [
            nil,
            %{"beam" => matrix},
            "${{ fromJSON(needs.toolchain.outputs.beam_lanes) }}"
          ] do
        assert_raise ExUnit.AssertionError, fn -> assert_beam_matrix(invalid) end
      end

      setup = Enum.find(job["steps"], &(&1["uses"] == "./.github/actions/setup-beam"))

      assert setup["with"] == %{
               "elixir-version" => "${{ matrix.elixir }}",
               "otp-version" => "${{ matrix.otp }}"
             }
    end
  end

  test "BEAM setup reads shared outputs and immediately checks the installed pair" do
    setup = YamlElixir.read_from_file!(".github/actions/setup-beam/action.yml")
    steps = setup["runs"]["steps"]
    assert_shared_beam_setup(steps)

    for index <- [0, 2] do
      mutated = List.update_at(steps, index, &Map.put(&1, "run", "true"))
      assert_raise ExUnit.AssertionError, fn -> assert_shared_beam_setup(mutated) end
    end

    [reader, install, check] = steps

    assert_raise ExUnit.AssertionError, fn ->
      assert_shared_beam_setup([reader, check, install])
    end

    for {path, job_name} <- [
          {".github/workflows/ci.yml", "livebooks-local"},
          {".github/workflows/ci.yml", "hex-qualification"},
          {".github/workflows/ci.yml", "package"},
          {".github/workflows/publish.yml", "published-livebooks"}
        ] do
      workflow = YamlElixir.read_from_file!(path)
      job_steps = workflow["jobs"][job_name]["steps"]
      setup_step = Enum.find(job_steps, &(&1["uses"] == "./.github/actions/setup-beam"))
      assert setup_step
      refute Map.has_key?(setup_step, "with")
    end
  end

  test "workflows and composites use no alternate toolchain readers or runtime literals" do
    for path <- workflows() ++ Path.wildcard(".github/actions/**/action.yml") do
      source = path |> File.read!() |> strip_comments()
      refute source =~ ".tool-versions", path
      refute source =~ ~r/\b[\w-]*version-file:/, path
      refute source =~ ~r/\b(?:bash|sh)\s+scripts\/toolchain\.sh/, path
      refute source =~ ~r/\b[\w-]+-version:\s*['"]?\d/, path
    end
  end

  test "publication reads the qualified toolchain before entering the upload environment" do
    jobs = YamlElixir.read_from_file!(".github/workflows/publish.yml")["jobs"]
    verify = jobs["verify-provenance"]

    assert Enum.any?(
             verify["steps"],
             &(&1["run"] == ~s|scripts/toolchain.sh >> "$GITHUB_OUTPUT"|)
           )

    for name <- ["upload", "read-back"] do
      steps = jobs[name]["steps"]
      setup = Enum.find(steps, &String.starts_with?(&1["uses"] || "", "erlef/setup-beam@"))
      assert setup["with"]["version-type"] == "strict"
      assert setup["with"]["elixir-version"] == "${{ needs.verify-provenance.outputs.elixir }}"
      assert setup["with"]["otp-version"] == "${{ needs.verify-provenance.outputs.otp }}"

      drift = Enum.find(steps, &(&1["name"] == "Refuse BEAM runtime drift"))
      assert drift["working-directory"] == "${{ runner.temp }}"
      assert drift["run"] =~ ~s(test "$elixir_version" = "$EXPECTED_ELIXIR")
      assert drift["run"] =~ ~s(test "$otp_version" = "$EXPECTED_OTP")
    end
  end

  test "every job in every workflow runs on the pinned GitHub-hosted image" do
    for path <- workflows(),
        [_, runner] <- Regex.scan(~r/^\s+runs-on: (.+)$/m, File.read!(path)) do
      assert runner == @runner,
             "#{path} runs a job on #{runner}; use #{@runner} (a public repository never " <>
               "uses an organization runner, and a floating image changes under the job)"
    end
  end

  test "external actions are release-pinned and local composites are inspected too" do
    uses =
      for path <- workflows() ++ Path.wildcard(".github/actions/**/action.yml"),
          [_, ref] <- Regex.scan(~r/^\s+(?:- )?uses: ([^\n]+)/m, File.read!(path)),
          do: {path, ref}

    assert length(uses) >= 10, "the uses: scan found #{length(uses)} actions; it is broken"

    for {path, ref} <- uses do
      if String.starts_with?(ref, "./") do
        assert ref in ["./.github/actions/setup-beam", "./.github/workflows/supply-chain.yml"]
        path = if String.ends_with?(ref, ".yml"), do: ref, else: Path.join(ref, "action.yml")
        assert File.regular?(path)
      else
        assert ref =~ @pinned_action or
                 ref =~ ~r|\Abaselabs/\.github/\.github/actions/hex-publish@[0-9a-f]{40}\z|,
               "#{path} uses #{ref}; pin it to a 40-hex commit SHA"
      end
    end

    # Non-vacuity: a tag reference fails the same pattern.
    refute "actions/attest@v4" =~ @pinned_action
    refute "actions/checkout@v4.4.0" =~ @pinned_action
  end

  test "pushes that change only Markdown or docs still run CI" do
    # The doc-sample, docs-currency, Livebook and vocabulary tests read the guides.
    workflow = File.read!(".github/workflows/ci.yml")

    refute workflow =~ "paths-ignore",
           "ci.yml skips some paths, but the tests read the Markdown guides and docs/"
  end

  test "local notebooks and rendered links qualify; published notebooks run after upload" do
    workflow = File.read!(".github/workflows/ci.yml")
    aliases = File.read!("mix.exs")
    [_, qualified] = String.split(workflow, "\n  qualified:", parts: 2)

    assert workflow =~ "  livebooks-local:"
    assert workflow =~ "run: elixir scripts/check_livebooks.exs --local"
    assert qualified =~ "livebooks-local"
    assert aliases =~ "cmd elixir scripts/check_livebooks.exs --local"
    assert workflow =~ "run: python3 scripts/check_doc_links.py doc"

    # Qualification never installs this package from Hex: a version commit names a
    # version Hex does not serve yet, so it could never land.
    refute workflow =~ "--published"
    refute aliases =~ "--published"

    publish = YamlElixir.read_from_file!(".github/workflows/publish.yml")["jobs"]
    published = publish["published-livebooks"]
    assert published["needs"] == "read-back"
    assert published["if"] == publish["upload"]["if"]
    refute Map.has_key?(published, "environment")
    refute inspect(published) =~ "secrets."

    assert Enum.any?(
             published["steps"],
             &(&1["run"] == "elixir scripts/check_livebooks.exs --published")
           )
  end

  defp workflows, do: Path.wildcard(".github/workflows/*.yml")

  defp assert_beam_matrix(matrix) do
    assert matrix == "${{ fromJSON(needs.toolchain.outputs.beam_matrix) }}"
  end

  defp build_beam_matrix(step, versions) do
    {output, 0} =
      System.cmd("bash", ["-euo", "pipefail", "-c", step["run"]],
        env: [
          {"ELIXIR", versions["elixir"]},
          {"OTP", versions["otp"]},
          {"BEAM_LANES", versions["beam_lanes"]},
          {"GITHUB_OUTPUT", "/dev/stdout"}
        ]
      )

    assert "beam_matrix=" <> matrix = String.trim(output)
    :json.decode(matrix)
  end

  defp assert_shared_beam_setup(steps) do
    assert [reader, install, check] = steps
    assert reader["id"] == "versions"
    assert reader["run"] == @toolchain_reader
    assert reader["working-directory"] == "${{ github.workspace }}"
    assert install["uses"]
    assert String.starts_with?(install["uses"], "erlef/setup-beam@")

    versions = %{
      "elixir-version" => "${{ inputs.elixir-version || steps.versions.outputs.elixir }}",
      "otp-version" => "${{ inputs.otp-version || steps.versions.outputs.otp }}"
    }

    assert install["with"] ==
             Map.merge(versions, %{"version-type" => "strict", "install-hex" => false})

    assert check["working-directory"] == "${{ github.workspace }}"
    assert check["run"] == @installed_check

    assert check["env"] == %{
             "EXPECTED_ELIXIR" => versions["elixir-version"],
             "EXPECTED_OTP" => versions["otp-version"]
           }
  end

  # Full-line comments (the alias's step annotations, the workflow's battery
  # comment) must not weaken step-adjacency matching: strip them so the
  # pattern pins ACTUAL adjacency of the commands.
  defp strip_comments(text), do: Regex.replace(~r/^\s*#[^\n]*$/m, text, "")

  # The alias spells a battery command as a bare task name (no `mix ` prefix
  # the cross-platform, env(1)-free shape).
  defp alias_form("mix " <> rest), do: rest
  defp alias_form(command), do: "cmd " <> command

  # The mix ci alias shape: comma-quoted bare task names, in battery order
  # (each entry carries its own quotes; the join is just comma + whitespace).
  defp alias_battery_pattern do
    @battery
    |> Enum.map_join(~s{,\\s*}, fn {_name, command} ->
      Regex.escape(~s{"#{alias_form(command)}"})
    end)
  end

  # The workflow shape: named steps with run commands, in battery order.
  defp workflow_battery_pattern do
    @battery
    |> Enum.map_join("\\s+", fn {_name, command} ->
      "- name: [^\\n]+\\s+run: #{Regex.escape(command)}"
    end)
  end
end
