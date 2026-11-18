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
    {"hex retirement audit", "mix hex.audit"},
    {"dependency advisory audit", "mix deps.audit"},
    {"package boundary check", "mix run --no-start scripts/check_package.exs"},
    {"release reproducibility", "mix run --no-start scripts/check_reproducible.exs"}
  ]

  test "mix ci boots through the env guard before any step" do
    root_mix = File.read!("mix.exs") |> strip_comments()

    assert root_mix =~ ~r|"#{@env_guard_step}",\s*"deps\.get --check-locked",|,
           "the env guard must be the FIRST ci step, immediately before locked deps.get — " <>
             "it replaces the old POSIX env(1) re-exec (the RA7 trap stays guarded)"

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

    assert example_job =~
             ~r|defaults:\s+run:\s+working-directory: #{@edge_dir}|,
           "the GitHub example job must bind every mix command to examples/edge_agent"

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
             ~r|- name: Test \(includes the conformance round-trip\)\s+run: mix test\s+#{workflow_battery_pattern()}|,
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
             "the workflow mutation fixture for #{command} did not change the gate job — " <>
               "the mutation proof is not exercising the red path"

      refute mutated_gate =~ Regex.compile!(workflow_battery_pattern()),
             "the parity pattern still matches the gate job with #{command} dropped — " <>
               "the gate would stay green over a missing step"

      # The mix ci alias surface: drop the quoted alias entry, then the
      # production alias pattern must no longer match mix.exs.
      mutated_alias =
        String.replace(root_mix, ~s{"#{alias_form(command)}",}, "", global: false)

      refute mutated_alias == root_mix,
             "the alias mutation fixture for #{command} did not change mix.exs — " <>
               "the mutation proof is not exercising the red path"

      refute mutated_alias =~ Regex.compile!(alias_battery_pattern()),
             "the alias parity pattern still matches mix.exs with #{command} dropped — " <>
               "the gate would stay green over a missing step"
    end
  end

  test "both jobs consume every declared compatibility lane through the toolchain reader" do
    workflow = File.read!(".github/workflows/ci.yml")
    declaration = File.read!(".tool-versions")

    for runner <- ["windows-", "macos-"] do
      refute String.contains?(workflow, runner)
      planted = String.replace(workflow, @runner, runner <> "latest", global: false)
      assert String.contains?(planted, runner), "the runner guard fixture changed nothing"
    end

    versions =
      declaration
      |> String.split("\n", trim: true)
      |> Map.new(fn line ->
        [tool | values] = String.split(line)
        {tool, values}
      end)

    assert versions["elixir"] == ["1.20.2-otp-29", "1.18.4-otp-27", "1.19.5-otp-28"]
    assert versions["erlang"] == ["29.0.3", "27.3.4.14", "28.5.0.3"]

    reader = workflow |> String.split("\n  gate:", parts: 2) |> hd()
    assert reader =~ "pathlib.Path('.tool-versions').read_text()"
    assert reader =~ "for elixir in versions['elixir']:"
    assert reader =~ "otp.split('.')[0] == match[2]"
    assert reader =~ "if len(matches) != 1:"
    assert reader =~ "lanes.append({'elixir': elixir, 'otp': matches[0]})"

    [_, gate_and_example] = String.split(workflow, "\n  gate:", parts: 2)
    [gate_job, example_and_qualified] = String.split(gate_and_example, "\n  example:", parts: 2)
    [example_job, _] = String.split(example_and_qualified, "\n  qualified:", parts: 2)
    matrix = "include: ${{ fromJSON(needs.toolchain.outputs.lanes) }}"

    for {job_name, job} <- [{"gate", gate_job}, {"example", example_job}] do
      assert job =~ "needs: toolchain"
      assert job =~ ~r/strategy:\s+fail-fast:\s*false\s+matrix:\s+include:/m
      assert job =~ "runs-on: #{@runner}\n"
      assert job =~ matrix, "#{job_name} must consume the reader's whole lane list"
      mutated = String.replace(job, matrix, "include: []", global: false)
      refute mutated == job
      refute mutated =~ matrix

      assert job =~
               ~r/uses: \.\/\.github\/actions\/setup-beam\s+with:\s+elixir-version: \$\{\{ matrix\.elixir \}\}\s+otp-version: \$\{\{ matrix\.otp \}\}/
    end

    setup = File.read!(".github/actions/setup-beam/action.yml")
    assert setup =~ "version-type: strict"
    assert setup =~ "elixir not in versions.get('elixir', [])"
    assert setup =~ "otp not in versions.get('erlang', [])"
    assert setup =~ "actual_otp == System.fetch_env!(\"EXPECTED_OTP\")"
    assert setup =~ "System.version() == version"
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
        assert ref == "./.github/actions/setup-beam"
        assert File.regular?(Path.join(ref, "action.yml"))
      else
        assert ref =~ @pinned_action,
               "#{path} uses #{ref}; pin it to a 40-hex commit SHA with its release comment"
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

  defp workflows, do: Path.wildcard(".github/workflows/*.yml")

  # Full-line comments (the alias's step annotations, the workflow's battery
  # comment) must not weaken step-adjacency matching: strip them so the
  # pattern pins ACTUAL adjacency of the commands.
  defp strip_comments(text), do: Regex.replace(~r/^\s*#[^\n]*$/m, text, "")

  # The alias spells a battery command as a bare task name (no `mix ` prefix
  # the cross-platform, env(1)-free shape).
  defp alias_form("mix " <> rest), do: rest

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
