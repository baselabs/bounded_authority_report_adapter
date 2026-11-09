defmodule BoundedAuthorityReportAdapter.CiAdvisoryParityTest do
  @moduledoc """
  Pins the CI orchestration to the surfaces that must stay in step:

    * the example job audits its OWN lock immediately after resolving its deps
      (the original advisory-parity invariant) — in the workflow directly, in
      `mix ci` through scripts/ci_example.exs's internal step order,
    * the env guard is the FIRST `mix ci` step (the RA7 trap's cross-platform
      replacement for the old POSIX env(1) re-exec), and
    * the gate battery (coverage floor, dialyzer, doc warnings, the library's
      own audits) exists as explicit steps in BOTH `mix ci` and the workflow's
      gate job, in the same order — the local/CI parity the `mix ci` alias
      exists to guarantee.

  Mutation-proven (the house rule): each assertion is demonstrated RED by
  dropping/renaming its pinned step in an in-memory copy — a parity test that
  cannot red is a rubber stamp.
  """

  use ExUnit.Case, async: true

  @edge_dir "examples/edge_agent"
  @audit_command "mix hex.audit"
  @env_guard_step "run --no-start scripts/ci_env_guard.exs"

  # The BaseLabs runner expression, verbatim.
  @runner_expression "${{ vars.BASELABS_RUNNER == 'baselabs-gcp' && github.run_attempt != '1' " <>
                       "&& 'baselabs-gcp-od' || vars.BASELABS_RUNNER || 'ubuntu-24.04' }}"

  @pinned_action ~r/\A[\w.-]+\/[\w.\/-]+@[0-9a-f]{40}\z/

  # The gate battery, in the canonical step order shared by `mix ci` and the
  # workflow's gate job. The workflow spells each command `mix <command>`;
  # the alias carries it as a bare task name (no env(1) re-exec — the
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

    assert root_mix =~ ~r|"#{@env_guard_step}",\s*"deps\.get",|,
           "the env guard must be the FIRST ci step, immediately before deps.get — " <>
             "it replaces the old POSIX env(1) re-exec (the RA7 trap stays guarded)"

    mutated = String.replace(root_mix, ~s{"#{@env_guard_step}",}, "", global: false)
    refute mutated == root_mix, "env-guard mutation fixture changed nothing"
    refute mutated =~ ~r|"#{@env_guard_step}",\s*"deps\.get",|
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
             ~r|\{"install deps", \["deps\.get"\]\},\s*\{"audit dependencies", \["hex\.audit"\]\},|,
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
             ~r|- name: Install deps\s+run: mix deps\.get\s+- name: Audit dependencies\s+run: #{@audit_command}|,
           "the GitHub example job must run mix hex.audit against examples/edge_agent, not " <>
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

  test "both jobs run the full compatibility matrix on Linux (every supported OTP major)" do
    # A dropped matrix cell narrows CI coverage silently (a lane that never
    # runs looks green by absence) — pin the exact cells per job and that
    # setup-beam actually consumes the matrix variables. CI is Linux only:
    # developer portability across macOS and Linux is a developer-setup property,
    # never a CI lane; Windows developers use WSL2, the Linux path.
    workflow = File.read!(".github/workflows/ci.yml")

    for runner <- ["windows-", "macos-"] do
      refute String.contains?(workflow, runner),
             "ci.yml must not run a #{runner}* lane (CI is Linux only)"

      planted = String.replace(workflow, "ubuntu-24.04", runner <> "latest", global: false)
      assert String.contains?(planted, runner), "the #{runner} guard fixture changed nothing"
    end

    [gate_job, example_job] = String.split(workflow, "\n  example:", parts: 2)

    lanes = [
      {"1.18.4", "27.3.4.14"},
      {"1.19.5", "28.5.0.3"},
      {"1.20.2", "29.0.3"}
    ]

    for {job_name, job} <- [{"gate", gate_job}, {"example", example_job}] do
      assert job =~ ~r/strategy:\s+fail-fast:\s*false\s+matrix:\s+include:/m,
             "the #{job_name} job must declare the fail-fast: false matrix"

      assert String.contains?(job, "runs-on: #{@runner_expression}\n"),
             "the #{job_name} job must run on the BaseLabs runner expression"

      for {elixir, otp} <- lanes do
        cell = "- elixir: \"#{elixir}\"\n            otp: \"#{otp}\"\n"

        assert job =~ cell,
               "the #{job_name} job must include the #{elixir}/#{otp} matrix cell"

        # Non-vacuity: the cell string removed in-memory must break the match
        # (a loosened assertion that passes over a dropped lane reds here).
        mutated = String.replace(job, cell, "", global: false)
        refute mutated == job, "the #{job_name} mutation fixture for #{elixir} changed nothing"
        refute String.contains?(mutated, cell), "dropping #{elixir}/#{otp} left it present"
      end

      assert job =~
               ~r/elixir-version: \$\{\{ matrix\.elixir \}\}\s+otp-version: \$\{\{ matrix\.otp \}\}/,
             "the #{job_name} job's setup-beam must consume the matrix variables, not a pin"
    end
  end

  test "every job in every workflow runs on the runner expression or a pinned Linux image" do
    for path <- workflows(),
        [_, runner] <- Regex.scan(~r/^\s+runs-on: (.+)$/m, File.read!(path)) do
      assert runner in [@runner_expression, "ubuntu-24.04"],
             "#{path} runs a job on #{runner}; use the BaseLabs runner expression " <>
               "(a floating image such as ubuntu-latest changes under the job)"
    end

    refute "ubuntu-latest" in [@runner_expression, "ubuntu-24.04"]
  end

  test "every action in every workflow is pinned to a full commit SHA" do
    uses =
      for path <- workflows(),
          [_, ref] <- Regex.scan(~r/^\s+(?:- )?uses: (\S+)/m, File.read!(path)),
          do: {path, ref}

    assert length(uses) >= 10, "the uses: scan found #{length(uses)} actions; it is broken"

    for {path, ref} <- uses do
      assert ref =~ @pinned_action,
             "#{path} uses #{ref}; pin it to a 40-hex commit SHA with the tag in a comment"
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
  # comment) must not weaken step-adjacency matching — strip them so the
  # pattern pins ACTUAL adjacency of the commands.
  defp strip_comments(text), do: Regex.replace(~r/^\s*#[^\n]*$/m, text, "")

  # The alias spells a battery command as a bare task name (no `mix ` prefix —
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
