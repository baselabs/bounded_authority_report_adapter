defmodule BoundedAuthorityReportAdapter.CiAdvisoryParityTest do
  @moduledoc """
  Pins the CI orchestration to the surfaces that must stay in step:

    * the example job audits its OWN lock immediately after resolving its deps
      (the original advisory-parity invariant) — in the workflow directly, in
      `mix ci` through scripts/ci_example.exs's internal step order,
    * the dependency-currency gate (ADR-0020) runs immediately after
      dependency resolution on BOTH surfaces, through the portable .exs,
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
  @currency_exs "scripts/check_deps_currency.exs"
  @env_guard_step "run --no-start scripts/ci_env_guard.exs"

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
    # the invariant is its INTERNAL step order (deps → currency → audit),
    # plus the alias entry that runs it.
    root_mix = File.read!("mix.exs") |> strip_comments()
    runner = File.read!("scripts/ci_example.exs")

    assert root_mix =~ ~r|"run --no-start scripts/ci_example\.exs"|,
           "mix ci must run the example job's runner as its example section"

    assert runner =~
             ~r|\{"install deps", \["deps\.get"\]\},\s*\{"check dependency currency \(latest-first\)",\s*\[[^\]]*\]\},\s*\{"audit dependencies", \["hex\.audit"\]\},|,
           "the example runner must audit the edge example's own lock immediately " <>
             "after resolving its dependencies (currency between them)"
  end

  test "the GitHub example job audits its owner-local lock after dependency resolution" do
    workflow = File.read!(".github/workflows/ci.yml")
    [_gate_job, example_job] = String.split(workflow, "\n  example:", parts: 2)

    assert example_job =~
             ~r|defaults:\s+run:\s+working-directory: #{@edge_dir}|,
           "the GitHub example job must bind every mix command to examples/edge_agent"

    assert example_job =~
             ~r|- name: Install deps\s+run: mix deps\.get\s+- name: Check dependency currency \(latest-first\)\s+run: mix run --no-start \.\./\.\./scripts/check_deps_currency\.exs\s+- name: Audit dependencies\s+run: #{@audit_command}|,
           "the GitHub example job must run mix hex.audit against examples/edge_agent, not " <>
             "the root library lock"
  end

  test "the dependency-currency gate runs in both surfaces immediately after dependency resolution" do
    # ADR-0020's wiring pin, both surfaces, adjacency to deps.get (drift is
    # known at resolution time; the earlier it reds, the less work follows).
    # Mutation-proven: dropping the step from either surface must break the
    # adjacency pattern — a gate the orchestration silently skips is absent.
    root_mix = File.read!("mix.exs") |> strip_comments()
    workflow = File.read!(".github/workflows/ci.yml") |> strip_comments()
    [gate_job, _] = String.split(workflow, "\n  example:", parts: 2)

    alias_pattern = ~r|"deps\.get",\s*"run --no-start scripts/check_deps_currency\.exs",|

    workflow_pattern =
      ~r|- name: Install deps\s+run: mix deps\.get\s+- name: Check dependency currency \(latest-first\)\s+run: mix run --no-start scripts/check_deps_currency\.exs|

    assert root_mix =~ alias_pattern,
           "mix ci must run the currency gate immediately after the library resolves its deps"

    assert gate_job =~ workflow_pattern,
           "the gate job must run the currency step immediately after dependency install"

    mutated_alias =
      String.replace(
        root_mix,
        ~s{"run --no-start scripts/check_deps_currency.exs",},
        "",
        global: false
      )

    refute mutated_alias == root_mix, "alias mutation fixture changed nothing"
    refute mutated_alias =~ alias_pattern, "alias adjacency survives a dropped currency step"

    mutated_gate =
      String.replace(gate_job, "run: mix run --no-start #{@currency_exs}\n", "run: mix test\n",
        global: false
      )

    refute mutated_gate == gate_job, "workflow mutation fixture changed nothing"
    refute mutated_gate =~ workflow_pattern, "workflow adjacency survives a dropped currency step"
  end

  test "mix ci runs the gate battery in the canonical order after the plain test step" do
    root_mix = File.read!("mix.exs") |> strip_comments()

    assert root_mix =~
             ~r|"test",\s*#{alias_battery_pattern()}|,
           "mix ci must run the gate battery (coverage floor, dialyzer, docs warnings, " <>
             "the library's own audits) in the canonical order immediately after the test step"
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

  test "both jobs run the full compatibility matrix (every supported OTP major + the windows lane)" do
    # A dropped matrix cell narrows CI coverage silently (a lane that never
    # runs looks green by absence) — pin the exact cells per job and that
    # setup-beam actually consumes the matrix variables. The windows-latest
    # cell is the owner's cross-platform standard (2026-09-16): clone → build
    # → test must hold on Windows, proven by CI on the pinned versions.
    workflow = File.read!(".github/workflows/ci.yml")
    [gate_job, example_job] = String.split(workflow, "\n  example:", parts: 2)

    lanes = [
      {"ubuntu-latest", "1.18.4", "27.3.4.14"},
      {"ubuntu-latest", "1.19.5", "28.5.0.3"},
      {"ubuntu-latest", "1.20.2", "29.0.3"},
      {"windows-latest", "1.20.2", "29.0.3"}
    ]

    for {job_name, job} <- [{"gate", gate_job}, {"example", example_job}] do
      assert job =~ ~r/strategy:\s+fail-fast:\s*false\s+matrix:\s+include:/m,
             "the #{job_name} job must declare the fail-fast: false matrix"

      assert job =~ ~r/runs-on: \$\{\{ matrix\.os \}\}/,
             "the #{job_name} job must run on the matrix OS, not a pinned runner"

      for {os, elixir, otp} <- lanes do
        cell = "- os: #{os}\n            elixir: \"#{elixir}\"\n            otp: \"#{otp}\"\n"

        assert job =~ cell,
               "the #{job_name} job must include the #{os} #{elixir}/#{otp} matrix cell"

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
