defmodule BoundedAuthorityReportAdapter.CiAdvisoryParityTest do
  @moduledoc """
  Pins the CI orchestration to the two surfaces that must stay in step:

    * the example job audits its OWN lock immediately after resolving its deps
      (the original advisory-parity invariant), and
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

  # The gate battery, in the canonical step order shared by `mix ci` and the
  # workflow's gate job.
  @battery [
    {"coverage floor", "mix test --cover"},
    {"dialyzer", "mix dialyzer"},
    {"docs warnings", "mix docs --warnings-as-errors"},
    {"hex retirement audit", "mix hex.audit"},
    {"dependency advisory audit", "mix deps.audit"},
    {"package boundary check", "mix run --no-start scripts/check_package.exs"},
    {"release reproducibility", "mix run --no-start scripts/check_reproducible.exs"}
  ]

  test "mix ci audits the edge example immediately after resolving its dependencies" do
    root_mix = File.read!("mix.exs")

    assert root_mix =~
             ~r|cmd --cd #{@edge_dir} env MIX_ENV=test mix deps\.get"\s*,\s*"cmd --cd #{@edge_dir} env MIX_ENV=test #{@audit_command}"|,
           "mix ci must fail on advisories in the edge example's own lock immediately after " <>
             "that project resolves its dependencies"
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

  test "mix ci runs the gate battery in the canonical order after the plain test step" do
    root_mix = File.read!("mix.exs") |> strip_comments()

    assert root_mix =~
             ~r|cmd env MIX_ENV=test mix test",\s*"#{battery_pattern()}|,
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
    [gate_job, example_job] = String.split(workflow, "\n  example:", parts: 2)
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
        String.replace(root_mix, ~s{"cmd env MIX_ENV=test #{command}",}, "", global: false)

      refute mutated_alias == root_mix,
             "the alias mutation fixture for #{command} did not change mix.exs — " <>
               "the mutation proof is not exercising the red path"

      refute mutated_alias =~ Regex.compile!(battery_pattern()),
             "the alias parity pattern still matches mix.exs with #{command} dropped — " <>
               "the gate would stay green over a missing step"
    end

    # The example job slice is untouched by the gate-job mutations above (its
    # own hex.audit survives) — the scoping the two-surface split relies on.
    assert String.contains?(example_job, "run: #{@audit_command}\n")
  end

  test "both jobs run the full three-cell compatibility matrix" do
    # A dropped matrix cell narrows CI coverage silently (a lane that never
    # runs looks green by absence) — pin the exact three cells per job and
    # that setup-beam actually consumes the matrix variables.
    workflow = File.read!(".github/workflows/ci.yml")
    [gate_job, example_job] = String.split(workflow, "\n  example:", parts: 2)

    lanes = [{"1.18.4", "27.3.4.14"}, {"1.19.5", "28.5.0.3"}, {"1.20.2", "29.0.3"}]

    for {job_name, job} <- [{"gate", gate_job}, {"example", example_job}] do
      assert job =~ ~r/strategy:\s+fail-fast:\s*false\s+matrix:\s*include:/m,
             "the #{job_name} job must declare the fail-fast: false matrix"

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

  # Full-line comments (the alias's step annotations, the workflow's battery
  # comment) must not weaken step-adjacency matching — strip them so the
  # pattern pins ACTUAL adjacency of the commands.
  defp strip_comments(text), do: Regex.replace(~r/^\s*#[^\n]*$/m, text, "")

  # The mix ci alias shape: comma-quoted commands, in battery order.
  defp battery_pattern do
    @battery
    |> Enum.map_join(~s{",\\s*"}, fn {_name, command} ->
      Regex.escape("cmd env MIX_ENV=test #{command}")
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
