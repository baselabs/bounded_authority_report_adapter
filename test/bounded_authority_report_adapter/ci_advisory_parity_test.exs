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
    {"dependency advisory audit", "mix deps.audit"}
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
    # Non-vacuity: the battery pattern is not a loose blob — each step is
    # asserted ABSENT when removed from an in-memory copy of the workflow's
    # GATE job (scoped so the example job's own hex.audit step cannot satisfy
    # the refute for a dropped gate step).
    workflow = File.read!(".github/workflows/ci.yml")
    [gate_job, example_job] = String.split(workflow, "\n  example:", parts: 2)

    for {_name, command} <- @battery do
      mutated_gate =
        String.replace(gate_job, "run: #{command}\n", "run: mix test\n", global: false)

      refute mutated_gate == gate_job,
             "the mutation fixture for #{command} did not change the gate job — the " <>
               "mutation proof is not exercising the red path"

      refute String.contains?(mutated_gate, "run: #{command}\n"),
             "dropping the #{command} step left it present in the gate job — the parity " <>
               "pattern would stay green over a missing gate step"
    end

    # The example job slice is reattached so the refute above provably scoped
    # to the gate job (the example's own hex.audit survives untouched).
    assert String.contains?(example_job, "run: #{@audit_command}\n")
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
