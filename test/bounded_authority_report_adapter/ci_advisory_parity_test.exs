defmodule BoundedAuthorityReportAdapter.CiAdvisoryParityTest do
  use ExUnit.Case, async: true

  @edge_dir "examples/edge_agent"
  @audit_command "mix hex.audit"

  test "mix ci audits the edge example immediately after resolving its dependencies" do
    root_mix = File.read!("mix.exs")

    assert root_mix =~
             ~r|cmd --cd #{@edge_dir} env MIX_ENV=test mix deps\.get"\s*,\s*"cmd --cd #{@edge_dir} env MIX_ENV=test #{@audit_command}"|,
           "mix ci must fail on advisories in the edge example's own lock immediately after " <>
             "that project resolves its dependencies"
  end

  test "the GitHub example job audits its owner-local lock after dependency resolution" do
    workflow = File.read!(".github/workflows/ci.yml")
    [_, example_job] = String.split(workflow, "\n  example:", parts: 2)

    assert example_job =~
             ~r|defaults:\s+run:\s+working-directory: #{@edge_dir}|,
           "the GitHub example job must bind every mix command to examples/edge_agent"

    assert example_job =~
             ~r|- name: Install deps\s+run: mix deps\.get\s+- name: Audit dependencies\s+run: #{@audit_command}|,
           "the GitHub example job must run mix hex.audit against examples/edge_agent, not " <>
             "the root library lock"
  end
end
