defmodule BoundedAuthorityReportAdapter.CiShellContractTest do
  use ExUnit.Case, async: true

  @hidden_failures [
    {~r/\|\|[ \t]*(?:true|:)(?:\s|[;&)]|$)/, ["false || true", "false || :"]},
    {~r/\becho\b[^\n]*\$\(/, [~S|echo "$(false)"|]},
    {~r/\bfor[ \t]+[^\n]*\bin[ \t]+[^\n]*\$\(/,
     [~S|for value in $(false); do printf '%s\n' "$value"; done|]},
    {~r/<\(/, [~S|diff <(false) expected|]},
    {~r/\b(?:local|declare|export|readonly)\b[^\n]*=[ \t]*["']?\$\(/,
     [~S|local value="$(false)"|]}
  ]

  test "workflows and shell scripts propagate command and pipeline failures" do
    workflows = Path.wildcard(".github/workflows/*.{yml,yaml}")
    actions = Path.wildcard(".github/actions/**/action.{yml,yaml}")
    assert workflows != []
    assert actions != []

    for path <- workflows do
      workflow = YamlElixir.read_from_file!(path)
      assert get_in(workflow, ["defaults", "run", "shell"]) == "bash", path

      for {_name, job} <- workflow["jobs"] do
        assert get_in(job, ["defaults", "run", "shell"]) in [nil, "bash"], path

        for step <- job["steps"] || [], Map.has_key?(step, "run") do
          assert step["shell"] in [nil, "bash"], path
        end
      end
    end

    for path <- actions do
      action = YamlElixir.read_from_file!(path)

      if get_in(action, ["runs", "using"]) == "composite" do
        for step <- action["runs"]["steps"], Map.has_key?(step, "run") do
          assert step["shell"] == "bash", path
        end
      end
    end

    {tracked, 0} = System.cmd("git", ["ls-files", "-z"])

    scripts =
      for path <- String.split(tracked, "\0", trim: true),
          source = File.read!(path),
          Path.extname(path) in ~w(.sh .bash .dash .ksh .zsh) or
            source =~ ~r/\A\#\![^\n]*\b(?:ba|da|k|z)?sh\b/,
          do: {path, source}

    assert scripts != []

    for {path, source} <- scripts do
      assert String.starts_with?(source, "#!/usr/bin/env bash\n"), path

      first_statement =
        source
        |> String.split("\n")
        |> Enum.drop(1)
        |> Enum.map(&String.trim/1)
        |> Enum.reject(&(&1 == "" or String.starts_with?(&1, "#")))
        |> List.first()

      assert (first_statement || "") =~
               ~r/\Aset -euo pipefail(?:[ \t]+-[a-zA-Z]+)*[ \t]*(?:\#.*)?\z/,
             path
    end

    sources = Enum.map(workflows ++ actions, &{&1, File.read!(&1)}) ++ scripts

    for {path, source} <- sources do
      # A continued shell line must not hide a substitution from the guard.
      source = Regex.replace(~r/\\\r?\n/, source, "")

      for {pattern, _violations} <- @hidden_failures do
        refute source =~ pattern, "#{path} hides a command failure: #{inspect(pattern)}"
      end
    end

    for {pattern, violations} <- @hidden_failures, violation <- violations do
      assert violation =~ pattern, "the guard missed #{violation}"
    end
  end
end
