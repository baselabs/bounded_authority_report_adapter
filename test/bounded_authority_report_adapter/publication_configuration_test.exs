defmodule BoundedAuthorityReportAdapter.PublicationConfigurationTest do
  use ExUnit.Case, async: true

  defp read(path), do: YamlElixir.read_from_file!(path)
  defp uses?(step, action), do: String.starts_with?(step["uses"] || "", action)
  defp unabridged(term), do: inspect(term, limit: :infinity, printable_limit: :infinity)

  test "only the isolated upload holds the registry key, between inspection and read-back" do
    workflow = read(".github/workflows/publish.yml")
    job = workflow["jobs"]["publish"]
    steps = job["steps"]
    assert workflow["on"] == %{"workflow_dispatch" => nil}
    assert workflow["permissions"] == %{"contents" => "read"}
    assert job["environment"] == "publish"
    assert job["timeout-minutes"] == 90
    assert hd(steps)["name"] == "Require the default branch"
    assert hd(steps)["run"] =~ ~s("refs/heads/$DEFAULT_BRANCH")

    assert job["if"] ==
             ~s|contains(fromJSON('["corepay","palermo-git"]'), github.actor) && contains(fromJSON('["corepay","palermo-git"]'), github.triggering_actor)|

    notebooks = workflow["jobs"]["published-livebooks"]
    assert notebooks["needs"] == "publish"
    assert notebooks["if"] == job["if"]
    refute Map.has_key?(notebooks, "environment")
    refute unabridged(notebooks) =~ "secrets."
    [upload] = Enum.filter(steps, &Map.has_key?(&1["env"] || %{}, "HEX_API_KEY"))
    assert upload["env"] == %{"HEX_API_KEY" => "${{ secrets.HEX_API_KEY }}"}
    assert upload["id"] == "upload"
    assert upload["working-directory"] == "${{ runner.temp }}"
    assert upload["run"] =~ "test ! -e mix.exs"
    assert upload["run"] =~ "sha256sum --check"

    assert upload["run"] =~
             ~s(mix run --no-mix-exs --no-start "$GITHUB_WORKSPACE/scripts/publish_hex_artifacts.exs")

    assert upload["run"] =~ ~s("$PACKAGE" "$VERSION" "$PACKAGE_ARCHIVE" "$DOCS_ARCHIVE")
    refute upload["run"] =~ "mix hex.publish"
    without_upload = put_in(workflow, ["jobs", "publish", "steps"], steps -- [upload])
    refute unabridged(without_upload) =~ "HEX_API_KEY"

    for path <- Path.wildcard(".github/workflows/*.yml") -- [".github/workflows/publish.yml"] do
      refute File.read!(path) =~ "HEX_API_KEY"
    end

    commands = Enum.map(steps, &(&1["run"] || ""))
    name = Enum.find_index(commands, &(&1 == "python3 scripts/check_hex_release.py name"))
    deps = Enum.find_index(commands, &(&1 == "mix deps.get --check-locked"))
    docs = Enum.find_index(commands, &String.contains?(&1, "mix docs --warnings-as-errors"))
    build = Enum.find_index(commands, &String.starts_with?(&1, "mix hex.build --output"))

    check =
      Enum.find_index(
        commands,
        &String.starts_with?(&1, "mix run --no-start scripts/check_package.exs")
      )

    verify = Enum.find_index(commands, &String.contains?(&1, "gh attestation verify"))
    prepare = Enum.find_index(commands, &String.contains?(&1, "check_hex_release.py prepare"))
    keyed = Enum.find_index(steps, &(&1 == upload))

    read_back =
      Enum.find_index(commands, &(&1 == "python3 scripts/check_hex_release.py read-back"))

    assert Enum.all?(
             [name, deps, docs, build, check, verify, prepare, keyed, read_back],
             &is_integer/1
           )

    assert name < deps and deps < docs
    assert Enum.at(steps, name)["env"] == %{"PACKAGE" => "bounded_authority_report_adapter"}
    assert docs < build and build < check and check < verify and verify < prepare
    assert prepare < keyed and keyed < read_back

    assert Enum.at(steps, read_back)["env"]["PUBLICATION_HELD"] ==
             "${{ steps.upload.outputs.held }}"

    assert Enum.at(commands, docs) =~ "--formatter html"
    assert Enum.at(commands, docs) =~ "--sort=name --mtime="
    assert Enum.at(commands, docs) =~ "gzip -n"
    assert Enum.at(commands, check) =~ ~s("$PACKAGE_ARCHIVE")
    assert Enum.at(commands, prepare) =~ ~s(sha256sum "$PACKAGE_ARCHIVE" "$DOCS_ARCHIVE")

    verifier = Enum.at(steps, verify)
    assert verifier["env"] == %{"GH_TOKEN" => "${{ github.token }}"}
    assert verifier["run"] =~ "--signer-workflow"
    assert verifier["run"] =~ "--source-digest"
    assert verifier["run"] =~ "--deny-self-hosted-runners"
    assert verifier["run"] =~ "cmp"
    assert verifier["run"] =~ "qualification-evidence/release.cdx.json"
    assert Enum.all?(Map.values(job["permissions"]), &(&1 == "read"))
    refute Enum.any?(steps, &uses?(&1, "actions/attest@"))
    assert List.last(steps)["if"] == "always()"
  end

  test "consumer files leave publication in exactly one release-assets bundle" do
    publish = read(".github/workflows/publish.yml")["jobs"]["publish"]
    [assets] = Enum.filter(publish["steps"], &uses?(&1, "actions/upload-artifact@"))
    assert assets["with"]["name"] == "release-assets"
    assert assets["with"]["if-no-files-found"] == "error"

    assert String.split(assets["with"]["path"], "\n", trim: true) == [
             "artifacts/bounded_authority_report_adapter-${{ env.VERSION }}.tar",
             "artifacts/SHA256SUMS",
             "artifacts/release.cdx.json"
           ]

    for path <- Path.wildcard(".github/workflows/*.yml") do
      source = File.read!(path)
      refute source =~ ~r/^\s+tags:/m
      refute source =~ "gh release create"
      refute source =~ "release-evidence-"
    end

    for path <- ["SECURITY.md", "docs/release.md"] do
      source = File.read!(path)
      assert source =~ "GitHub release"
      assert source =~ "gh release download"
      assert source =~ "SHA256SUMS"
      assert source =~ "release.cdx.json"
      refute source =~ "gh run download"
      refute source =~ "workflow artifact"
    end
  end

  test "resumption compares both archives and refuses retirement or differing bytes" do
    source = File.read!("scripts/check_hex_release.py")

    for required <- [
          "if release.get(\"retirement\") is not None:",
          "checksum.lower() != expected",
          "if served != expected:",
          "https://repo.hex.pm/tarballs/{package}-{version}.tar",
          "https://repo.hex.pm/docs/{package}-{version}.tar.gz",
          "PUBLISH_PACKAGE={str(not package_served).lower()}",
          "PUBLISH_DOCS={str(not docs_served).lower()}",
          "if held or not (release is not None and package_served and docs_served):",
          "Publication is held or not yet served",
          "this same commit"
        ] do
      assert source =~ required
      mutated = String.replace(source, required, "", global: false)
      refute mutated == source
      refute mutated =~ required
    end

    upload = File.read!("scripts/publish_hex_artifacts.exs")
    assert upload =~ "def main([name, version, archive, docs])"
    assert upload =~ "if Mix.Project.get(), do: raise("
    assert upload =~ "exists!(Hex.API.Package.get_anonymous(nil, name), name)"
    assert upload =~ ~S(#{name} is not on Hex; first publication is the owner's decision)
    assert upload =~ ~S(could not confirm #{name} exists on Hex; publication refused)
    [before_upload, _] = String.split(upload, "Hex.API.Release.publish(", parts: 2)
    assert before_upload =~ "package_bytes = File.read!(archive)"
    assert before_upload =~ "docs_bytes = File.read!(docs)"
    assert upload =~ "Hex.API.Release.publish("
    assert upload =~ "Hex.API.ReleaseDocs.publish("
    assert upload =~ "replace: false"
    refute upload =~ "replace: true"
    assert upload =~ ~S|System.fetch_env!("PUBLISH_PACKAGE") == "true"|
    assert upload =~ ~S|System.fetch_env!("PUBLISH_DOCS") == "true"|
    assert upload =~ ~s(state in ["staged", "held", "pending"])
    assert upload =~ "status == 202"
    assert upload =~ "held for approval on Hex; publication is incomplete"
    refute upload =~ "Mix.Project.config"
    refute upload =~ "Mix.Task"
    refute upload =~ "Hex.API.Release.get("
    refute upload =~ "do not redispatch"
  end

  test "qualification gates its reusable attestation and never writes caches" do
    ci = read(".github/workflows/ci.yml")
    qualified = ci["jobs"]["qualified"]
    assert qualified["if"] == "always()"
    refute Map.has_key?(qualified, "name")
    assert MapSet.new(qualified["needs"]) == MapSet.new(Map.keys(ci["jobs"]) -- ["qualified"])
    assert "attest" in qualified["needs"]
    assert ci["jobs"]["attest"]["uses"] == "./.github/workflows/supply-chain.yml"
    assert "package" in ci["jobs"]["attest"]["needs"]
    supply = read(".github/workflows/supply-chain.yml")
    assert Map.keys(supply["on"]) == ["workflow_call"]
    assert Map.keys(supply["jobs"]) == ["attest"]
    steps = supply["jobs"]["attest"]["steps"]
    assert Enum.all?(steps, &Map.has_key?(&1, "uses"))
    assert Enum.count(steps, &uses?(&1, "actions/attest@")) == 2
    assert supply["jobs"]["attest"]["permissions"]["artifact-metadata"] == "write"

    for path <- Path.wildcard(".github/workflows/*.yml"),
        {_name, job} <- read(path)["jobs"],
        step <- job["steps"] || [] do
      refute uses?(step, "actions/cache@") or uses?(step, "actions/cache/save@")

      if uses?(step, "actions/setup-go@") or uses?(step, "ocaml/setup-ocaml@") do
        assert step["with"]["cache"] == false
      end

      if uses?(step, "actions/setup-node@") do
        assert step["with"]["package-manager-cache"] == false
      end
    end
  end
end
