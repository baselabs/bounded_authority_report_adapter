defmodule BoundedAuthorityReportAdapter.PublicationConfigurationTest do
  use ExUnit.Case, async: true

  defp read(path), do: YamlElixir.read_from_file!(path)
  defp uses?(step, action), do: String.starts_with?(step["uses"] || "", action)
  defp unabridged(term), do: inspect(term, limit: :infinity, printable_limit: :infinity)

  @package "bounded_authority_report_adapter"
  @hex_action "baselabs/.github/.github/actions/hex-publish@654fcd0ef63daf8e3f79dfeb4ca900adffd0d4e2"

  test "only the upload in the publish environment can exchange a Hex write token" do
    workflow = read(".github/workflows/publish.yml")
    jobs = workflow["jobs"]
    upload = jobs["upload"]
    dispatch = workflow["on"]["workflow_dispatch"]
    assert Map.keys(workflow["on"]) == ["workflow_dispatch"]
    assert dispatch["inputs"]["release_commit"]["required"] == true
    assert dispatch["inputs"]["release_commit"]["type"] == "string"
    assert dispatch["inputs"]["qualification_run"]["required"] == false
    assert workflow["permissions"] == %{"contents" => "read"}
    refute Map.has_key?(workflow, "env")
    assert upload["needs"] == "verify-provenance"
    assert upload["environment"] == "publish"

    assert upload["permissions"] == %{
             "contents" => "read",
             "actions" => "read",
             "id-token" => "write"
           }

    assert upload["if"] ==
             ~s|contains(fromJSON('["corepay","palermo-git"]'), github.actor) && contains(fromJSON('["corepay","palermo-git"]'), github.triggering_actor)|

    for {name, job} <- jobs do
      assert job["if"] == upload["if"]
      refute Map.has_key?(job, "env")

      if name != "upload" do
        refute Map.has_key?(job, "environment")
        refute (job["permissions"] || %{})["id-token"] == "write"
        refute unabridged(job) =~ "secrets."
      end
    end

    for job <- [jobs["verify-provenance"], upload] do
      [refusal | _] = job["steps"]
      refute Map.has_key?(refusal, "uses")
      refute Map.has_key?(refusal, "if")
      sha = String.duplicate("a", 40)

      for {ref, commit, accepted?} <- [
            {"refs/heads/master", sha, true},
            {"refs/heads/kci/candidate", sha, false},
            {"refs/tags/v1.0.0", sha, false},
            {"refs/heads/master", String.upcase(sha), false},
            {"refs/heads/master", "deadbeef", false}
          ] do
        {_, status} =
          System.cmd("bash", ["-e", "-c", refusal["run"]],
            env: [{"DEFAULT_BRANCH", "master"}, {"GITHUB_REF", ref}, {"RELEASE_COMMIT", commit}]
          )

        assert {ref, commit, status == 0} == {ref, commit, accepted?}
      end
    end

    step = hex_step(upload)
    assert step["id"] == "upload"

    assert step["with"] == %{
             "operation" => "upload",
             "package" => @package,
             "package-directory" => ".",
             "release-commit" => "${{ inputs.release_commit }}",
             "qualification-run" => "${{ needs.verify-provenance.outputs.qualification-run }}",
             "organization-read-key" => "${{ secrets.HEX_ORG_KEY_PUBLISH_API_READ }}"
           }

    assert List.last(upload["steps"]) == step
    without_upload = put_in(jobs, ["upload", "steps"], upload["steps"] -- [step])
    refute unabridged(without_upload) =~ "secrets."
    refute Enum.any?(upload["steps"], &String.starts_with?(&1["uses"] || "", "./"))

    for step <- upload["steps"], command = step["run"] || "" do
      refute command =~ "scripts/"
      refute command =~ ~r/mix (?:run|compile|deps|docs|hex\.build)/
    end

    for path <- Path.wildcard(".github/workflows/*.yml") do
      refute File.read!(path) =~ "HEX_API_KEY"
    end
  end

  test "qualification checks and attests the exact archive that can be uploaded" do
    ci = read(".github/workflows/ci.yml")
    qualification = ci["jobs"]["hex-qualification"]
    package = ci["jobs"]["package"]
    step = hex_step(qualification)

    assert step["with"] == %{
             "operation" => "qualify",
             "package" => @package,
             "package-directory" => "."
           }

    assert step["env"]["HEX_DOCS_SOURCE_REF"] == "${{ github.sha }}"
    assert List.last(qualification["steps"]) == step
    refute Map.has_key?(step, "if")

    assert package["needs"] == "hex-qualification"
    assert package["permissions"] == %{"actions" => "read", "contents" => "read"}

    for job <- [qualification, package] do
      refute Map.has_key?(job, "if")
      refute Map.has_key?(job, "environment")
      refute (job["permissions"] || %{})["id-token"] == "write"
    end

    [_, commit] = String.split(step["uses"], "@")

    pin_url =
      "https://raw.githubusercontent.com/baselabs/.github/#{commit}/.github/actions/hex-publish/hex-version"

    for job <- [qualification, package] do
      assert Enum.any?(job["steps"], &String.contains?(&1["run"] || "", pin_url))
    end

    for workflow <- [ci, read(".github/workflows/publish.yml")],
        {_name, job} <- workflow["jobs"],
        install <- job["steps"] || [],
        command = install["run"] || "",
        command =~ "mix local.hex" do
      assert command =~ pin_url
    end

    steps = package["steps"]
    [download] = Enum.filter(steps, &uses?(&1, "actions/download-artifact@"))

    assert download["with"] == %{
             "name" => "hex-hexpm-#{@package}",
             "path" => "${{ runner.temp }}/qualified-hex",
             "github-token" => "${{ github.token }}",
             "run-id" => "${{ github.run_id }}",
             "digest-mismatch" => "error"
           }

    archive = "artifacts/#{@package}-$VERSION.tar"
    [extract] = Enum.filter(steps, &(&1["id"] == "archive"))
    assert extract["run"] =~ ~s(cp "$RUNNER_TEMP/qualified-hex/package.tar" "#{archive}")

    check = Enum.find(steps, &String.contains?(&1["run"] || "", "check_package.exs"))
    assert check["run"] =~ ~s("#{archive}")

    checksum = Enum.find(steps, &(&1["name"] == "Record archive checksum"))
    manifest = ~S("$RUNNER_TEMP/qualified-hex/qualified.json")
    assert checksum["run"] =~ ~s(sha256sum "#{@package}-$VERSION.tar" > SHA256SUMS)
    assert checksum["run"] =~ ~s(jq -er .package_sha256 #{manifest})
    assert checksum["run"] =~ ~S|test "$(cut -d' ' -f1 SHA256SUMS)" = "$expected"|

    [upload] = Enum.filter(steps, &uses?(&1, "actions/upload-artifact@"))
    assert upload["with"]["if-no-files-found"] == "error"
    assert upload["with"]["retention-days"] == 7

    indexes =
      Enum.map([download, extract, check, checksum, upload], fn expected ->
        refute Map.has_key?(expected, "if")
        Enum.find_index(steps, &(&1 == expected))
      end)

    assert indexes == Enum.sort(indexes)
    refute Enum.any?(steps, &String.contains?(&1["run"] || "", "mix hex.build"))
    assert List.last(steps)["if"] == "always()"
    assert List.last(steps)["run"] == ~s(rm -rf -- "$RUNNER_TEMP/qualified-hex")

    declared = ".github/hex-packages.json" |> File.read!() |> :json.decode()
    assert Map.keys(declared) == [@package]
    assert %{"app" => @package, "directory" => ".", "files" => files} = declared[@package]
    assert files == Enum.sort(Enum.uniq(files))
    assert Enum.all?(["CHANGELOG.md", "mix.exs", "lib/#{@package}.ex"], &(&1 in files))
  end

  test "upload uses the same run whose archive was verified before publication" do
    jobs = read(".github/workflows/publish.yml")["jobs"]
    verify = jobs["verify-provenance"]
    steps = verify["steps"]
    lookup = Enum.find(steps, &(&1["id"] == "qualification"))
    assert lookup["run"] =~ "git merge-base --is-ancestor"
    assert lookup["run"] =~ "actions/workflows/ci.yml/runs?head_sha="
    assert lookup["run"] =~ ~s|.head_branch == ("kci/" + $sha)|

    assert Enum.map(
             Enum.filter(steps, &uses?(&1, "actions/download-artifact@")),
             & &1["with"]["name"]
           ) == [
             "hex-hexpm-#{@package}",
             "bounded-authority-report-adapter-${{ inputs.release_commit }}"
           ]

    for step <- Enum.filter(steps, &uses?(&1, "actions/download-artifact@")) do
      assert step["with"]["run-id"] == "${{ steps.qualification.outputs.run }}"
      assert step["with"]["digest-mismatch"] == "error"
    end

    proof = Enum.find(steps, &(&1["id"] == "provenance"))

    assert proof["run"] =~
             ~s(git tag --list "v$VERSION" "$VERSION" "baselabs_#{@package}-v$VERSION")

    assert proof["run"] =~ ~s(test -z "$version_tags")
    assert proof["run"] =~ ~s(cmp "$archive" "$evidence/#{@package}-$VERSION.tar")
    assert proof["run"] =~ "gh attestation verify"
    assert proof["run"] =~ ".github/workflows/supply-chain.yml"
    assert proof["run"] =~ ~s(--source-digest "$RELEASE_COMMIT" --deny-self-hosted-runners)
    assert verify["outputs"]["qualification-run"] == "${{ steps.qualification.outputs.run }}"
    assert verify["outputs"]["package-sha256"] == "${{ steps.provenance.outputs.package-sha256 }}"
    assert List.last(steps)["if"] == "always()"
  end

  test "consumer files leave the read-back job in exactly one release-assets bundle" do
    jobs = read(".github/workflows/publish.yml")["jobs"]
    read_back = jobs["read-back"]
    assert read_back["needs"] == ["verify-provenance", "upload"]
    assert read_back["permissions"] == %{"contents" => "read", "actions" => "read"}
    step = hex_step(read_back)
    assert step["id"] == "served"

    assert step["with"] == %{
             "operation" => "read-back",
             "package" => @package,
             "package-directory" => ".",
             "release-commit" => "${{ inputs.release_commit }}",
             "qualification-run" => "${{ needs.upload.outputs.qualification-run }}",
             "qualification-sha256" => "${{ needs.upload.outputs.qualification-sha256 }}",
             "release-assets-directory" => "${{ runner.temp }}/release-assets"
           }

    for name <- ["verify-provenance", "upload", "read-back"] do
      [checkout] = Enum.filter(jobs[name]["steps"], &uses?(&1, "actions/checkout@"))
      assert checkout["with"]["fetch-depth"] == 0
      assert checkout["with"]["persist-credentials"] == false
      assert checkout["with"]["ref"] == "${{ inputs.release_commit }}"
    end

    steps = read_back["steps"]
    [download] = Enum.filter(steps, &uses?(&1, "actions/download-artifact@"))

    assert download["with"]["name"] ==
             "bounded-authority-report-adapter-${{ steps.served.outputs.commit }}"

    assert download["with"]["run-id"] == "${{ needs.upload.outputs.qualification-run }}"

    compare = Enum.find(steps, &String.contains?(&1["run"] || "", "ATTESTED_SHA256"))

    assert compare["env"]["ATTESTED_SHA256"] ==
             "${{ needs.verify-provenance.outputs.package-sha256 }}"

    assert compare["env"]["UPLOADED_SHA256"] == "${{ needs.upload.outputs.package-sha256 }}"
    assert compare["run"] =~ ~s(test "$ATTESTED_SHA256" = "$UPLOADED_SHA256")
    assert compare["run"] =~ "sha256sum --check SHA256SUMS"
    assert compare["run"] =~ "release.cdx.json"

    assert [assets] =
             for(
               {_name, job} <- jobs,
               step <- job["steps"],
               uses?(step, "actions/upload-artifact@"),
               do: step
             )

    assert assets["with"] == %{
             "name" => "release-assets",
             "path" => "${{ runner.temp }}/release-assets/",
             "if-no-files-found" => "error",
             "retention-days" => 7
           }

    assert Enum.find_index(steps, &(&1 == step)) < Enum.find_index(steps, &(&1 == compare))
    assert Enum.find_index(steps, &(&1 == compare)) < Enum.find_index(steps, &(&1 == assets))
    assert List.last(steps)["if"] == "always()"

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

  defp hex_step(job) do
    assert [step] = Enum.filter(job["steps"], &uses?(&1, @hex_action))
    assert step["uses"] == @hex_action
    step
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
    [download | _] = steps
    assert uses?(download, "actions/download-artifact@")
    assert download["with"]["digest-mismatch"] == "error"
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
