defmodule BoundedAuthorityReportAdapter.PackageVocabularyTest do
  @moduledoc """
  The files the Hex package ships (source, `mix.exs` and the guides) are public text. They
  must not carry the repository's internal planning or review vocabulary (roadmap row ids,
  review-finding ids, process notes, the private runtime's name), and neither they nor the
  repository's other public documents may cite a decision record: the records are local to
  maintainers' checkouts, so a citation names a document no reader has.
  """

  use ExUnit.Case, async: true

  @internal ~r/\bBARA\b|(?<![-\w])RA\d+\b|\bBA[- ](signed|trust-root|runtime|attested|signature|asserted)\b|charter §|[Cc]ross-vendor|\bC1\b|\bC5\b|\bM3\b|\bB[12]\b|Codex|\bslice\b|design §|design Q\d|design-adversarial|Challenge \d|owner (ruling|direction)|\bCV\b|CV-finding|CV round/

  test "shipped files carry no internal planning or review vocabulary" do
    findings =
      for path <- shipped_files(),
          {line, number} <- path |> File.read!() |> String.split("\n") |> Enum.with_index(1),
          Regex.match?(@internal, line),
          do: "#{path}:#{number}: #{String.trim(line)}"

    assert findings == [], "internal vocabulary in shipped files:\n" <> Enum.join(findings, "\n")
  end

  # Decision records are local to the maintainers' checkout (gitignored, never packaged or
  # published), so a citation of one names a document no reader has.
  @decision_record ~r/\bADR\b|\.kimosabe|ash_onetime/

  # Public documents outside the package that readers of the repository and the site see.
  # AGENTS.md and docs/reference/agent-history.md are instructions and history for agents
  # working in a maintainer checkout, where the records exist; they are not listed.
  @public_documents [
    "README.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "docs/ROADMAP.md",
    "docs/charter.md",
    "docs/strategy.md",
    "docs/release.md",
    "examples/README.md",
    "examples/edge_agent/README.md",
    "examples/edge_agent/mix.exs",
    "examples/edge_agent/config/config.exs",
    "config/config.exs",
    "scripts/check-bap-drift.sh",
    "site/index.html",
    ".github/workflows/ci.yml",
    ".github/workflows/supply-chain.yml"
  ]

  test "no shipped file or public document cites a local decision record" do
    findings =
      for path <- Enum.uniq(shipped_files() ++ @public_documents),
          {line, number} <- path |> File.read!() |> String.split("\n") |> Enum.with_index(1),
          Regex.match?(@decision_record, line),
          do: "#{path}:#{number}: #{String.trim(line)}"

    assert findings == [],
           "decision-record citations in public files:\n" <> Enum.join(findings, "\n")

    # Non-vacuity: each form the pattern exists to catch.
    for planted <- ["(ADR-0021)", "ADR 0003", "see .kimosabe/adr/", "the ash_onetime posture"] do
      assert Regex.match?(@decision_record, planted), "#{planted} slipped past the pattern"
    end

    refute Regex.match?(@decision_record, "the adapter's address and readers")
  end

  test "the scan sees the shipped files" do
    files = shipped_files()
    assert "lib/bounded_authority_report_adapter.ex" in files
    assert "CHANGELOG.md" in files
    assert "mix.exs" in files
  end

  defp shipped_files do
    Mix.Project.config()[:package][:files]
    |> Enum.flat_map(fn path ->
      if File.dir?(path), do: Path.wildcard(Path.join(path, "**/*.{ex,exs,md}")), else: [path]
    end)
    |> Enum.filter(&(Path.extname(&1) in [".ex", ".exs", ".md"]))
  end
end
