defmodule BoundedAuthorityReportAdapter.PackageVocabularyTest do
  @moduledoc """
  The files the Hex package ships (source, `mix.exs` and the guides) are public text. They
  must not carry the repository's internal planning or review vocabulary (roadmap row ids,
  review-finding ids, process notes, the private runtime's name), and an ADR reference in a
  shipped Markdown file must be a link: the ADRs are repository documents, not in the
  package, so a bare "ADR-0023" names a file the reader does not have.
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

  test "every ADR reference in a shipped Markdown file is a link" do
    findings =
      for path <- shipped_files(),
          Path.extname(path) == ".md",
          {line, number} <- path |> File.read!() |> String.split("\n") |> Enum.with_index(1),
          unlinked = Regex.replace(~r/\[[^\]]*\]\([^)]*\)/, line, ""),
          Regex.match?(~r/\bADR[- ]?\d{4}\b/, unlinked),
          do: "#{path}:#{number}: #{String.trim(line)}"

    assert findings == [], "unlinked ADR references:\n" <> Enum.join(findings, "\n")
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
