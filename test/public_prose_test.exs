defmodule BoundedAuthorityReportAdapter.PublicProseTest do
  use ExUnit.Case, async: true

  # Rule definitions and their in-memory examples are the only excluded source.
  @this_file "test/public_prose_test.exs"
  @rules [
    ~r/\b(?:paid\s+)?subscription\b|\bpricing\b/i,
    ~r/private[- ](?:Hex|package|publication|publishing)\b/i,
    ~r/owner(?:'s)?\s+(?:approval|ruling|direction|standard)|fresh\s+approval/i,
    ~r/agent[- ](?:workflow|history)|as an AI coding agent|prior session's handoff|cross[- ]vendor[^\n]*(?:Codex|Claude|Gemini)/i,
    ~r/\.claude\/|\.codex\/|\.kimosabe\/(?:intents|records|handoffs)/i
  ]

  test "all tracked public files exclude business policy and agent process material" do
    {output, 0} = System.cmd("git", ["ls-files", "-z"], stderr_to_stdout: true)
    paths = String.split(output, <<0>>, trim: true)
    assert "AGENTS.md" in paths

    findings =
      for path <- paths,
          path != @this_file,
          File.regular?(path),
          content = File.read!(path),
          String.valid?(content),
          Enum.any?(@rules, &Regex.match?(&1, content)),
          do: path

    assert findings == [], "public-text hygiene violations: #{Enum.join(findings, ", ")}"
  end

  test "each hygiene rule rejects its intended class and permits technical contracts" do
    examples = [
      "a paid\nsubscription is required",
      "private Hex publication policy",
      "fresh\napproval for this release",
      "archived agent workflow",
      ".kimosabe/handoffs/session.md"
    ]

    for {rule, example} <- Enum.zip(@rules, examples), do: assert(Regex.match?(rule, example))

    for text <- [
          "Verification is never authorization.",
          "The key owner retains custody.",
          "GitHub Actions runs the supply-chain workflow.",
          "Report vulnerabilities through GitHub private reporting."
        ],
        rule <- @rules,
        do: refute(Regex.match?(rule, text))
  end
end
