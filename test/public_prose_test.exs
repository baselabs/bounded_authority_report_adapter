defmodule BoundedAuthorityReportAdapter.PublicProseTest do
  use ExUnit.Case, async: true

  # The business-policy rules exclude their definitions and in-memory examples.
  # The punctuation rule scans this file too.
  @this_file "test/public_prose_test.exs"
  @em_dash ~r/\x{2014}|\\u(?:2014)/iu
  @rules [
    ~r/\b(?:paid\s+)?subscription\b|\bpricing\b/i,
    ~r/private[- ](?:Hex|package|publication|publishing)\b/i,
    ~r/owner(?:'s)?\s+(?:approval|ruling|direction|standard)|fresh\s+approval/i,
    ~r/agent[- ](?:workflow|history)|as an AI coding agent|prior session's handoff|cross[- ]vendor[^\n]*(?:Codex|Claude|Gemini)/i,
    ~r/\.claude\/|\.codex\/|\.kimosabe\/(?:intents|records|handoffs)/i
  ]

  test "all tracked public files exclude em dashes, business policy and agent process material" do
    {output, 0} = System.cmd("git", ["ls-files", "-z"], stderr_to_stdout: true)
    paths = String.split(output, <<0>>, trim: true)
    assert "AGENTS.md" in paths

    findings =
      for path <- paths,
          File.regular?(path),
          content = File.read!(path),
          String.valid?(content),
          Regex.match?(@em_dash, content) or
            (path != @this_file and Enum.any?(@rules, &Regex.match?(&1, content))),
          do: path

    assert findings == [], "public-text hygiene violations: #{Enum.join(findings, ", ")}"
  end

  test "each hygiene rule rejects its intended class and permits technical contracts" do
    for spelling <- [<<0x2014::utf8>>, "\\u" <> "2014"] do
      assert Regex.match?(@em_dash, "A public sentence #{spelling} continues.")
    end

    refute Regex.match?(@em_dash, "Use a comma, a colon: or a separate sentence.")

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
