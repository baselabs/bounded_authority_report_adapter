defmodule BoundedAuthorityReportAdapter.PublicSurfacePrivacyTest do
  use ExUnit.Case, async: false

  # These hashes represent generic deployment-topology phrases, not private names.
  # Exact private identifiers live only in the ignored .kimosabe manifest consumed
  # by the commit guard; publishing their unhashed or unkeyed hashes would create a
  # confirmation oracle for guessed names.
  @forbidden_topology_hashes MapSet.new([
                               "44abe4ace21b534dfb1eef35741807ec85dd1766486a86fd7d6b5a822f58e470",
                               "4e8c2d200b4a4538da9dc9d04c618a1e10117629799f690113f7caf1e4a29a15",
                               "6f7b03460ad6bbbf99ac00c89f3939e825c846d38da079f0e920b3d0347bcae6",
                               "a32b176c56bea1f4e551e76e17d60bb6acac7822850dc3673b944ae8f3db8dce"
                             ])

  @three_word_canary_hash "8e67e6fc7f5e336d9f4e58162eae53641a1426acb9f82767cebde52f68f65a5b"
  @concatenated_canary_hash "2d5601031d798a56a26fc011fb50a6aa13c56d154e10de2746a37c525d9ff7b7"
  @production_canaries [
    [99, 100, 99],
    [101, 100, 103, 101, 45, 104, 111, 108, 100, 101, 114],
    [99, 104, 97, 110, 103, 101, 45, 100, 97, 116, 97, 45, 99, 97, 112, 116, 117, 114, 101],
    [99, 111, 110, 116, 114, 111, 108, 32, 112, 108, 97, 110, 101]
  ]

  test "tracked files and reachable history contain no consumer-specific topology" do
    {tracked_output, 0} = System.cmd("git", ["ls-files", "-z"])

    tracked_findings =
      tracked_output
      |> String.split(<<0>>, trim: true)
      |> Enum.count(fn path -> forbidden?(path <> "\n" <> File.read!(path)) end)

    {messages, 0} = System.cmd("git", ["log", "--all", "--format=fuller"])

    {patches, 0} =
      System.cmd(
        "git",
        ["log", "--all", "--format=", "--name-status", "-p", "--no-ext-diff", "--text"]
      )

    assert {tracked_findings, forbidden?(messages), forbidden?(patches)} == {0, false, false},
           "public-surface privacy gate found forbidden generic topology"
  end

  test "candidate normalization is red-capable for three-word and joined variants" do
    assert forbidden?("Public privacy canary", MapSet.new([@three_word_canary_hash]))
    assert forbidden?("Public privacy canary", MapSet.new([@concatenated_canary_hash]))
  end

  test "every production topology digest is red-capable" do
    Enum.each(@production_canaries, fn codepoints ->
      assert forbidden?(List.to_string(codepoints))
    end)
  end

  test "invalid UTF-8 is handled deterministically" do
    refute forbidden?(<<255, 254, 0, 1>>)
  end

  defp forbidden?(content, forbidden_hashes \\ @forbidden_topology_hashes) do
    content
    |> String.replace_invalid("")
    |> String.downcase()
    |> candidates()
    |> Enum.any?(&(digest(&1) in forbidden_hashes))
  end

  defp candidates(content) do
    tokens =
      ~r/[a-z0-9_]+(?:-[a-z0-9_]+)*/
      |> Regex.scan(content, capture: :first)
      |> List.flatten()

    components = Enum.flat_map(tokens, &String.split(&1, ["-", "_"], trim: true))

    (windows(tokens, 3) ++ windows(components, 3))
    |> Enum.flat_map(fn parts ->
      [Enum.join(parts), Enum.join(parts, " "), Enum.join(parts, "_"), Enum.join(parts, "-")]
    end)
    |> Enum.uniq()
  end

  defp windows(tokens, max_size) do
    case length(tokens) do
      0 ->
        []

      token_count ->
        for size <- 1..min(max_size, token_count),
            offset <- 0..(token_count - size),
            do: Enum.slice(tokens, offset, size)
    end
  end

  defp digest(value), do: :crypto.hash(:sha256, value) |> Base.encode16(case: :lower)
end
