defmodule BoundedAuthorityReportAdapter.PublicSurfacePrivacyTest do
  use ExUnit.Case, async: false

  @moduletag timeout: 180_000

  # These hashes represent generic deployment-topology phrases, not private names.
  # Exact private identifiers live only in the ignored .kimosabe manifest consumed
  # by the commit guard; publishing their unhashed or unkeyed hashes would create a
  # confirmation oracle for guessed names.
  @forbidden_topology_hashes MapSet.new([
                               "44abe4ace21b534dfb1eef35741807ec85dd1766486a86fd7d6b5a822f58e470",
                               "3909646b8c708c0ca1dbe6ae42246b1ca1f0962dd921dd77d5dfc445c3e12f9d",
                               "8ba856db7af39ad490c3c482ffe3e6a07c77cc65f22249da21e98790d9746770",
                               "aedf9140c8923575ea004557e6ba9c2ceabe2b63d2c99a164aa1501547d5bc6a"
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
    assert scan_repo(".") == {0, false, false, false, false},
           "public-surface privacy gate found forbidden generic topology"
  end

  test "candidate normalization and every production rule are red-capable" do
    assert forbidden?("Public privacy canary", MapSet.new([@three_word_canary_hash]))
    assert forbidden?("Public privacy canary", MapSet.new([@concatenated_canary_hash]))

    Enum.each(@production_canaries, fn codepoints ->
      parts = codepoints |> List.to_string() |> String.split(["-", "_", " "], trim: true)

      for separator <- ["", " ", "_", "-"] do
        assert forbidden?(Enum.join(parts, separator))
      end
    end)
  end

  test "invalid UTF-8 is handled deterministically" do
    refute forbidden?(<<255, 254, 0, 1>>)
  end

  test "Git plumbing detects tracked, historical, merge, and annotated-tag violations" do
    repo =
      Path.join(System.tmp_dir!(), "bara-public-privacy-#{System.unique_integer([:positive])}")

    File.mkdir_p!(repo)
    on_exit(fn -> File.rm_rf!(repo) end)

    git!(repo, ["init", "--initial-branch=master"])
    git!(repo, ["config", "user.email", "privacy-gate@example.invalid"])
    git!(repo, ["config", "user.name", "Privacy Gate"])

    File.write!(Path.join(repo, "README.md"), "public adapter\n")
    git!(repo, ["add", "README.md"])
    git!(repo, ["commit", "-m", "clean root"])
    assert scan_repo(repo) == {0, false, false, false, false}

    canary =
      @production_canaries
      |> Enum.at(1)
      |> List.to_string()
      |> String.split(["-", "_", " "], trim: true)
      |> Enum.join()

    git!(repo, ["tag", "-a", "v-canary", "-m", canary])
    assert scan_repo(repo) == {0, false, false, false, true}
    git!(repo, ["tag", "-d", "v-canary"])

    git!(repo, ["switch", "-c", "side"])
    File.write!(Path.join(repo, "side.txt"), "side\n")
    git!(repo, ["add", "side.txt"])
    git!(repo, ["commit", "-m", "side"])
    git!(repo, ["switch", "master"])
    File.write!(Path.join(repo, "master.txt"), "master\n")
    git!(repo, ["add", "master.txt"])
    git!(repo, ["commit", "-m", "master"])
    git!(repo, ["merge", "--no-commit", "side"])
    merge_path = canary <> ".txt"
    File.write!(Path.join(repo, merge_path), "merge-only path\n")
    git!(repo, ["add", merge_path])
    git!(repo, ["commit", "-m", "merge"])
    git!(repo, ["config", "log.diffMerges", "off"])

    merge_patch = git!(repo, ["show", "--format=", "--diff-merges=separate", "HEAD"])
    assert forbidden?(merge_patch)
    assert scan_repo(repo) == {1, false, true, false, false}

    git!(repo, ["rm", merge_path])
    git!(repo, ["commit", "-m", "remove merge-only file"])
    assert scan_repo(repo) == {0, false, true, false, false}
  end

  defp scan_repo(repo) do
    tracked_findings =
      repo
      |> git!(["ls-files", "-z"])
      |> String.split(<<0>>, trim: true)
      |> Enum.count(fn path -> forbidden?(path <> "\n" <> File.read!(Path.join(repo, path))) end)

    messages = git!(repo, ["log", "--all", "--format=fuller"])

    historical_paths =
      git!(repo, ["log", "--all", "--format=", "--name-only", "--diff-merges=separate"])

    tag_messages = git!(repo, ["for-each-ref", "--format=%(contents)", "refs/tags"])

    {tracked_findings, forbidden?(messages), forbidden?(historical_paths),
     historical_content_forbidden?(repo), forbidden?(tag_messages)}
  end

  defp historical_content_forbidden?(repo) do
    commits =
      repo
      |> git!(["rev-list", "--all"])
      |> String.split("\n", trim: true)

    patterns =
      Enum.map(@production_canaries, fn codepoints ->
        parts = codepoints |> List.to_string() |> String.split(["-", "_", " "], trim: true)
        body = Enum.map_join(parts, "[-_ ]?", &Regex.escape/1)
        "(?i)(?<![[:alnum:]_])#{body}(?![[:alnum:]_])"
      end)

    args =
      ["-C", repo, "grep", "--quiet", "-I", "-P"] ++
        Enum.flat_map(patterns, &["-e", &1]) ++ commits ++ ["--"]

    case System.cmd("git", args, stderr_to_stdout: true) do
      {_output, 0} -> true
      {_output, 1} -> false
      {output, status} -> raise "git grep failed with #{status}: #{output}"
    end
  end

  defp git!(repo, args) do
    {output, 0} = System.cmd("git", ["-C", repo | args], stderr_to_stdout: true)
    output
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
