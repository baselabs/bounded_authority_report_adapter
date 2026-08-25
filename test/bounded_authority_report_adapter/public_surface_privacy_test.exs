defmodule BoundedAuthorityReportAdapter.PublicSurfacePrivacyTest do
  use ExUnit.Case, async: false

  @forbidden_hashes MapSet.new([
                      "2e30ad6c8aca2e4546f9f025ad772ba49e95b9d1a174e647fa793aeded6691b9",
                      "44abe4ace21b534dfb1eef35741807ec85dd1766486a86fd7d6b5a822f58e470",
                      "4e8c2d200b4a4538da9dc9d04c618a1e10117629799f690113f7caf1e4a29a15",
                      "6f7b03460ad6bbbf99ac00c89f3939e825c846d38da079f0e920b3d0347bcae6",
                      "a32b176c56bea1f4e551e76e17d60bb6acac7822850dc3673b944ae8f3db8dce",
                      "b117c7b0bf3e433efb7d9d0153e4c0935be834921e19dc4bf371fd1484613e30",
                      "e3cfccf27e299a2e01f32d5cb8e7a63bf23a23d7071d396e8b042b9f6ae72885"
                    ])

  test "tracked files and reachable history contain no private consumer topology" do
    {tracked_output, 0} = System.cmd("git", ["ls-files", "-z"], stderr_to_stdout: true)

    tracked_findings =
      tracked_output
      |> String.split(<<0>>, trim: true)
      |> Enum.count(fn path -> forbidden?(path <> "\n" <> File.read!(path)) end)

    {history, 0} =
      System.cmd(
        "git",
        ["log", "--all", "--format=fuller", "--name-status", "-p", "--no-ext-diff", "--text"],
        stderr_to_stdout: true
      )

    history_findings = if forbidden?(history), do: 1, else: 0

    assert {tracked_findings, history_findings} == {0, 0},
           "public-surface privacy gate found forbidden material: " <>
             "tracked_sources=#{tracked_findings}, reachable_history=#{history_findings}"
  end

  defp forbidden?(content) do
    content
    |> String.downcase()
    |> candidates()
    |> Enum.any?(&(digest(&1) in @forbidden_hashes))
  end

  defp candidates(content) do
    tokens =
      ~r/[a-z0-9_]+(?:-[a-z0-9_]+)*/u
      |> Regex.scan(content, capture: :first)
      |> List.flatten()

    components = Enum.flat_map(tokens, &String.split(&1, ["-", "_"], trim: true))
    token_pairs = Enum.zip(tokens, Enum.drop(tokens, 1)) |> Enum.map(&Tuple.to_list/1)
    component_pairs = Enum.zip(components, Enum.drop(components, 1)) |> Enum.map(&Tuple.to_list/1)

    tokens ++
      components ++
      Enum.flat_map(token_pairs ++ component_pairs, fn [left, right] ->
        [left <> " " <> right, left <> "_" <> right, left <> "-" <> right]
      end)
  end

  defp digest(value), do: :crypto.hash(:sha256, value) |> Base.encode16(case: :lower)
end
