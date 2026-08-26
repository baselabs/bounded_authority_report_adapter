# Release-candidate reproducibility gate (adapted from the BAP sibling's
# check_release_candidate.exs, read first-hand).
#
# Builds the unpublished candidate archive TWICE, each in a fresh COPY of the
# source tree under a temp dir, and asserts the two archives are byte-identical
# (SHA-256 equal). Two independently-built archives — never a shared-cache
# self-comparison. Cache isolation: each copy gets its own deps.get +
# hex.build; the developer's _build/deps are never mutated (copies removed in
# after).
#
# Honest scope: hex.build packages SOURCE files (the files: list), not
# compiled BEAMs, and Hex normalizes tar mtimes to epoch — the gate's value is
# REGRESSION DETECTION: it catches the moment a change introduces a
# non-deterministic packaged input (a generated file embedding a path or
# timestamp, a dep writing into a packaged dir, a per-build metadata field).
# A tamper that changes a packaged source file between the two builds is
# proven to red the gate (the slice's red-capable proof, quoted in the
# ticket closeout).

defmodule BoundedAuthorityReportAdapter.ReproducibleCheck do
  @moduledoc false

  def run! do
    source_root = File.cwd!()
    assert_mix_lock_present!(source_root)

    tmp = unique_tmp_root!()

    try do
      copy1 = Path.join(tmp, "copy1")
      copy2 = Path.join(tmp, "copy2")
      build1 = Path.join(tmp, "build1.tar")
      build2 = Path.join(tmp, "build2.tar")

      copy_source_tree!(source_root, copy1)
      copy_source_tree!(source_root, copy2)

      build_in!(copy1, build1)
      build_in!(copy2, build2)

      digest1 = sha256_file(build1)
      digest2 = sha256_file(build2)

      unless digest1 == digest2 do
        raise(
          "release candidate check failed: candidate archive is not reproducible across " <>
            "independent builds: build1=#{digest1} build2=#{digest2} (two fresh source-tree " <>
            "copies, no shared cache; a non-deterministic input produced different bytes)"
        )
      end

      IO.puts("release candidate reproducibility gate passed (two independent builds agree)")
      IO.puts("candidate archive SHA-256: #{digest1}")
    after
      File.rm_rf!(tmp)
    end
  end

  defp assert_mix_lock_present!(source_root) do
    unless File.regular?(Path.join(source_root, "mix.lock")) do
      raise("release candidate check failed: mix.lock is missing — reproducibility cannot be checked without a locked dep set")
    end
  end

  # What a reproducible build starts from: source only — no build artifacts,
  # fetched deps, tool/state dirs, or generated output.
  @copy_excludes ~w(_build deps .git .forge .zcode .kimosabe artifacts cover doc
                    graphify-out erl_crash.dump)

  defp copy_source_tree!(source, dest) do
    File.mkdir_p!(dest)

    source
    |> File.ls!()
    |> Enum.reject(&(&1 in @copy_excludes))
    |> Enum.each(fn entry ->
      File.cp_r!(Path.join(source, entry), Path.join(dest, entry))
    end)
  end

  defp build_in!(copy_root, output) do
    run!("mix", ["deps.get"], copy_root)
    run!("mix", ["hex.build", "--output", output], copy_root)
    assert_regular_nonempty!(output)
  end

  defp unique_tmp_root! do
    template = Path.join(System.tmp_dir!(), "bounded-authority-report-reproducible.XXXXXX")

    case System.cmd("mktemp", ["-d", template], stderr_to_stdout: true) do
      {path, 0} ->
        path = String.trim(path)

        if File.dir?(path),
          do: path,
          else: raise("release candidate check failed: mktemp returned a missing directory")

      {output, status} ->
        raise("release candidate check failed: mktemp exited with status #{status}: #{String.trim(output)}")
    end
  end

  defp sha256_file(path) do
    data = File.read!(path)
    Base.encode16(:crypto.hash(:sha256, data), case: :lower)
  end

  defp assert_regular_nonempty!(path) do
    unless File.regular?(path) and File.stat!(path).size > 0 do
      raise("release candidate check failed: candidate archive is missing or empty: #{path}")
    end
  end

  defp run!(command, arguments, directory) do
    case System.cmd(command, arguments,
           cd: directory,
           stderr_to_stdout: true,
           into: IO.stream(:stdio, :line)
         ) do
      {_output, 0} ->
        :ok

      {_output, status} ->
        raise("release candidate check failed: #{command} #{Enum.join(arguments, " ")} exited with status #{status}")
    end
  end
end

BoundedAuthorityReportAdapter.ReproducibleCheck.run!()
