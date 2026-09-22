defmodule BoundedAuthorityReportAdapter.ConformanceCorpusTest do
  @moduledoc """
  The three-corpus leg (B2 / ADR-0021; supersedes ADR-0013 decision 1's
  one-vector scope by explicit owner direction — see ADR-0013's dated
  amendment).

  Executes BAP's COMPLETE certified conformance corpora — v1, v2, and v3 —
  through the pinned dependency's own certified loader and runner:

    * **Index identity** — each corpus's `index.json` SHA-256 equals the
      pinned value, INDEPENDENTLY re-derived here (not read from the
      package's own pin map, so a patched dependency cannot lie about its
      own certification). The pins are the registry-read-back values from
      the BAP 0.5.1 release program.
    * **Full integrity** — `Corpus.load/1` verifies per-file SHA-256,
      exact file-set equality both directions, per-file and total case
      counts, corpus-wide case-id uniqueness, applicability totality, and
      tamper binding. A tamper leg proves the load reds on a flipped byte
      (the harness is not vacuously green).
    * **Every case agrees** — `Runner.run/1` dispatches each case against
      the corpus's contract-major facade (the v3 leg includes the
      byte-exact signing-input reproduction and the suite matrices) and
      compares against the case-declared expectation.
    * **Census** — the declared and executed case counts equal the
      certified census (283 / 268 / 292).

  The v1 and v2 legs are dep tamper-evidence — BAP's certified corpus
  executed through BAP's own functions; a patched or mutated dependency
  reds here. The v3 leg is that PLUS this library's adopted suite: the
  same surfaces `BoundedAuthorityReportAdapter.V3` drives
  (`proof_signing_input/2`, `assemble_compact/3`, `check_envelope/2`) are
  the ones the v3 corpus certifies.
  """

  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.Conformance.{Corpus, Runner}

  @corpus_root Path.join(["deps", "bounded_authority_protocol", "priv", "conformance"])

  # The certified corpus index identities (ADR 0014 D4 semantics), pinned
  # independently of the package: base64url SHA-256 of the exact index.json
  # bytes. Rotation reds here by design until deliberately extended.
  @pinned_index_sha256 %{
    "v1" => "TLUHKrQP_UsRFlnm1KsgIJICOAUF8fhCS5bSLlM8uRs",
    "v2" => "beYom39HsOCnjqRhDnhEoPHVJH2OrOAuyc-YQTCPE9A",
    "v3" => "pcgHXnU0NFw7tmEdC0ApKQS8-jrwcC4HrgFPpmkmQzw"
  }

  @pinned_total_cases %{"v1" => 283, "v2" => 268, "v3" => 292}

  @tag :conformance
  test "each corpus index.json hashes to its independently pinned identity" do
    for {major, pin} <- @pinned_index_sha256 do
      index_bytes = File.read!(Path.join([@corpus_root, major, "corpus", "index.json"]))

      actual = Base.url_encode64(:crypto.hash(:sha256, index_bytes), padding: false)

      assert actual == pin,
             "the #{major} corpus index drifted from its certified pin — a corpus " <>
               "rotation must be a deliberate change (bump the pin)"
    end
  end

  @tag :conformance
  test "each corpus loads through the package loader with full integrity verification" do
    for {major, census} <- @pinned_total_cases do
      assert {:ok, corpus} = Corpus.load(corpus_map(major))
      assert corpus.index["total_cases"] == census, major
    end
  end

  @tag :conformance
  test "every certified case agrees through the pinned package's runner" do
    for major <- Map.keys(@pinned_total_cases) do
      {:ok, corpus} = Corpus.load(corpus_map(major))

      disagreements =
        for {_path, results} <- Runner.run(corpus),
            result <- results,
            not result.agree,
            do: result.case_id

      assert disagreements == [],
             "#{major} corpus cases disagreed with the dependency: " <> inspect(disagreements)
    end
  end

  @tag :conformance
  test "the executed census equals the certified census (no silent case loss)" do
    for {major, census} <- @pinned_total_cases do
      {:ok, corpus} = Corpus.load(corpus_map(major))

      executed =
        corpus.cases |> Enum.map(fn {_path, cases} -> length(cases) end) |> Enum.sum()

      assert executed == census, major
      assert corpus.index["total_cases"] == executed, major
    end
  end

  @tag :conformance
  test "the integrity verification is not vacuous: a tampered corpus byte reds the load" do
    # Non-vacuity proof (the defect-injection discipline): flip one byte in
    # one case file's in-memory copy and the loader must reject — proving
    # the green loads above certify content, not mere presence.
    map = corpus_map("v3")
    [{path, bytes} | _] = Enum.sort(map)

    {head, rest} = String.split_at(bytes, 8)
    tampered = Map.put(map, path, head <> "X" <> rest)

    assert {:error, :invalid} = Corpus.load(tampered)
  end

  defp corpus_map(major) do
    walk(Path.join([@corpus_root, major, "corpus"]))
  end

  # The corpus map in the pure loader's shape: every file under the corpus
  # dir keyed by its path relative to the corpus root (the same walk the
  # package's CLI performs — `Conformance.Cli`'s read_corpus_dir).
  defp walk(dir) do
    walk(dir, File.ls!(dir), "")
  end

  defp walk(_dir, [], _prefix), do: %{}

  defp walk(dir, [entry | rest], prefix) do
    full = Path.join(dir, entry)
    rel = if prefix == "", do: entry, else: Path.join(prefix, entry)

    if File.dir?(full) do
      Map.merge(walk(full, File.ls!(full), rel), walk(dir, rest, prefix))
    else
      Map.put(walk(dir, rest, prefix), rel, File.read!(full))
    end
  end
end
