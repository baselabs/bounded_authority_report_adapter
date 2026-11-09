defmodule BoundedAuthorityReportAdapter.ConformanceCorpusTest do
  @moduledoc """
  Executes the protocol package's complete certified conformance corpora for contract-majors
  1, 2 and 3 through its documented verifier CLI, `BoundedAuthorityProtocol.Conformance.Cli.run/1`,
  over the corpus directories the package ships in `deps/`.

    * **Index identity** — each corpus's `index.json` SHA-256 equals the value pinned here,
      re-derived from the bytes on disk, not read from the package's own certification map,
      so a patched dependency cannot vouch for itself. The report's
      `index_sha256_base64url` must equal the same pin.
    * **Every case agrees** — `Cli.run/1` exits 0 only when every index file is present, no
      file is unlisted, every SHA-256 and count matches, the corpus is the certified one,
      and every case's verdict and producer bytes equal the expectation.
    * **Census** — the report's `total` and `agreed` equal the census pinned here
      (283 / 268 / 292) and `disagreed` is 0, so a run that executed fewer cases cannot pass.
    * **Not vacuous** — a copy of a corpus with one appended byte in a hash-verified sidecar
      exits 1.

  The v1 and v2 legs are dependency tamper evidence. The v3 leg also certifies the surfaces
  `BoundedAuthorityReportAdapter.V3` drives (`proof_signing_input/2`, `assemble_compact/3`,
  `check_envelope/2`).
  """

  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.Conformance.Cli

  @corpus_root Path.join(["deps", "bounded_authority_protocol", "priv", "conformance"])

  # Each certified corpus: its directory under priv/conformance, the base64url SHA-256 of its
  # exact index.json bytes, and its case census. A corpus rotation reds here until the pin
  # and census move deliberately.
  #
  # RELEASE COMMIT (protocol 1.0): add the selector-float-zero corpus, which the protocol
  # ships from 1.0.0 on, as
  #   {"selector-float-zero", "l_16mc2_OswKePW6HGVW4jpj4K1m9TPjH9afgtxfMAM", 161}
  # (directory, index pin, census), in the same commit that moves the requirement to `~> 1.0`.
  @corpora [
    {"v1/corpus", "TLUHKrQP_UsRFlnm1KsgIJICOAUF8fhCS5bSLlM8uRs", 283},
    {"v2/corpus", "beYom39HsOCnjqRhDnhEoPHVJH2OrOAuyc-YQTCPE9A", 268},
    {"v3/corpus", "pcgHXnU0NFw7tmEdC0ApKQS8-jrwcC4HrgFPpmkmQzw", 292}
  ]

  @tag :conformance
  test "each corpus index.json hashes to its independently pinned identity" do
    for {dir, pin, _census} <- @corpora do
      index_bytes = File.read!(Path.join([@corpus_root, dir, "index.json"]))

      assert index_identity(index_bytes) == pin,
             "the #{dir} corpus index drifted from its certified pin; a corpus rotation " <>
               "must be a deliberate change (move the pin)"
    end
  end

  @tag :conformance
  @tag :tmp_dir
  test "the CLI agrees on every certified case and its report carries the census",
       %{tmp_dir: tmp_dir} do
    for {dir, pin, census} <- @corpora do
      report_path = Path.join(tmp_dir, String.replace(dir, "/", "-") <> ".json")

      assert Cli.run(["--corpus", Path.join(@corpus_root, dir), "--report", report_path]) == 0,
             "the protocol CLI did not agree on the #{dir} corpus"

      report = report_path |> File.read!() |> JSON.decode!()

      assert %{
               "agreement" => true,
               "exit_status" => 0,
               "total" => ^census,
               "agreed" => ^census,
               "disagreed" => 0,
               "index_sha256_base64url" => ^pin
             } = report,
             "the #{dir} report does not carry the pinned census #{census} and index pin: " <>
               inspect(report)
    end
  end

  @tag :conformance
  @tag :tmp_dir
  test "the CLI is not vacuous: a tampered corpus copy exits 1", %{tmp_dir: tmp_dir} do
    # Append a byte to a .raw sidecar, which the loader hash-checks and never parses, so the
    # failure proves hash enforcement rather than a decode error.
    copy = Path.join(tmp_dir, "v3-corpus")
    File.cp_r!(Path.join(@corpus_root, "v3/corpus"), copy)
    assert Cli.run(["--corpus", copy, "--report", Path.join(tmp_dir, "intact.json")]) == 0

    sidecar =
      Path.wildcard(Path.join(copy, "**/*.raw")) |> Enum.sort() |> List.first() ||
        flunk("no .raw sidecar in the v3 corpus")

    File.write!(sidecar, <<0>>, [:append])

    assert Cli.run(["--corpus", copy, "--report", Path.join(tmp_dir, "tampered.json")]) == 1
  end

  defp index_identity(bytes),
    do: Base.url_encode64(:crypto.hash(:sha256, bytes), padding: false)
end
