defmodule BoundedAuthorityReportAdapter.LocalLoopbackCorpusTest do
  @moduledoc """
  Executes BAP's COMPLETE packaged local-loopback profile corpus through the
  dependency — the profile-side acceptance oracle for the 0.3.0 pin (the
  standard corpus stays discharged by `conformance_roundtrip_test.exs`).

  Coverage (every certified case, no sampling):

    * **identity** — the index's declared profile string + revision, and its
      sha256 self-declaration over BOTH content files (the loader refuses an
      unverified corpus at compile time; this test re-asserts the counts the
      index declares so corpus growth/revision reds until deliberately
      extended).
    * **8 proof cases** — each case's three DECLARED verdicts
      (`decode_local`, `decode_standard`, `envelope_local`) against the
      dependency's profile decoder, the standard decoder, and the profile
      envelope verifier with the corpus's own `expected_overrides` derivation
      (mirrors BAP's own runner, read first-hand).
    * **36 URI cases** — `normalize_uri/2` against each case's declared
      accept/reject (the exact admission code `sign_local_loopback_report/3`
      delegates to).
    * **certified proofs** — both certified compacts reproduce BYTE-EXACTLY
      from `proof_signing_input/2` + `assemble_compact/3` over the corpus's
      own context (the producer/assembler pair the adapter drives), and each
      verifies green through `check_envelope/2` with its per-family target.
  """

  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.ApplicationProfile.LocalLoopbackHttp.V1, as: Loopback
  alias BoundedAuthorityProtocol.V1
  alias BoundedAuthorityProtocol.V1.{Credentials, Proof}
  alias BoundedAuthorityReportAdapter.Conformance.{LocalProfileCase, Tag}

  @tag :conformance
  test "the index declares the certified profile identity, revision, and file set" do
    index = LocalProfileCase.index()

    assert index["profile"] == "bap-application-proof/local-loopback-http/1"
    assert index["revision"] == 1

    # The exact certified file set — a corpus file added or removed reds here.
    assert Enum.sort(Enum.map(index["files"], & &1["path"])) == [
             "profile.json",
             "proof-cases.json"
           ]
  end

  @tag :conformance
  test "the corpus hashes to its certified index (compile-time load + runtime re-assert)" do
    index = LocalProfileCase.index()

    assert index["proof_cases"] == length(LocalProfileCase.proof_cases())
    assert index["uri_cases"] == length(LocalProfileCase.uri_cases())

    # The loader verified each sha256 at compile; re-assert here so the test
    # itself (not only the compile step) carries the tamper evidence.
    profile_dir =
      Path.join([
        "deps",
        "bounded_authority_protocol",
        "priv",
        "conformance",
        "application-profiles",
        "local-loopback-http",
        "v1"
      ])

    for %{"path" => path, "sha256" => declared} <- index["files"] do
      actual =
        Path.join(profile_dir, path)
        |> File.read!()
        |> then(&:crypto.hash(:sha256, &1))
        |> Base.encode16(case: :lower)

      assert actual == declared, "corpus file #{path} drifted from the certified index"
    end
  end

  @tag :conformance
  test "every certified proof case matches its three declared verdicts" do
    for proof_case <- LocalProfileCase.proof_cases() do
      compact = proof_case["compact"]

      local_decode = match?({:ok, _}, Loopback.decode_proof(compact, %{}))
      standard_decode = match?({:ok, _}, V1.decode_proof(compact, %{}))

      envelope =
        match?(
          {:ok, _},
          Loopback.check_envelope(
            %Credentials{grant: LocalProfileCase.grant_compact(), proof: compact},
            LocalProfileCase.expected_request(proof_case)
          )
        )

      assert local_decode == proof_case["decode_local"], proof_case["id"]
      assert standard_decode == proof_case["decode_standard"], proof_case["id"]
      assert envelope == proof_case["envelope_local"], proof_case["id"]
    end
  end

  @tag :conformance
  test "the corpus's cross-profile verdicts are non-vacuous (both families present)" do
    cases = LocalProfileCase.proof_cases()

    ids = Enum.map(cases, & &1["id"])

    # A case the LOCAL decoder accepts and the STANDARD decoder rejects...
    assert "local-ipv4-valid" in ids
    assert Enum.any?(cases, &(&1["decode_local"] and not &1["decode_standard"]))

    # ...and the mirror image (standard bytes the local decoder rejects).
    assert Enum.any?(cases, &(&1["decode_standard"] and not &1["decode_local"]))

    # Both envelope verdict directions are certified.
    assert Enum.any?(cases, & &1["envelope_local"])
    assert Enum.any?(cases, &(not &1["envelope_local"]))
  end

  @tag :conformance
  test "every URI admission case matches its declared verdict through the dependency" do
    for uri_case <- LocalProfileCase.uri_cases() do
      actual = Loopback.normalize_uri(uri_case["input"], %{})

      if uri_case["valid"] do
        assert actual == {:ok, uri_case["normalized"]}, uri_case["id"]
      else
        assert actual == {:error, :invalid}, uri_case["id"]
      end
    end
  end

  @tag :conformance
  test "the certified proofs reproduce byte-exactly through the producer/assembler pair" do
    profile = LocalProfileCase.profile()
    holder_public = LocalProfileCase.holder_public_key()

    for {family, certified} <- profile["proofs"] do
      proof = %Proof{
        holder_public_key: holder_public,
        proof_id: certified["proof_id"],
        method: profile["request"]["method"],
        target_uri: certified["target_uri"],
        issued_at: profile["request"]["evaluation_time"],
        nonce: certified["nonce"],
        invocation_id: profile["request"]["invocation_id"],
        operation: profile["request"]["operation"],
        grant_compact: profile["grant_compact"],
        cast_arguments: Tag.from_raw(profile["request"]["cast_arguments"])
      }

      [protected, payload, signature] = String.split(certified["compact"], ".")

      assert {:ok, signing_input} = Loopback.proof_signing_input(proof, %{}),
             "certified #{family} proof did not reproduce its signing input"

      assert signing_input.protected_segment == protected, family
      assert signing_input.payload_segment == payload, family

      {:ok, signature_bytes} = Base.url_decode64(signature, padding: false)

      assert {:ok, assembled} = Loopback.assemble_compact(signing_input, signature_bytes, %{})
      assert assembled == certified["compact"], family

      # And the certified compact verifies green under its own family target.
      expected = %{
        LocalProfileCase.base_expected_request()
        | target_uri: certified["target_uri"],
          nonce: {:required, certified["nonce"]}
      }

      assert {:ok, _facts} =
               Loopback.check_envelope(
                 %Credentials{grant: profile["grant_compact"], proof: certified["compact"]},
                 expected
               ),
             family
    end
  end
end
