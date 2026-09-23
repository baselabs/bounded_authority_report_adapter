defmodule BoundedAuthorityReportAdapter.RoleAttestationCorpusTest do
  @moduledoc """
  Executes BAP's COMPLETE packaged role-attestation profile corpus through the dependency —
  the profile-side acceptance oracle for the 0.6.0 pin (cross-vendor review B2: the RA11
  gate suite proves the adapter's own gate; this file proves the dependency's attestation
  verification against the 40 CERTIFIED cases, the `LocalLoopbackCorpusTest` discipline).

  Coverage (every certified case, no sampling):

    * **identity** — the index's declared profile string, revision, exact two-file set, and
      case count (corpus growth/revision reds until deliberately extended).
    * **digests** — the index's own bytes pinned to the certified digest (compile-time in
      the loader, re-asserted here) + each content file's sha256 re-verified at runtime.
    * **40 cases** — each case's two DECLARED verdicts (`decode`, `verify`) against the
      dependency's `RoleAttestation.V1` with the corpus's own `expected_overrides`
      derivation, plus the decode-false-implies-verify-false invariant.
    * **cross-profile** — the certified attestation bytes rejected by the v1 surface, and
      the corpus's own live-grant case rejected by the profile decode (both directions).
  """

  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.RoleAttestation.V1, as: RoleAttestationV1
  alias BoundedAuthorityProtocol.V1
  alias BoundedAuthorityReportAdapter.Conformance.RoleAttestationCase

  @certified_index_sha "be5275c69539a0f31734242ff00a484c2f855f39181c55689d8b0f671195d62a"

  @tag :conformance
  test "the index declares the certified profile identity, revision, file set, and count" do
    index = RoleAttestationCase.index()

    assert index["profile"] == "bap-role-attestation/1"
    assert index["revision"] == 1
    assert index["attestation_cases"] == 40

    assert Enum.sort(Enum.map(index["files"], & &1["path"])) == [
             "attestation-cases.json",
             "profile.json"
           ]

    assert length(RoleAttestationCase.cases()) == index["attestation_cases"]
  end

  @tag :conformance
  test "the corpus hashes to its certified index (index digest pinned + per-file sha256)" do
    index = RoleAttestationCase.index()

    profile_dir =
      Path.join([
        "deps",
        "bounded_authority_protocol",
        "priv",
        "conformance",
        "attestation-profiles",
        "role-attestation",
        "v1"
      ])

    index_actual =
      Path.join(profile_dir, "index.json")
      |> File.read!()
      |> then(&:crypto.hash(:sha256, &1))
      |> Base.encode16(case: :lower)

    assert index_actual == @certified_index_sha

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
  test "every certified case matches its two declared verdicts through the dependency" do
    for attestation_case <- RoleAttestationCase.cases() do
      compact = attestation_case["compact"]

      decode_ok = match?({:ok, _}, RoleAttestationV1.decode_attestation(compact, %{}))

      verify_ok =
        match?(
          {:ok, _},
          RoleAttestationV1.verify_attestation(
            compact,
            RoleAttestationCase.expected(attestation_case)
          )
        )

      assert decode_ok == attestation_case["decode"], attestation_case["id"]
      assert verify_ok == attestation_case["verify"], attestation_case["id"]

      # A structurally invalid attestation can never verify.
      if not attestation_case["decode"] do
        refute verify_ok, attestation_case["id"]
      end
    end
  end

  @tag :conformance
  test "the corpus's verdict families are non-vacuous" do
    cases = RoleAttestationCase.cases()
    ids = Enum.map(cases, & &1["id"])

    assert Enum.any?(cases, & &1["verify"])
    assert Enum.count(cases, & &1["verify"]) == 5

    # The discriminating boundary + self-attestation families are all present.
    for id <-
          ~w(now-at-exp now-at-nbf nbf-at-attestor-valid-from exp-at-attestor-valid-before
             self-attestation-same-material self-attestation-same-key-id
             self-attestation-material-only subject-key-mismatch es256-signed-confusion
             cross-profile-grant-rejected) do
      assert id in ids, "certified case #{id} missing from the packaged corpus"
    end
  end

  @tag :conformance
  test "cross-profile rejection holds in both directions through the dependency" do
    valid =
      Enum.find(RoleAttestationCase.cases(), &(&1["id"] == "issuer-valid"))

    # The certified attestation bytes are rejected by the v1 surface.
    assert {:error, :invalid} = V1.decode_grant(valid["compact"], %{})

    # The corpus's own live v1 grant compact is rejected by the profile decode.
    grant_case =
      Enum.find(RoleAttestationCase.cases(), &(&1["v1_grant"] == true))

    assert {:error, :invalid} = RoleAttestationV1.decode_attestation(grant_case["compact"], %{})
  end
end
