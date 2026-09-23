defmodule BoundedAuthorityReportAdapter.Conformance.RoleAttestationCase do
  @moduledoc """
  TEST-ONLY loader for BAP's packaged role-attestation profile corpus (BAP 0.6.0, ADR 0036).

  The profile corpus ships in the DEPENDENCY at
  `priv/conformance/attestation-profiles/role-attestation/v1/` — an `index.json` (identity +
  revision + counts + per-file sha256s), a `profile.json` (the certified context: attestor
  trust-root, subject binding, now), and an `attestation-cases.json` (40 cases, each carrying
  `decode`/`verify` verdicts plus optional `expected_overrides`).

  The loader REFUSES an unverified corpus twice over: the index's sha256 over BOTH content
  files is checked at load, AND the index's own bytes are pinned to the certified digest
  (REQ-RA1-CONFORMANCE-certified-pin: every consumer pins that digest independently) — a
  patched corpus reds at COMPILE, before any case executes. `@external_resource` recompiles
  on any corpus edit (the `LocalProfileCase` discipline).
  """

  alias BoundedAuthorityProtocol.RoleAttestation.V1, as: RoleAttestationV1
  alias BoundedAuthorityProtocol.V1.{Bounds, HistoricalPublicKey}

  @profile_dir Path.join([
                 "deps",
                 "bounded_authority_protocol",
                 "priv",
                 "conformance",
                 "attestation-profiles",
                 "role-attestation",
                 "v1"
               ])

  @index_path Path.join(@profile_dir, "index.json")
  @profile_path Path.join(@profile_dir, "profile.json")
  @cases_path Path.join(@profile_dir, "attestation-cases.json")

  @external_resource @index_path
  @external_resource @profile_path
  @external_resource @cases_path

  # The certified revision-1 index digest (spec/bap-role-attestation-v1.md §6), pinned
  # independently by every corpus consumer — this package's is the third pin (BAP's ExUnit
  # suite + every in-repo SDK hold the others).
  @certified_index_sha "be5275c69539a0f31734242ff00a484c2f855f39181c55689d8b0f671195d62a"

  @index_bytes File.read!(@index_path)
  @index :json.decode(@index_bytes)
  @profile File.read!(@profile_path) |> :json.decode()
  @cases File.read!(@cases_path) |> :json.decode()

  unless Base.encode16(:crypto.hash(:sha256, @index_bytes), case: :lower) == @certified_index_sha do
    raise "role-attestation profile corpus index.json does not hash to the certified digest"
  end

  for %{"path" => file, "sha256" => expected_sha} <- @index["files"] do
    actual =
      Path.join(@profile_dir, file)
      |> File.read!()
      |> then(&:crypto.hash(:sha256, &1))
      |> Base.encode16(case: :lower)

    unless actual == expected_sha do
      raise "role-attestation profile corpus file #{file} hashes to #{actual}, index declares #{expected_sha}"
    end
  end

  @doc "The decoded profile-corpus index (identity, revision, counts, file hashes)."
  def index, do: @index

  @doc "The decoded profile.json (certified context: attestor, subject, now)."
  def profile, do: @profile

  @doc "The decoded attestation-cases.json (40 cases with declared verdicts)."
  def cases, do: @cases

  @doc """
  The baseline `%RoleAttestation.V1.ExpectedAttestation{}` from the certified context, with
  per-case `expected_overrides` applied (attestor_public_key / subject_key_id /
  subject_public_key / now — mirroring the corpus's own declared shape).
  """
  def expected(attestation_case) do
    base = base_expected()

    attestation_case
    |> Map.get("expected_overrides", %{})
    |> apply_overrides(base)
  end

  defp apply_overrides(overrides, base) when map_size(overrides) == 0, do: base

  defp apply_overrides(%{"attestor_public_key" => encoded}, base) do
    public_key = Base.url_decode64!(encoded, padding: false)
    %{base | attestor: %{base.attestor | public_key: public_key}}
  end

  defp apply_overrides(%{"subject_key_id" => subject_key_id}, base) do
    %{base | subject_key_id: subject_key_id}
  end

  defp apply_overrides(%{"subject_public_key" => encoded}, base) do
    %{base | subject_public_key: Base.url_decode64!(encoded, padding: false)}
  end

  defp apply_overrides(%{"now" => now}, base) do
    %{base | now: now}
  end

  defp apply_overrides(overrides, _base) do
    raise "unsupported expected_overrides in the certified corpus: #{inspect(Map.keys(overrides))}"
  end

  @doc "The baseline expected context (no overrides)."
  def base_expected do
    %RoleAttestationV1.ExpectedAttestation{
      attestor: %HistoricalPublicKey{
        key_id: @profile["attestor"]["key_id"],
        public_key: Base.url_decode64!(@profile["attestor"]["public_key"], padding: false),
        valid_from: @profile["attestor"]["valid_from"],
        valid_before: @profile["attestor"]["valid_before"]
      },
      subject_key_id: @profile["subject"]["key_id"],
      subject_public_key: Base.url_decode64!(@profile["subject"]["public_key"], padding: false),
      now: @profile["now"],
      bounds: Bounds.maximum()
    }
  end
end
