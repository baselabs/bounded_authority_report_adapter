defmodule BoundedAuthorityReportAdapter.Conformance.LocalProfileCase do
  @moduledoc """
  TEST-ONLY loader for BAP's packaged local-loopback profile corpus (0.3.0).

  The profile corpus ships in the DEPENDENCY at
  `priv/conformance/application-profiles/local-loopback-http/v1/` — a DIFFERENT
  tree and schema from the standard V1 corpus (`priv/conformance/v1/`): an
  `index.json` (identity + per-file sha256s + counts), a `profile.json` (the
  certified context: issuer, grant, both proofs, request, and the 36 URI
  cases), and a `proof-cases.json` (8 cases, each carrying
  `decode_local`/`decode_standard`/`envelope_local` verdicts plus optional
  `expected_overrides` for the wrong-* cases).

  The loader REFUSES an unverified corpus: the index's sha256 over BOTH
  content files is checked at load (a patched corpus reds loudly here, never
  silently executes). The `@external_resource` bindings recompile this module
  on any corpus edit (the same discipline as `VectorCase`).
  """

  alias BoundedAuthorityProtocol.V1.{Bounds, ExpectedRequest, TrustedIssuer}
  alias BoundedAuthorityReportAdapter.Conformance.Tag

  @profile_dir Path.join([
                 "deps",
                 "bounded_authority_protocol",
                 "priv",
                 "conformance",
                 "application-profiles",
                 "local-loopback-http",
                 "v1"
               ])

  @index_path Path.join(@profile_dir, "index.json")
  @profile_path Path.join(@profile_dir, "profile.json")
  @cases_path Path.join(@profile_dir, "proof-cases.json")

  @external_resource @index_path
  @external_resource @profile_path
  @external_resource @cases_path

  @index File.read!(@index_path) |> :json.decode()
  @profile File.read!(@profile_path) |> :json.decode()
  @cases File.read!(@cases_path) |> :json.decode()

  # Verify the index's self-declared sha256 over each content file at load —
  # a corpus that does not hash to its certified index is not the certified
  # corpus. Compile-time, so a patched dependency reds at COMPILE, before any
  # case executes.
  for %{"path" => file, "sha256" => expected_sha} <- @index["files"] do
    actual =
      Path.join(@profile_dir, file)
      |> File.read!()
      |> then(&:crypto.hash(:sha256, &1))
      |> Base.encode16(case: :lower)

    unless actual == expected_sha do
      raise "local-loopback profile corpus file #{file} hashes to #{actual}, index declares #{expected_sha}"
    end
  end

  @doc "The decoded profile-corpus index (identity, revision, counts, file hashes)."
  def index, do: @index

  @doc "The decoded profile.json (certified context + uri_cases)."
  def profile, do: @profile

  @doc "The decoded proof-cases.json (8 cases with declared verdicts)."
  def proof_cases, do: @cases

  @doc "The 36 URI admission cases."
  def uri_cases, do: @profile["uri_cases"]

  @doc """
  The 32-byte issuer trust anchor from the certified context.
  """
  def issuer_public_key do
    Base.url_decode64!(@profile["issuer"]["public_key"], padding: false)
  end

  @doc """
  Builds the `%ExpectedRequest{}` the verifier-side surface consumes: the
  certified context's bound fields, the IPv4 proof's target/nonce as the
  baseline, and per-case `expected_overrides` applied (the wrong-* cases carry
  their poison in-corpus — the derivation mirrors BAP's own profile corpus
  runner, read first-hand at
  test/bounded_authority_protocol/application_profile/local_loopback_http/v1_test.exs).
  """
  def expected_request(proof_case) do
    base = base_expected_request()

    case Map.get(proof_case, "expected_overrides", %{}) do
      overrides when map_size(overrides) == 0 ->
        base

      %{"trusted_issuer_public_key" => encoded} = overrides when map_size(overrides) == 1 ->
        public_key = Base.url_decode64!(encoded, padding: false)
        %{base | trusted_issuer: %{base.trusted_issuer | public_key: public_key}}

      %{"invocation_id" => invocation_id} = overrides when map_size(overrides) == 1 ->
        %{base | invocation_id: invocation_id}

      overrides ->
        raise "unsupported expected_overrides in the certified corpus: #{inspect(Map.keys(overrides))}"
    end
  end

  @doc """
  The baseline `%ExpectedRequest{}` from the certified context (no overrides)
  — the shared base `expected_request/1` derives every case from.
  """
  def base_expected_request do
    %ExpectedRequest{
      trusted_issuer: %TrustedIssuer{
        key_id: @profile["issuer"]["key_id"],
        public_key: issuer_public_key()
      },
      issuer: @profile["issuer"]["issuer"],
      audience: @profile["issuer"]["audience"],
      method: @profile["request"]["method"],
      target_uri: @profile["proofs"]["ipv4"]["target_uri"],
      invocation_id: @profile["request"]["invocation_id"],
      operation: @profile["request"]["operation"],
      cast_arguments: Tag.from_raw(@profile["request"]["cast_arguments"]),
      evaluation_time: @profile["request"]["evaluation_time"],
      clock_skew: @profile["request"]["clock_skew"],
      proof_max_age: @profile["request"]["proof_max_age"],
      nonce: {:required, @profile["proofs"]["ipv4"]["nonce"]},
      bounds: Bounds.maximum()
    }
  end

  @doc "The corpus's grant compact (issuer-signed, certified)."
  def grant_compact, do: @profile["grant_compact"]

  @doc "The holder public key the certified proofs bind (raw 32 bytes)."
  def holder_public_key,
    do: Base.url_decode64!(@profile["holder_public_key"], padding: false)
end
