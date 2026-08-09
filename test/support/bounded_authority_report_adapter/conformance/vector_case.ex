defmodule BoundedAuthorityReportAdapter.Conformance.VectorCase do
  @moduledoc """
  TEST-ONLY loader + builder for RA2's conformance round-trip harness.

  Loads BAP's published `grant-holder-proof.json` vector (at the pinned dep ref)
  once, decodes it, and builds the `ExpectedRequest` (bars i / iii / iv) /
  `ExpectedGrant` (bar i-grant) / `TrustedIssuer` structs BAP's
  `check_envelope/2` + `verify_grant/3` consume.

  ## The three non-obvious pieces (design §1.6 — all first-hand verified)

    * **(A) Typed-tuple translation.** `cast_arguments` MUST be BAP's tagged
      `Json.value()` form, not a raw map. The vector carries the typed form as a
      JSON array `["type", value]`; `Tag.from_json/1` translates it. **No type
      guard** on the object/array arms — `:json.decode` yields maps for JSON
      objects, and `Enum.map` over a map yields `{k,v}` tuples.
    * **(B) Synthesized `:bounds`.** The vector's `expected_context` carries no
      `bounds`; the structs require it (`@enforce_keys`). `V1.Bounds.maximum/0`
      is synthesized (BAP's default).
    * **(C) Per-case nonce derivation.** The shared `expected_context.nonce` is
      `{"required": "challenge-001"}`, but `positive_cases.nonce_absent` is a
      declared-VALID case whose proof payload carries NO nonce. Deriving the
      nonce expectation from the SHARED context reds that case; the expectation
      is derived PER CASE from the proof payload's nonce presence.

  The selector_denied sub-cases carry their OWN `typed_cast_arguments` (a
  different `ba_req`), so `cast_arguments` is derived per case when present.
  """

  alias BoundedAuthorityProtocol.V1
  alias BoundedAuthorityProtocol.V1.{ExpectedGrant, ExpectedRequest, TrustedIssuer}

  # The typed-tuple translator lives in a sibling test-support module
  # (design §1.6 A). Same `Conformance` namespace, so the alias is explicit.
  alias BoundedAuthorityReportAdapter.Conformance.Tag

  @vector_path Path.join([
                 "deps",
                 "bounded_authority_protocol",
                 "priv",
                 "conformance",
                 "v1",
                 "vectors",
                 "grant-holder-proof.json"
               ])

  @vector File.read!(@vector_path) |> :json.decode()

  @doc "The decoded published vector."
  def vector, do: @vector

  @doc "The expected_context block (shared across the published cases)."
  def expected_context, do: @vector["expected_context"]

  @doc "The 32-byte raw issuer public key (from `public_keys.issuer.raw_base64url`)."
  def issuer_public_key do
    Base.url_decode64!(
      @vector["public_keys"]["issuer"]["raw_base64url"],
      padding: false
    )
  end

  @doc "The `%TrustedIssuer{}` from the vector's expected_context."
  def trusted_issuer do
    %TrustedIssuer{
      key_id: @vector["expected_context"]["trusted_issuer"]["key_id"],
      public_key: issuer_public_key()
    }
  end

  @doc """
  The tagged `Json.value()` form of the vector's top-level `cast_arguments`,
  via `Tag.from_json/1`. Verified: `RequestDigest.digest_raw` of this value
  matches the vector's published `ba_req`.
  """
  def typed_cast_arguments do
    Tag.from_json(@vector["request"]["typed_cast_arguments"])
  end

  @doc """
  Builds an `%ExpectedRequest{}` for a published case.

  `case` is either `:top_level` (the top-level envelope) or a case map from the
  vector (`received_member_order_variant`, a `positive_cases` / `negative_cases`
  entry, a `selector_denied` sub-case). The builder:

    * derives `cast_arguments` from the case's OWN `typed_cast_arguments` when
      present (selector_denied carries a distinct `ba_req`), else from the
      top-level `request.typed_cast_arguments`;
    * derives `nonce` PER CASE (design §1.6 C): if the case's proof payload has
      a `"nonce"` key, `{:required, that_nonce}`; otherwise `:not_required`
      (the shared `expected_context.nonce` would red `nonce_absent`);
    * synthesizes `bounds: V1.Bounds.maximum/0` (design §1.6 B);
    * carries the shared expected_context's request fields.
  """
  def expected_request(case)

  def expected_request(:top_level) do
    build_expected_request(typed_cast_arguments(), @vector["proof"]["payload"])
  end

  def expected_request(case) when is_map(case) do
    proof_payload = case["proof"]["payload"]

    cast =
      case case["typed_cast_arguments"] do
        nil -> typed_cast_arguments()
        typed -> Tag.from_json(typed)
      end

    build_expected_request(cast, proof_payload)
  end

  @doc """
  Builds an `%ExpectedGrant{}` for bar (i-grant) — the grant-only verifier
  surface. No nonce field on `ExpectedGrant`; `bounds` synthesized.
  """
  def expected_grant do
    ec = @vector["expected_context"]

    %ExpectedGrant{
      issuer: ec["issuer"],
      audience: ec["audience"],
      evaluation_time: ec["evaluation_time"],
      clock_skew: ec["clock_skew"],
      bounds: V1.Bounds.maximum()
    }
  end

  defp build_expected_request(cast_arguments, proof_payload) do
    ec = @vector["expected_context"]

    %ExpectedRequest{
      trusted_issuer: trusted_issuer(),
      issuer: ec["issuer"],
      audience: ec["audience"],
      method: ec["method"],
      target_uri: ec["target_uri"],
      invocation_id: ec["invocation_id"],
      operation: ec["operation"],
      cast_arguments: cast_arguments,
      evaluation_time: ec["evaluation_time"],
      clock_skew: ec["clock_skew"],
      proof_max_age: ec["proof_max_age"],
      nonce: nonce_for(proof_payload),
      bounds: V1.Bounds.maximum()
    }
  end

  # Per-case nonce derivation (design §1.6 C). A proof payload that carries a
  # "nonce" key -> {:required, that_nonce}; otherwise :not_required. The shared
  # expected_context.nonce would red the nonce_absent declared-valid case.
  defp nonce_for(proof_payload) when is_map(proof_payload) do
    case proof_payload["nonce"] do
      nil -> :not_required
      nonce -> {:required, nonce}
    end
  end

  defp nonce_for(_), do: :not_required
end
