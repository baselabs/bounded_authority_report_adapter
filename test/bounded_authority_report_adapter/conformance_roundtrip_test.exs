defmodule BoundedAuthorityReportAdapter.ConformanceRoundtripTest do
  @moduledoc """
  RA2 — the conformance round-trip harness. Makes BAP's published
  `grant-holder-proof.json` vector the oracle for the adapter's envelope
  contract (ROADMAP RA2). Bars (design §1):

    * **(i)** published ENVELOPE cases verify via `check_envelope/2` matching
      each declared `expected_verdict`.
    * **(i-grant)** published GRANT-TIME cases (`grant_time_cases`, grant-only,
      no proof) verify via `verify_grant/3` matching each declared verdict.
    * **(iii)** adapter-coherent round-trip: the adapter signs a fresh holder
      proof against a fresh issuer-signed grant binding that holder; the
      envelope verifies green.
    * **(iv)** defect-injection non-vacuity: a bad-signature or tampered-body
      envelope goes RED (proven RED-first).

  ## The honest boundary (design §1.1)

  The handoff's "bar (ii)" — adapter-produced proof vs the *published* grant —
  is a falsifiable impossibility: `verify_proof_parsed` (runtime.ex:482) binds
  the proof's holder thumbprint to the grant's `cnf.jkt`, and the published
  holder's private key is not tracked. The reachable adapter-coherent bar is
  (iii): re-issue a grant against the adapter's fresh holder.
  """

  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.V1
  alias BoundedAuthorityProtocol.V1.{Credentials, TrustedIssuer}
  alias BoundedAuthorityReportAdapter.Conformance.VectorCase
  alias BoundedAuthorityReportAdapter.Keys.RawKey
  alias BoundedAuthorityReportAdapter.TestKeys

  # Pinned evaluation time for the adapter-coherent bar (iii): aligned to the
  # RA1 fixture grant windows (the TestKeys grant builder is the issuer here).
  @now 1_750_000_000

  # The cast_arguments for bar (iii) — tagged Json.value() form (the RA1
  # gotcha: a raw map is rejected by RequestDigest.typed/1).
  @cast_arguments {:object, [{"record", {:object, [{"region", {:string, "us-east"}}]}}]}
  @operation "report_external_materialization"

  describe "bar (i): published ENVELOPE cases verify via check_envelope/2" do
    @tag :conformance
    test "top-level grant+proof verify green (valid)" do
      v = VectorCase.vector()

      assert {:ok, _facts} =
               V1.check_envelope(
                 %Credentials{
                   grant: v["grant"]["compact"],
                   proof: v["proof"]["compact"]
                 },
                 VectorCase.expected_request(:top_level)
               )
    end

    @tag :conformance
    test "received_member_order_variant grant+proof verify green (valid)" do
      # A SEPARATE issuer-signed grant+proof pair (its ath is distinct from the
      # top-level). It is verified with its own grant + its own
      # expected_request (derived from the shared expected_context).
      rmo = VectorCase.vector()["received_member_order_variant"]

      assert {:ok, _facts} =
               V1.check_envelope(
                 %Credentials{
                   grant: rmo["grant"]["compact"],
                   proof: rmo["proof"]["compact"]
                 },
                 VectorCase.expected_request(rmo)
               )
    end

    @tag :conformance
    test "positive_cases.nonce_absent verifies green (valid) — per-case :not_required nonce" do
      # The proof payload carries NO nonce. The shared expected_context.nonce
      # would red this declared-valid case; the per-case derivation in
      # VectorCase sets nonce: :not_required (design §1.6 C).
      v = VectorCase.vector()
      na = v["positive_cases"]["nonce_absent"]

      assert {:ok, _facts} =
               V1.check_envelope(
                 %Credentials{
                   grant: v["grant"]["compact"],
                   proof: na["proof"]["compact"]
                 },
                 VectorCase.expected_request(na)
               )
    end

    @tag :conformance
    test "negative_cases.wrong_holder goes red (invalid)" do
      v = VectorCase.vector()
      wh = v["negative_cases"]["wrong_holder"]

      assert {:error, :invalid} =
               V1.check_envelope(
                 %Credentials{
                   grant: v["grant"]["compact"],
                   proof: wh["proof"]["compact"]
                 },
                 VectorCase.expected_request(wh)
               )
    end

    @tag :conformance
    test "negative_cases.duplicate_member goes red (invalid — malformed header)" do
      # A bare compact with a duplicated "alg" member in the protected header.
      # check_envelope rejects at decode (duplicate member); feeding it as the
      # proof against the top-level grant reds.
      v = VectorCase.vector()
      dm = v["negative_cases"]["duplicate_member"]

      assert {:error, :invalid} =
               V1.check_envelope(
                 %Credentials{
                   grant: v["grant"]["compact"],
                   proof: dm["compact"]
                 },
                 VectorCase.expected_request(:top_level)
               )
    end

    @tag :conformance
    test "negative_cases.selector_denied.equals goes red (invalid selector)" do
      v = VectorCase.vector()
      sd = v["negative_cases"]["selector_denied"]["equals"]

      assert {:error, :invalid} =
               V1.check_envelope(
                 %Credentials{
                   grant: v["grant"]["compact"],
                   proof: sd["proof"]["compact"]
                 },
                 VectorCase.expected_request(sd)
               )
    end

    @tag :conformance
    test "negative_cases.selector_denied.one_of goes red (invalid selector)" do
      v = VectorCase.vector()
      sd = v["negative_cases"]["selector_denied"]["one_of"]

      assert {:error, :invalid} =
               V1.check_envelope(
                 %Credentials{
                   grant: v["grant"]["compact"],
                   proof: sd["proof"]["compact"]
                 },
                 VectorCase.expected_request(sd)
               )
    end
  end

  describe "bar (i-grant): published GRANT-TIME cases verify via verify_grant/3" do
    # The grant_time_cases carry ONLY a grant (no proof). They are
    # grant-time-predicate exercises; the published proof's ath binds the
    # top-level grant, so check_envelope reds at the ath binding before the
    # time predicate is reached. The grant-only verifier verify_grant/3 is the
    # correct surface (design §1 bar i-grant; verified first-hand).

    @tag :conformance
    test "every grant_time_case matches its declared expected_verdict via verify_grant/3" do
      v = VectorCase.vector()
      trusted = VectorCase.trusted_issuer()
      expected_grant = VectorCase.expected_grant()

      for gtc <- v["grant_time_cases"] do
        verdict = gtc["expected_verdict"]

        result =
          V1.verify_grant(gtc["grant"]["compact"], trusted, expected_grant)

        case verdict do
          "valid" ->
            assert {:ok, _facts} = result,
                   "grant_time_case #{gtc["name"]} declared valid but verify_grant red"

          "invalid" ->
            assert {:error, :invalid} = result,
                   "grant_time_case #{gtc["name"]} declared invalid but verify_grant green"
        end
      end
    end

    @tag :conformance
    test "the grant_time_cases pin is non-vacuous: at least one valid AND one invalid" do
      cases = VectorCase.vector()["grant_time_cases"]
      verdicts = Enum.map(cases, & &1["expected_verdict"]) |> MapSet.new()

      assert MapSet.member?(verdicts, "valid"),
             "no valid grant_time_cases — the pin would be vacuously red-only"

      assert MapSet.member?(verdicts, "invalid"),
             "no invalid grant_time_cases — the pin would be vacuously green-only"
    end
  end

  describe "bar (iii): adapter-coherent round-trip (fresh holder + fresh grant)" do
    # The reachable form of "adapter-produced proof verifies": the adapter signs
    # a proof with a fresh holder keypair against a freshly issuer-signed grant
    # binding that holder's thumbprint. The handoff's "bar (ii)" (adapter proof
    # vs the PUBLISHED grant) is a falsifiable impossibility — the published
    # grant's cnf.jkt binds the published holder (private key not tracked), so
    # verify_proof_parsed (runtime.ex:482) reds any fresh-holder proof against
    # it. This bar proves the adapter's proof is byte-compatible with a grant a
    # real issuer would mint for that holder.

    @tag :conformance
    test "an envelope signed through the adapter verifies green via check_envelope/2" do
      {holder_pub, _holder_priv} = TestKeys.holder_keypair()
      thumb = TestKeys.holder_thumbprint_raw(holder_pub)

      {grant_compact, issuer_pub} =
        TestKeys.issuer_signed_grant_compact(thumb,
          issued_at: @now - 100,
          not_before: @now - 100,
          expires_at: @now + 3600
        )

      report = %{
        grant_compact: grant_compact,
        operation: @operation,
        method: "POST",
        target_uri: "https://api.example.test/invoke",
        invocation_id: "123e4567-e89b-42d3-a456-426614174000",
        cast_arguments: @cast_arguments,
        nonce: nil
      }

      assert {:ok, %{grant: grant, proof: proof}} =
               BoundedAuthorityReportAdapter.sign_report(
                 report,
                 {RawKey, TestKeys.holder_keypair()},
                 %{issued_at: @now - 50, proof_id: "ra2-adapter-coherent-001"}
               )

      # The grant passes through; the adapter signs ONLY the proof.
      assert grant == grant_compact

      assert {:ok, _facts} =
               V1.check_envelope(
                 %Credentials{grant: grant, proof: proof},
                 %V1.ExpectedRequest{
                   trusted_issuer: %TrustedIssuer{
                     key_id: "issuer-2026-07",
                     public_key: issuer_pub
                   },
                   issuer: "https://issuer.example.test",
                   audience: "https://verifier.example.test",
                   method: report.method,
                   target_uri: report.target_uri,
                   invocation_id: report.invocation_id,
                   operation: report.operation,
                   cast_arguments: report.cast_arguments,
                   evaluation_time: @now,
                   clock_skew: 60,
                   proof_max_age: 300,
                   # The proof carries no nonce (report.nonce == nil); the
                   # shared {:required, _} would red at nonce_matches?/2.
                   nonce: :not_required,
                   bounds: V1.Bounds.maximum()
                 }
               )
    end
  end

  describe "bar (iv): defect-injection non-vacuity (RED-first)" do
    # The protected mutation: a tampered proof must go RED. A suite of green
    # paths passes over a broken contract (the forge tripwire rule); the
    # defect-injection tests prove the harness is not vacuously green. Each
    # injected defect is proven RED; the un-tampered envelope is green.

    setup do
      # Build the green envelope once (bar iii's mechanism).
      {holder_pub, _holder_priv} = TestKeys.holder_keypair()
      thumb = TestKeys.holder_thumbprint_raw(holder_pub)

      {grant_compact, issuer_pub} =
        TestKeys.issuer_signed_grant_compact(thumb,
          issued_at: @now - 100,
          not_before: @now - 100,
          expires_at: @now + 3600
        )

      report = %{
        grant_compact: grant_compact,
        operation: @operation,
        method: "POST",
        target_uri: "https://api.example.test/invoke",
        invocation_id: "123e4567-e89b-42d3-a456-426614174000",
        cast_arguments: @cast_arguments,
        nonce: nil
      }

      {:ok, %{grant: grant, proof: proof}} =
        BoundedAuthorityReportAdapter.sign_report(
          report,
          {RawKey, TestKeys.holder_keypair()},
          %{issued_at: @now - 50, proof_id: "ra2-defect-injection-001"}
        )

      expected =
        %V1.ExpectedRequest{
          trusted_issuer: %TrustedIssuer{key_id: "issuer-2026-07", public_key: issuer_pub},
          issuer: "https://issuer.example.test",
          audience: "https://verifier.example.test",
          method: report.method,
          target_uri: report.target_uri,
          invocation_id: report.invocation_id,
          operation: report.operation,
          cast_arguments: report.cast_arguments,
          evaluation_time: @now,
          clock_skew: 60,
          proof_max_age: 300,
          nonce: :not_required,
          bounds: V1.Bounds.maximum()
        }

      # The un-tampered envelope MUST be green — otherwise the red tests below
      # prove nothing (they would red for the wrong reason).
      assert {:ok, _} = V1.check_envelope(%Credentials{grant: grant, proof: proof}, expected)

      %{grant: grant, proof: proof, expected: expected}
    end

    @tag :conformance
    test "the un-tampered envelope is green (the non-vacuity baseline)", %{
      grant: grant,
      proof: proof,
      expected: expected
    } do
      assert {:ok, _} = V1.check_envelope(%Credentials{grant: grant, proof: proof}, expected)
    end

    @tag :conformance
    test "a flipped proof-signature byte goes RED", %{
      grant: grant,
      proof: proof,
      expected: expected
    } do
      tampered = flip_signature_byte(proof)

      assert {:error, :invalid} =
               V1.check_envelope(%Credentials{grant: grant, proof: tampered}, expected)
    end

    @tag :conformance
    test "a flipped proof-payload byte goes RED", %{
      grant: grant,
      proof: proof,
      expected: expected
    } do
      tampered = flip_payload_byte(proof)

      assert {:error, :invalid} =
               V1.check_envelope(%Credentials{grant: grant, proof: tampered}, expected)
    end

    @tag :conformance
    test "the published vector's tamper_verdicts are all invalid (the oracle agrees)" do
      tamper_verdicts = VectorCase.vector()["expected"]["tamper_verdicts"]

      for {tamper_class, verdict} <- tamper_verdicts do
        assert verdict == "invalid",
               "published tamper_verdict #{tamper_class} is #{verdict}, expected invalid"
      end
    end
  end

  # --- defect-injection helpers ---

  defp flip_signature_byte(compact) do
    # compact = protected.payload.signature. Flip the LAST byte of the signature
    # segment (byte 63 of the 64-byte Ed25519 signature — the high byte of the
    # second half, S). A single-bit change invalidates the signature; the red
    # comes from verify_signature/3 in verify_proof_parsed (the signature no
    # longer verifies against the holder public key), proving signature binding.
    [protected, payload, signature_b64] = String.split(compact, ".")
    signature = Base.url_decode64!(signature_b64, padding: false)
    {pre, <<last>> = _rest} = split_last(signature)
    flipped = <<pre::binary, Bitwise.bxor(last, 0x01)>>

    protected <> "." <> payload <> "." <> Base.url_encode64(flipped, padding: false)
  end

  defp flip_payload_byte(compact) do
    # compact = protected.payload.signature. Flip an INTERIOR byte of the payload
    # that lands inside a string VALUE (not a structural byte: " : , { } ), so
    # the re-encoded payload is still valid JSON with a CHANGED value. This
    # forces check_envelope's red to come from verify_proof_parsed's field-binding
    # checks (secure_equal? of the tampered field — e.g. the request_hash at
    # runtime.ex:491 — which run BEFORE verify_signature), NOT from parse_proof's
    # JSON decode (cross-vendor CV-payload finding: a flip of the closing brace
    # `}` reds at parse, which a verifier that omitted the payload from signature
    # coverage would still pass — proving malformed-body rejection, not that the
    # tampered field is bound to the verified payload). The functional point
    # stands: the red is a BODY-BINDING check inside verify_proof_parsed, not a
    # parse reject.
    [protected, payload_b64, signature_b64] = String.split(compact, ".")
    payload = Base.url_decode64!(payload_b64, padding: false)
    flipped = flip_interior_value_byte(payload)

    protected <>
      "." <>
      Base.url_encode64(flipped, padding: false) <>
      "." <> signature_b64
  end

  # Flip an interior byte that is NOT a JSON structural character
  # (`"`, `:`, `,`, `{`, `}`, `[`, `]`, whitespace) AND whose single-bit flip
  # also yields a non-structural byte (so the flipped payload stays valid JSON
  # with a CHANGED value). Starts at the middle of the payload (reliably inside
  # a string value for these JCS-sorted payloads) and walks forward to the first
  # qualifying byte. Operates on the byte list directly to avoid the compiler's
  # "accessed inside size()" warning on a size derived from the bound binary.
  @structural_bytes MapSet.new([
                      ?",
                      ?:,
                      ?,,
                      ?{,
                      ?},
                      ?[,
                      ?],
                      ?\s,
                      ?\t,
                      ?\n,
                      ?\r
                    ])

  defp flip_interior_value_byte(payload) do
    bytes = :binary.bin_to_list(payload)
    start = div(length(bytes), 2)

    target_idx =
      bytes
      |> Enum.drop(start)
      |> Enum.with_index(start)
      |> Enum.find_value(fn {byte, idx} ->
        flipped = Bitwise.bxor(byte, 0x01)

        if not MapSet.member?(@structural_bytes, byte) and
             not MapSet.member?(@structural_bytes, flipped),
           do: idx
      end) || raise "no interior non-structural byte found in payload"

    {pre_bytes, [target | rest_bytes]} = Enum.split(bytes, target_idx)
    IO.iodata_to_binary(pre_bytes ++ [Bitwise.bxor(target, 0x01)] ++ rest_bytes)
  end

  # Splits a binary into {all-but-last-byte, last-byte} via a list (avoids the
  # compiler's "accessed inside size() but defined outside of the match"
  # warning that fires when a variable is used in a size expression derived
  # from that same variable).
  defp split_last(<<last>>) when is_integer(last), do: {<<>>, <<last>>}

  defp split_last(binary) do
    bytes = :binary.bin_to_list(binary)
    {pre_bytes, [last]} = Enum.split(bytes, -1)
    {IO.iodata_to_binary(pre_bytes), <<last>>}
  end
end
