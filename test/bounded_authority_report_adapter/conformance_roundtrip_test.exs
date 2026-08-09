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
    test "negative_cases.duplicate_member goes red (invalid)" do
      # The duplicate_member case compact is multiply-defective by construction
      # (its protected header carries a duplicated "alg" member, AND its payload
      # is `{"v":1}` missing every required proof member, AND its embedded
      # thumbprint differs from the grant's cnf.jkt). check_envelope returns an
      # opaque {:error, :invalid}, so the first assert proves the envelope REDS
      # but CANNOT attribute the red to the duplicate-member rejection
      # specifically — a verifier that tolerated duplicate members would still
      # red here on the other defects (cross-vendor finding: this is not an
      # isolation of duplicate-member rejection).
      #
      # The second assert (decoding the protected header through BAP's normative
      # Json.decode) is an INDEPENDENT property: it proves BAP's JSON decoder
      # rejects objects with duplicated member keys, applied to the case's
      # `{"alg":"EdDSA","alg":"HS256","typ":"ba+cap"}` header. This is a
      # decoder property, not an envelope-verifier attribution — the two
      # asserts together show (a) the published case reds and (b) BAP's decoder
      # rejects duplicate members, but not that (a) is caused by (b).
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

      # BAP's normative Json.decode rejects an object with a duplicated member
      # key — an independent decoder property, verified on the case's header.
      protected_segment = dm["protected_segment"]

      assert {:error, :invalid} =
               V1.Json.decode(
                 Base.url_decode64!(protected_segment, padding: false),
                 V1.Bounds.maximum()
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

    @tag :conformance
    test "every nonce-carrying published case's nonce VALUE equals expected_context.nonce (no silent drift)" do
      # The harness derives the nonce EXPECTATION's presence from the proof
      # payload (the only per-case signal the vector offers) but its VALUE from
      # expected_context.nonce["required"] (the authoritative oracle). This test
      # closes the residual a cross-vendor note named: a hypothetical future
      # nonce-carrying case whose proof nonce DRIFTED from expected_context would
      # otherwise compare the proof's nonce against the authoritative value and
      # red — but only if such a case were added. Asserting here that every
      # CURRENT nonce-carrying published case's proof nonce equals the
      # authoritative value makes the invariant explicit and pins it: a future
      # vector edit that drifts a carrying case's nonce reds this test, not just
      # the per-case verify.
      v = VectorCase.vector()
      authoritative = v["expected_context"]["nonce"]["required"]

      carrying =
        [v["proof"], v["received_member_order_variant"]["proof"]]
        |> Kernel.++(Enum.map(Map.values(v["negative_cases"]["selector_denied"]), & &1["proof"]))
        |> Kernel.++([v["negative_cases"]["wrong_holder"]["proof"]])

      for proof <- carrying do
        payload_nonce = proof["payload"]["nonce"]

        assert payload_nonce == authoritative,
               "a published nonce-carrying proof's nonce drifted from expected_context.nonce: #{inspect(payload_nonce)} != #{inspect(authoritative)}"
      end
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
      # Build the green envelope once (bar iii's mechanism). The holder private
      # key is kept so the payload-tamper test can RE-SIGN a tampered payload
      # (a byte-flip that keeps the original signature reds at verify_signature,
      # making it redundant with the signature-flip test; re-signing isolates
      # the field-binding property).
      {holder_pub, holder_priv} = TestKeys.holder_keypair()
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

      %{grant: grant, proof: proof, expected: expected, holder_priv: holder_priv}
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
    test "a tampered ba_req payload (RE-SIGNED so the signature stays valid) goes RED at the field binding",
         %{
           grant: grant,
           proof: proof,
           expected: expected,
           holder_priv: holder_priv
         } do
      # A payload byte-flip that keeps the original signature reds at
      # verify_signature (the signature covers protected.payload), making it
      # redundant with the signature-flip test. To exercise the ba_req
      # FIELD-BINDING check (runtime.ex:491) independently, this test tampers
      # the ba_req value AND RE-SIGNS the tampered payload with the holder key —
      # so the signature is valid over the tampered payload, verify_signature
      # passes, and the red MUST come from the request-hash field binding
      # (recomputed request hash != tampered ba_req). This is a genuinely
      # different property from the signature-flip test.
      tampered = tamper_and_resign_ba_req(proof, holder_priv)

      assert {:error, :invalid} =
               V1.check_envelope(%Credentials{grant: grant, proof: tampered}, expected)
    end

    @tag :conformance
    test "the published vector's tamper_verdicts all go RED through check_envelope (the oracle + the verifier agree)" do
      # The published expected.tamper_verdicts declares 7 tamper classes. The
      # prior version of this test only asserted the metadata strings equal
      # "invalid" — it constructed no tampered credential and never called
      # check_envelope, so it tested the JSON file's self-description, not BAP's
      # rejection (a cross-vendor blocking finding: vacuous for the verifier).
      # This version constructs each tampered credential and confirms
      # check_envelope reds on every one.
      v = VectorCase.vector()
      grant = v["grant"]["compact"]
      proof = v["proof"]["compact"]
      expected = VectorCase.expected_request(:top_level)

      # The 6 byte-flip tamper classes: flip a byte in the named segment of the
      # named compact. Each must red through check_envelope.
      flips = %{
        "grant_protected_byte_flip" => {:grant, 0},
        "grant_payload_byte_flip" => {:grant, 1},
        "grant_signature_byte_flip" => {:grant, 2},
        "proof_protected_byte_flip" => {:proof, 0},
        "proof_payload_byte_flip" => {:proof, 1},
        "proof_signature_byte_flip" => {:proof, 2}
      }

      for {tamper_class, verdict} <- v["expected"]["tamper_verdicts"] do
        assert verdict == "invalid",
               "published tamper_verdict #{tamper_class} is #{verdict}, expected invalid"

        case Map.fetch(flips, tamper_class) do
          {:ok, {which, segment}} ->
            tampered =
              case which do
                :grant -> %Credentials{grant: flip_segment_byte(grant, segment), proof: proof}
                :proof -> %Credentials{grant: grant, proof: flip_segment_byte(proof, segment)}
              end

            assert {:error, :invalid} = V1.check_envelope(tampered, expected),
                   "tamper #{tamper_class} did not go RED through check_envelope"

          :error when tamper_class == "request_operation_drift" ->
            drifted = %{expected | operation: "write_record"}

            assert {:error, :invalid} =
                     V1.check_envelope(%Credentials{grant: grant, proof: proof}, drifted),
                   "tamper request_operation_drift did not go RED through check_envelope"

          :error ->
            flunk("unhandled published tamper class: #{tamper_class}")
        end
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

  # Flip a byte in segment `segment_index` (0=protected, 1=payload, 2=signature)
  # of a compact JWS. Used by the published-tamper test to exercise every one of
  # the vector's 6 byte-flip tamper classes through check_envelope. Flips the
  # LAST byte of the decoded segment (a meaningful byte in every segment: a
  # header/payload content byte or the signature's high byte).
  defp flip_segment_byte(compact, segment_index) do
    segments = String.split(compact, ".")
    {seg_b64, rest} = List.pop_at(segments, segment_index)
    decoded = Base.url_decode64!(seg_b64, padding: false)
    {pre, <<last>> = _rest} = split_last(decoded)
    flipped = <<pre::binary, Bitwise.bxor(last, 0x01)>>

    List.insert_at(rest, segment_index, Base.url_encode64(flipped, padding: false))
    |> Enum.join(".")
  end

  # Tamper the ba_req value in the proof payload AND re-sign with the holder
  # private key, so the signature is valid over the tampered payload. A
  # byte-flip that keeps the original signature reds at verify_signature (the
  # signature covers protected.payload), making it redundant with the
  # signature-flip test. Re-signing isolates the ba_req FIELD-BINDING check
  # (runtime.ex:491: secure_equal?(proof.request_hash, request_hash)) — the
  # tampered ba_req no longer matches the recomputed request hash, so check_envelope
  # reds there, with verify_signature passing.
  defp tamper_and_resign_ba_req(compact, holder_priv) do
    [protected_seg, payload_seg, _old_sig] = String.split(compact, ".")
    payload_bytes = Base.url_decode64!(payload_seg, padding: false)
    {:ok, {:object, members}} = V1.Json.decode(payload_bytes, V1.Bounds.maximum())

    tampered_members =
      Enum.map(members, fn
        {"ba_req", _} ->
          # A different valid-shape 43-char base64url string (32-byte digest).
          {"ba_req", {:string, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}

        other ->
          other
      end)

    {:ok, tampered_canon} = V1.Jcs.encode({:object, tampered_members}, V1.Bounds.maximum())
    new_payload_seg = Base.url_encode64(tampered_canon, padding: false)
    new_message = protected_seg <> "." <> new_payload_seg
    new_sig = :crypto.sign(:eddsa, :ed25519, new_message, [holder_priv, :ed25519])
    new_message <> "." <> Base.url_encode64(new_sig, padding: false)
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
