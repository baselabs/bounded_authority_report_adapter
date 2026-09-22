defmodule BoundedAuthorityReportAdapter.V1ByteIdentityTest do
  @moduledoc """
  Byte-level regression oracle for the major-1 surface across the v3 tail
  changes (ADR-0021, adversarial finding 13).

  The signing machinery gains a suite-parameterized sibling in
  `BoundedAuthorityReportAdapter.V3`; verdict-level green (the RA2 vector, the
  round-trips) cannot see a byte-level regression hiding behind a still-valid
  signature. These fixtures were captured from the pre-v3 code (2026-09-22,
  deterministic by construction: a fixed seeded keypair, fixed ids and
  timestamps — Ed25519 is deterministic, so each compact is fully determined)
  and must stay byte-identical. Each fixture ALSO verifies green through the
  dependency, so the pinned bytes are valid credentials, not merely
  yesterday's output.
  """

  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.V1
  alias BoundedAuthorityProtocol.V1.{Credentials, ExpectedAnchor, ExpectedGrant,
                                     ExpectedKeyTransition, ExpectedRequest,
                                     HistoricalPublicKey, TrustedIssuer}
  alias BoundedAuthorityReportAdapter.Keys.RawKey

  # The fixed seeded fixture keypair (seed <<7::256>>) and the fixed successor
  # keypair (seed <<8::256>>) — derived, not embedded, so the test pins the
  # DERIVATION and the compacts, not opaque key literals.
  @holder_pub :crypto.generate_key(:eddsa, :ed25519, <<7::256>>) |> elem(0)
  @holder_priv :crypto.generate_key(:eddsa, :ed25519, <<7::256>>) |> elem(1)
  @next_pub :crypto.generate_key(:eddsa, :ed25519, <<8::256>>) |> elem(0)

  # Captured 2026-09-22 against the pin-bump commit 8910b26 (the v1 signing
  # path there is byte-identical to 0.6.3's). Do NOT regenerate to "fix" a red
  # here — a red means the major-1 surface changed bytes.
  @proof_compact "eyJhbGciOiJFZERTQSIsImp3ayI6eyJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6IlB1S29weWc4c3YxeWlVUGFvU2Z2Q2VTREJ4cUxTOGFadWtVaThKc1V6OTQifSwidHlwIjoiZHBvcCtqd3QifQ.eyJhdGgiOiJoem4tODk4ZDlqX1d6azB5TW9lVjBmWElfU0NJcmxfTlItcVF0NmJBZG9vIiwiYmFfaW52IjoiMTIzZTQ1NjctZTg5Yi00MmQzLWE0NTYtNDI2NjE0MTc0MDAwIiwiYmFfb3AiOiJyZXBvcnRfZXh0ZXJuYWxfbWF0ZXJpYWxpemF0aW9uIiwiYmFfcmVxIjoiT19uTlBSVXNPYzRRUmhRRFg2bmRQQWpFYkh5SmpWRHlyRk9jUzNYaHdvdyIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwczovL2FwaS5leGFtcGxlLnRlc3QvaW52b2tlIiwiaWF0IjoxNTAwLCJqdGkiOiJieXRlLWlkZW50aXR5LXYxLXByb29mLTAwMSIsInYiOjF9.UfI4cxtWEi7zKY2XS1rHt0QxrO0CymS2PSjRzP92f8PojEIP_zQeh5JLkvEsJhHZQ5Jd-n77YdPPSWlAFYLYCg"
  @grant_compact "eyJhbGciOiJFZERTQSIsImtpZCI6Imlzc3Vlci0yMDI2LTA3IiwidHlwIjoiYmErY2FwIn0.eyJhdWQiOlsiaHR0cHM6Ly92ZXJpZmllci5leGFtcGxlLnRlc3QiXSwiY25mIjp7ImprdCI6IkFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBS3MifSwiZXhwIjoyMDAwLCJpYXQiOjEwMDAsImlzcyI6Imh0dHBzOi8vaXNzdWVyLmV4YW1wbGUudGVzdCIsImp0aSI6InVybjpleGFtcGxlOmdyYW50OmJ5dGUtaWRlbnRpdHktdjEiLCJuYmYiOjEwMDAsIm9wZXJhdGlvbnMiOlt7Im5hbWUiOiJyZXBvcnRfZXh0ZXJuYWxfbWF0ZXJpYWxpemF0aW9uIiwic2VsZWN0b3JzIjpbeyJraW5kIjoiYWxsIn1dfV0sInYiOjF9.xHaOAyLoTp4oVNSl8X8cQfATDbzsQc6WD7w5WyuzJwUdUlOzxKt12VFl2AOamc4h4mbGh5TFsLX-pIy71rHrDg"
  @anchor_compact "eyJhbGciOiJFZERTQSIsImtpZCI6InRlc3QtYW5jaG9yLWtleS0wMDEiLCJ0eXAiOiJiYStjaGFpbi1hbmNob3IifQ.eyJhbmNob3JfaWQiOiJ1cm46ZXhhbXBsZTphbmNob3I6Ynl0ZS1pZGVudGl0eS12MSIsImFuY2hvcmVkX2F0IjoxNTAwLCJjaGFpbl9oYXNoIjoiQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFNMCIsImNoYWluX2lkIjoidXJuOmV4YW1wbGU6Y2hhaW46Ynl0ZS1pZGVudGl0eS12MSIsImtleV9maW5nZXJwcmludCI6InRzMWVUSV9vWllYZWNxWEJVTGJpenJVbTlfdnRMMzJXalJoMi1sSGVPWjgiLCJzZXF1ZW5jZSI6NywidiI6MX0.UsekgP8KGQ7EUmtyMbbq5r0QIWHZuSimFMAGAX6hq9rqPHVdONF3sfKUFp40IkykZsZFj9i0Yr05yHQy9aclCw"
  @transition_compact "eyJhbGciOiJFZERTQSIsImtpZCI6InRlc3QtYW5jaG9yLWtleS0wMDEiLCJ0eXAiOiJiYStrZXktdHJhbnNpdGlvbiJ9.eyJjaGFpbl9pZCI6InVybjpleGFtcGxlOmNoYWluOmJ5dGUtaWRlbnRpdHktdjEiLCJlZmZlY3RpdmVfYXQiOjIwMDAsImZyb21fa2V5X2ZpbmdlcnByaW50IjoidHMxZVRJX29aWVhlY3FYQlVMYml6clVtOV92dEwzMldqUmgyLWxIZU9aOCIsInRvX2tleV9maW5nZXJwcmludCI6ImVYVmlTUEJhc2htQUdWVlliSGZpZDh2cTZjM3h1TUZqd2Z3VXFVZTJsaDQiLCJ0b19rZXlfaWQiOiJuZXh0LWtleS1ieXRlLWlkZW50aXR5IiwidHJhbnNpdGlvbl9pZCI6InVybjpleGFtcGxlOnRyYW5zaXRpb246Ynl0ZS1pZGVudGl0eS12MSIsInYiOjF9.4g8narVblSjCapNNf2EiO576MHaQUJmtfQgVOMbWGVFFnazfW5SMdeUqb7ndYgSOrfHyrAdoB2liZ7mkMdpFDw"

  # The issuer-signed grant the proof fixture binds (TestKeys' deterministic
  # seeded issuer keypair; its bytes are part of the proof's ath binding, so
  # they are pinned too).
  @issuer_grant "eyJhbGciOiJFZERTQSIsImtpZCI6Imlzc3Vlci0yMDI2LTA3IiwidHlwIjoiYmErY2FwIn0.eyJhdWQiOlsiaHR0cHM6Ly92ZXJpZmllci5leGFtcGxlLnRlc3QiXSwiY25mIjp7ImprdCI6InRzMWVUSV9vWllYZWNxWEJVTGJpenJVbTlfdnRMMzJXalJoMi1sSGVPWjgifSwiZXhwIjoyMDAwLCJpYXQiOjEwMDAsImlzcyI6Imh0dHBzOi8vaXNzdWVyLmV4YW1wbGUudGVzdCIsImp0aSI6InVybjpleGFtcGxlOmdyYW50OnJhMS10ZXN0IiwibmJmIjoxMDAwLCJvcGVyYXRpb25zIjpbeyJuYW1lIjoicmVwb3J0X2V4dGVybmFsX21hdGVyaWFsaXphdGlvbiIsInNlbGVjdG9ycyI6W3sia2luZCI6ImFsbCJ9XX1dLCJ2IjoxfQ.FcoR2mE2mxRKiguM-TIY_UllivdfrVER-JdNJnt8jNw8xLLWX2yCtZmPikDRTgck7Mc9xBuk0pak-LsOMy11AA"

  @cast_arguments {:object, [{"record", {:object, [{"region", {:string, "us-east"}}]}}]}

  defp handle do
    {RawKey, {@holder_pub, @holder_priv}}
  end

  defp thumb(public_key) do
    {:ok, digest} = V1.Jwk.public_key_thumbprint_raw(public_key, %{})
    digest
  end

  defp report do
    %{
      grant_compact: @issuer_grant,
      operation: "report_external_materialization",
      method: "POST",
      target_uri: "https://api.example.test/invoke",
      invocation_id: "123e4567-e89b-42d3-a456-426614174000",
      cast_arguments: @cast_arguments,
      nonce: nil
    }
  end

  @tag :byte_identity
  test "sign_report/3 reproduces the captured proof compact byte-exactly" do
    {:ok, %{proof: proof}} =
      BoundedAuthorityReportAdapter.sign_report(report(), handle(), %{
        issued_at: 1_500,
        proof_id: "byte-identity-v1-proof-001"
      })

    assert proof == @proof_compact
  end

  @tag :byte_identity
  test "sign_grant/3 reproduces the captured grant compact byte-exactly" do
    {:ok, %{grant: grant}} =
      BoundedAuthorityReportAdapter.sign_grant(grant_input(), {GrantIssuerHandle, handle_term()})

    assert grant == @grant_compact
  end

  @tag :byte_identity
  test "sign_anchor/3 reproduces the captured anchor compact byte-exactly" do
    {:ok, %{anchor: anchor}} =
      BoundedAuthorityReportAdapter.sign_anchor(anchor_input(), handle(), %{
        anchored_at: 1_500
      })

    assert anchor == @anchor_compact
  end

  @tag :byte_identity
  test "sign_key_transition/3 reproduces the captured transition compact byte-exactly" do
    {:ok, %{key_transition: transition}} =
      BoundedAuthorityReportAdapter.sign_key_transition(transition_input(), handle(), %{})

    assert transition == @transition_compact
  end

  @tag :byte_identity
  test "every pinned fixture is a VALID v1 credential through the dependency" do
    # The pins are not merely yesterday's bytes: each verifies green through
    # the pinned BAP release, so a fixture that stopped verifying reds here
    # even if a byte comparison above somehow passed.
    {issuer_pub, _} = BoundedAuthorityReportAdapter.TestKeys.issuer_keypair()

    assert {:ok, _} =
             V1.check_envelope(
               %Credentials{grant: @issuer_grant, proof: @proof_compact},
               %ExpectedRequest{
                 trusted_issuer: %TrustedIssuer{key_id: "issuer-2026-07", public_key: issuer_pub},
                 issuer: "https://issuer.example.test",
                 audience: "https://verifier.example.test",
                 method: "POST",
                 target_uri: "https://api.example.test/invoke",
                 invocation_id: "123e4567-e89b-42d3-a456-426614174000",
                 operation: "report_external_materialization",
                 cast_arguments: @cast_arguments,
                 evaluation_time: 1_550,
                 clock_skew: 60,
                 proof_max_age: 300,
                 nonce: :not_required,
                 bounds: V1.Bounds.maximum()
               }
             )

    assert {:ok, _} =
             V1.verify_grant(
               @grant_compact,
               %TrustedIssuer{key_id: "issuer-2026-07", public_key: @holder_pub},
               %ExpectedGrant{
                 issuer: "https://issuer.example.test",
                 audience: "https://verifier.example.test",
                 evaluation_time: 1_500,
                 clock_skew: 60,
                 bounds: V1.Bounds.maximum()
               }
             )

    assert {:ok, _} =
             V1.verify_historical_anchor(
               @anchor_compact,
               historical("test-anchor-key-001", @holder_pub, 1_500),
               %ExpectedAnchor{
                 anchor_id: "urn:example:anchor:byte-identity-v1",
                 anchored_at: 1_500,
                 chain_id: "urn:example:chain:byte-identity-v1",
                 sequence: 7,
                 chain_hash: <<0xCD::256>>,
                 key_id: "test-anchor-key-001",
                 key_fingerprint: thumb(@holder_pub),
                 bounds: V1.Bounds.maximum()
               }
             )

    assert {:ok, _} =
             V1.verify_key_transition(
               @transition_compact,
               historical("test-anchor-key-001", @holder_pub, 2_000),
               historical("next-key-byte-identity", @next_pub, 2_000),
               %ExpectedKeyTransition{
                 transition_id: "urn:example:transition:byte-identity-v1",
                 chain_id: "urn:example:chain:byte-identity-v1",
                 effective_at: 2_000,
                 current_key_id: "test-anchor-key-001",
                 current_key_fingerprint: thumb(@holder_pub),
                 next_key_id: "next-key-byte-identity",
                 next_key_fingerprint: thumb(@next_pub),
                 bounds: V1.Bounds.maximum()
               }
             )
  end

  defp handle_term, do: {@holder_pub, @holder_priv}

  defp historical(key_id, public_key, around) do
    %HistoricalPublicKey{
      key_id: key_id,
      public_key: public_key,
      valid_from: around - 100,
      valid_before: around + 100
    }
  end

  defp grant_input do
    %{
      issuer: "https://issuer.example.test",
      grant_id: "urn:example:grant:byte-identity-v1",
      audiences: ["https://verifier.example.test"],
      issued_at: 1_000,
      not_before: 1_000,
      expires_at: 2_000,
      holder_thumbprint: <<0xAB::256>>,
      operations: [
        %BoundedAuthorityProtocol.V1.Operation{
          name: "report_external_materialization",
          selectors: [:all]
        }
      ]
    }
  end

  defp anchor_input do
    %{
      anchor_id: "urn:example:anchor:byte-identity-v1",
      chain_id: "urn:example:chain:byte-identity-v1",
      sequence: 7,
      chain_hash: <<0xCD::256>>
    }
  end

  defp transition_input do
    %{
      transition_id: "urn:example:transition:byte-identity-v1",
      chain_id: "urn:example:chain:byte-identity-v1",
      effective_at: 2_000,
      next_key_id: "next-key-byte-identity",
      next_public_key: @next_pub
    }
  end
end
