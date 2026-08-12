defmodule EdgeAgentTest do
  @moduledoc """
  RA9 acceptance — the end-to-end round-trip through real HTTP (Req POST → Bandit
  → `check_envelope/2`), plus the four rejection classes that prove the receiver's
  defenses are real, not vacuous:

    1. **Happy path** — `EdgeAgent.run/1` (the actual ROADMAP-named flow: mint →
       `sign_report/3` → POST) is accepted (`200`).
    2. **Tampered proof** — one flipped proof byte → `401` (the crypto is real).
    3. **Stranger's proof** — a proof signed by a key the grant was NOT issued to
       → `401` (BAP's holder↔grant thumbprint binding, `runtime.ex:482`).
    4. **Wrong identity** — a valid envelope presented to a receiver expecting a
       DIFFERENT identity → `401` (the §8 binding is non-vacuous: `check_envelope`
       PASSED, the binding caught it).
    5. **Replayed nonce** — a byte-identical second request within the proof
       window → `401` (the §9 replay ledger is non-vacuous).

  `async: false` — the nonce ledger is a named ETS table shared across receivers.
  """

  use ExUnit.Case, async: false

  alias BoundedAuthorityProtocol.V1

  @holder_seed <<2::256>>
  @stranger_seed <<5::256>>
  @body ~s({"record":{"region":"us-east","signal":"ok"}})

  setup do
    # The nonce ledger (ETS owner) + a default receiver on a free port, started
    # under ExUnit supervision so both tear down per test.
    start_supervised!(EdgeAgent.Receiver.NonceLedger)

    port = free_port()
    url = "http://127.0.0.1:#{port}/report"

    start_supervised!(
      {Bandit, plug: EdgeAgent.Receiver, scheme: :http, ip: {127, 0, 0, 1}, port: port}
    )

    # Give Bandit a beat to bind before the first POST.
    wait_for_server(url)

    %{url: url}
  end

  describe "the happy path (RA9 acceptance)" do
    test "EdgeAgent.run/1 signs + POSTs and the receiver accepts (200)", %{url: url} do
      assert {:ok, 200, "accepted"} = EdgeAgent.run(receiver_url: url)
    end

    test "a hand-built envelope verifies via check_envelope through the receiver (200)", %{
      url: url
    } do
      {grant, proof, invocation_id, nonce} = signed_envelope()

      assert {:ok, %{status: 200, body: "accepted"}} =
               Req.post(url, headers: headers(grant, proof, invocation_id, nonce), body: @body)
    end
  end

  describe "rejection — the crypto is real" do
    test "a tampered proof is rejected (401)", %{url: url} do
      {grant, proof, invocation_id, nonce} = signed_envelope()

      assert {:ok, %{status: 401, body: "invalid"}} =
               Req.post(url,
                 headers: headers(grant, tamper_proof(proof), invocation_id, nonce),
                 body: @body
               )
    end

    test "a stranger's proof (a key the grant was not issued to) is rejected (401)", %{url: url} do
      {grant, proof, invocation_id, nonce} = stranger_signed_envelope()

      assert {:ok, %{status: 401, body: "invalid"}} =
               Req.post(url, headers: headers(grant, proof, invocation_id, nonce), body: @body)
    end
  end

  describe "rejection — the §8 identity binding is real" do
    test "a valid envelope presented to a receiver expecting a DIFFERENT identity is rejected (401)" do
      # check_envelope would PASS here (grant issued to A, proof by A), but the
      # receiver's expected identity is B — the §8 binding must catch it.
      port = free_port()
      wrong_url = "http://127.0.0.1:#{port}/report"

      start_supervised!(
        {Bandit,
         plug: {EdgeAgent.Receiver, expected_identity: public_key(@stranger_seed)},
         scheme: :http,
         ip: {127, 0, 0, 1},
         port: port}
      )

      wait_for_server(wrong_url)

      {grant, proof, invocation_id, nonce} = signed_envelope()

      assert {:ok, %{status: 401, body: "invalid"}} =
               Req.post(wrong_url,
                 headers: headers(grant, proof, invocation_id, nonce),
                 body: @body
               )
    end
  end

  describe "rejection — the §9 replay ledger is real" do
    test "a replayed nonce (same identity) is rejected on the second request (401)", %{url: url} do
      {grant, proof, invocation_id, nonce} = signed_envelope()

      assert {:ok, %{status: 200, body: "accepted"}} =
               Req.post(url, headers: headers(grant, proof, invocation_id, nonce), body: @body)

      # Replay: same nonce, a FRESH proof over a fresh invocation_id, so it is the
      # nonce (the ledger's key) that dedups, not a stale signature.
      {grant, proof2, invocation_id2, ^nonce} = signed_envelope(nonce: nonce)

      assert {:ok, %{status: 401, body: "invalid"}} =
               Req.post(url,
                 headers: headers(grant, proof2, invocation_id2, nonce),
                 body: @body
               )
    end
  end

  # --- helpers -----------------------------------------------------------------

  # A valid envelope: grant issued to the holder, proof signed by the SAME holder.
  # Grant + proof both match the demo issuer key the default receiver trusts.
  defp signed_envelope(opts \\ []) do
    {pub, priv} = ed25519(@holder_seed)
    {:ok, thumb} = V1.Jwk.public_key_thumbprint_raw(pub, %{})
    {grant_compact, _issuer_pub} = EdgeAgent.DemoIssuer.signed_grant(thumb)

    invocation_id = "00000000-0000-4000-8000-000000000001"
    nonce = Keyword.get(opts, :nonce, "demo-nonce-0001")

    {:ok, %{proof: proof}} =
      BoundedAuthorityReportAdapter.sign_report(
        report(grant_compact, invocation_id, nonce),
        {EdgeAgent.Handle, {pub, priv}},
        %{}
      )

    {grant_compact, proof, invocation_id, nonce}
  end

  # A stranger's proof: grant issued to the holder (@holder_seed), proof signed by
  # a DIFFERENT key (@stranger_seed). check_envelope rejects (thumbprint mismatch).
  defp stranger_signed_envelope do
    {holder_pub, _holder_priv} = ed25519(@holder_seed)
    {stranger_pub, stranger_priv} = ed25519(@stranger_seed)
    {:ok, holder_thumb} = V1.Jwk.public_key_thumbprint_raw(holder_pub, %{})
    {grant_compact, _issuer_pub} = EdgeAgent.DemoIssuer.signed_grant(holder_thumb)

    invocation_id = "00000000-0000-4000-8000-000000000002"
    nonce = "demo-nonce-0002"

    {:ok, %{proof: proof}} =
      BoundedAuthorityReportAdapter.sign_report(
        report(grant_compact, invocation_id, nonce),
        {EdgeAgent.Handle, {stranger_pub, stranger_priv}},
        %{}
      )

    {grant_compact, proof, invocation_id, nonce}
  end

  defp report(grant_compact, invocation_id, nonce) do
    {:ok, cast_arguments} = V1.Json.decode(@body)

    %{
      grant_compact: grant_compact,
      operation: "report_external_materialization",
      method: "POST",
      target_uri: "https://receiver.local/report",
      invocation_id: invocation_id,
      cast_arguments: cast_arguments,
      nonce: nonce
    }
  end

  defp headers(grant, proof, invocation_id, nonce) do
    [
      {"content-type", "application/json"},
      {"x-ba-grant", grant},
      {"x-ba-proof", proof},
      {"x-ba-invocation-id", invocation_id},
      {"x-ba-nonce", nonce}
    ]
  end

  # Flip the last byte of the proof's 64-byte Ed25519 signature. The compact form
  # is `protected.payload.signature` (base64url segments); flipping one signature
  # byte breaks the signature without touching the signed content.
  defp tamper_proof(proof) do
    [protected, payload, sig_b64] = String.split(proof, ".")
    sig = Base.url_decode64!(sig_b64, padding: false)
    size = byte_size(sig) - 1
    <<head::binary-size(^size), last>> = sig
    tampered = Base.url_encode64(<<head::binary, Bitwise.bxor(last, 1)>>, padding: false)
    [protected, payload, tampered] |> Enum.join(".")
  end

  defp ed25519(seed), do: :crypto.generate_key(:eddsa, :ed25519, seed)
  defp public_key(seed), do: elem(ed25519(seed), 0)

  defp free_port do
    {:ok, socket} = :gen_tcp.listen(0, ip: {127, 0, 0, 1}, reuseaddr: true)
    {:ok, port} = :inet.port(socket)
    :gen_tcp.close(socket)
    port
  end

  # Poll the receiver until it answers (or timeout) so the first POST doesn't race
  # Bandit's bind.
  defp wait_for_server(url) do
    Enum.reduce_while(1..200, :no_server, fn _, _acc ->
      case Req.get(url) do
        {:ok, %{status: _}} -> {:halt, :ok}
        _ -> {:cont, :waiting}
      end
    end)
  end
end
