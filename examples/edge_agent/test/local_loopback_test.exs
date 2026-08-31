defmodule EdgeAgent.LocalLoopbackTest do
  @moduledoc """
  The local-loopback external-consumer smoke — the byte-distinct
  `ba+loopback-proof` flow end-to-end over REAL sockets on BOTH literal
  loopback families:

    1. **IPv4 happy path** — a Bandit listener bound to `{127, 0, 0, 1}`;
       `EdgeAgent.run_local_loopback/1` reserves the listener's challenge,
       signs via `sign_local_loopback_report/3`, and POSTs through Req; the
       receiver verifies via the profile's `check_envelope` against the target
       DERIVED from its own bound listener → `200`.
    2. **IPv6 happy path** — the same flow against a listener bound to
       `{0, 0, 0, 0, 0, 0, 0, 1}` (canonical `http://[::1]:PORT/report`) →
       `200`.
    3. **Cross-profile rejection** — a STANDARD `dpop+jwt` proof presenting a
       properly reserved challenge is still rejected by the loopback receiver
       (`401`, the typ gate); a loopback proof is rejected by the STANDARD
       receiver; `run_local_loopback/1` against a `localhost` URL fails closed
       at signing.
    4. **The reserved-challenge defenses** — a proof signed under challenge A
       presented with reserved challenge B → `401` (the {:required, nonce}
       binding); an unreserved (never minted) nonce → `401`; a replayed
       envelope → `401` (the challenge is single-use: consumed by the first
       arrival, so a captured request cannot be replayed even once).
    5. **Boot binding** — the loopback receiver REFUSES to start on a
       non-loopback interface, and refuses a hand-configured `target_uri`
       (the target is derived from the listener, never configured).

  `async: false` — the nonce ledger is a named ETS table shared across receivers.
  """

  use ExUnit.Case, async: false

  alias BoundedAuthorityProtocol.V1

  @holder_seed <<2::256>>
  @body ~s({"record":{"region":"us-east","signal":"ok"}})

  # Binds a free port on `ip`, starts the profile receiver there (the plug
  # DERIVES its target from the listener state it is given), and returns the
  # canonical target — the listener's own URL.
  defp start_loopback_receiver(ip) do
    start_supervised!(EdgeAgent.Receiver.NonceLedger)

    port = free_port(ip)
    target = "http://#{host(ip)}:#{port}/report"

    start_supervised!(
      {Bandit,
       plug: {EdgeAgent.Receiver, profile: :local_loopback, ip: ip, port: port},
       scheme: :http,
       ip: ip,
       port: port}
    )

    wait_for_server(target)
    target
  end

  defp host({127, 0, 0, 1}), do: "127.0.0.1"
  defp host({0, 0, 0, 0, 0, 0, 0, 1}), do: "[::1]"

  # Reserves a challenge from the listener (the GET the receiver mints on).
  defp reserved_challenge(target) do
    assert {:ok, %{status: 200, body: challenge}} = Req.get(target)
    assert is_binary(challenge) and challenge != ""
    challenge
  end

  describe "the happy paths — real IPv4 and IPv6 loopback listeners" do
    test "IPv4: run_local_loopback/1 reserves, signs + POSTs and the profile receiver accepts (200)" do
      target = start_loopback_receiver({127, 0, 0, 1})

      assert {:ok, 200, "accepted"} = EdgeAgent.run_local_loopback(receiver_url: target)
    end

    test "IPv6: run_local_loopback/1 against a [::1] listener accepts (200)" do
      target = start_loopback_receiver({0, 0, 0, 0, 0, 0, 0, 1})

      assert {:ok, 200, "accepted"} = EdgeAgent.run_local_loopback(receiver_url: target)
    end
  end

  describe "cross-profile rejection — the profiles never mix on the wire" do
    test "a STANDARD proof presenting a properly reserved challenge is still rejected (401)" do
      # The challenge gate passes (it was minted by this listener), so the red
      # is the PROFILE's: standard bytes carry typ dpop+jwt and red at the
      # profile verifier's typ gate.
      target = start_loopback_receiver({127, 0, 0, 1})

      {grant, proof, invocation_id, _standard_nonce} = standard_signed_envelope()

      assert {:ok, %{status: 401, body: "invalid"}} =
               Req.post(target,
                 headers:
                   envelope_headers(grant, proof, invocation_id, reserved_challenge(target)),
                 body: @body
               )
    end

    test "a loopback proof is rejected by the STANDARD receiver (401)" do
      start_supervised!(EdgeAgent.Receiver.NonceLedger)

      port = free_port({127, 0, 0, 1})
      url = "http://127.0.0.1:#{port}/report"

      start_supervised!(
        {Bandit, plug: EdgeAgent.Receiver, scheme: :http, ip: {127, 0, 0, 1}, port: port}
      )

      wait_for_server(url)

      # The STANDARD receiver mints no challenges (its flow is client-nonce +
      # ledger) — sign the loopback proof with a plain nonce value; the red we
      # assert is the STANDARD verifier rejecting ba+loopback-proof bytes.
      {grant, proof, invocation_id, nonce} = loopback_signed_envelope(url, "plain-nonce-here")

      assert {:ok, %{status: 401, body: "invalid"}} =
               Req.post(url,
                 headers: envelope_headers(grant, proof, invocation_id, nonce),
                 body: @body
               )
    end

    test "run_local_loopback/1 against a reachable localhost URL fails closed at signing" do
      # localhost resolves and CONNECTS (a live listener is up on the port), so
      # the challenge reservation succeeds — and BAP's profile admission still
      # rejects the spelling at SIGNING: localhost is not a canonical literal
      # loopback target, and no proof is ever produced.
      port = free_port({127, 0, 0, 1})
      live = "http://127.0.0.1:#{port}/report"

      start_supervised!(EdgeAgent.Receiver.NonceLedger)

      start_supervised!(
        {Bandit,
         plug: {EdgeAgent.Receiver, profile: :local_loopback, ip: {127, 0, 0, 1}, port: port},
         scheme: :http,
         ip: {127, 0, 0, 1},
         port: port}
      )

      wait_for_server(live)

      assert {:error, {:producer_error, :invalid}} =
               EdgeAgent.run_local_loopback(receiver_url: "http://localhost:#{port}/report")
    end
  end

  describe "the reserved-challenge defenses" do
    test "a proof signed under challenge A presented with reserved challenge B is rejected (401)" do
      target = start_loopback_receiver({127, 0, 0, 1})

      # TWO genuine, distinct reserved challenges. The proof binds A; the POST
      # presents B. The challenge gate passes (B is minted + unconsumed) — the
      # red is the profile verifier's {:required, nonce} binding.
      {grant, proof, invocation_id, _challenge_a} = loopback_signed_envelope(target)
      challenge_b = reserved_challenge(target)

      assert {:ok, %{status: 401, body: "invalid"}} =
               Req.post(target,
                 headers: envelope_headers(grant, proof, invocation_id, challenge_b),
                 body: @body
               )
    end

    test "a never-minted nonce is rejected (401)" do
      target = start_loopback_receiver({127, 0, 0, 1})

      {grant, proof, invocation_id, _challenge} = loopback_signed_envelope(target)

      assert {:ok, %{status: 401, body: "invalid"}} =
               Req.post(target,
                 headers: envelope_headers(grant, proof, invocation_id, "never-minted-nonce"),
                 body: @body
               )
    end

    test "a replayed loopback envelope is rejected on the second request (401)" do
      target = start_loopback_receiver({127, 0, 0, 1})

      {grant, proof, invocation_id, challenge} = loopback_signed_envelope(target)

      assert {:ok, %{status: 200, body: "accepted"}} =
               Req.post(target,
                 headers: envelope_headers(grant, proof, invocation_id, challenge),
                 body: @body
               )

      # Byte-identical replay: the challenge was CONSUMED by the first arrival
      # (single-use), so the replay reds at the challenge gate itself — the
      # first-use replay window a client-chosen nonce leaves open is closed.
      assert {:ok, %{status: 401, body: "invalid"}} =
               Req.post(target,
                 headers: envelope_headers(grant, proof, invocation_id, challenge),
                 body: @body
               )
    end
  end

  describe "boot binding — the profile receiver is bound to the literal listener" do
    test "init refuses a non-loopback interface (fail loud at boot)" do
      assert_raise ArgumentError, ~r/literal loopback interface/, fn ->
        EdgeAgent.Receiver.init(profile: :local_loopback, ip: {0, 0, 0, 0}, port: 4000)
      end
    end

    test "init refuses a hand-configured target_uri (the target is listener-derived)" do
      assert_raise ArgumentError, ~r/derives target_uri/, fn ->
        EdgeAgent.Receiver.init(
          profile: :local_loopback,
          ip: {127, 0, 0, 1},
          port: 4000,
          target_uri: "http://127.0.0.1:4000/report"
        )
      end
    end

    test "init derives the canonical target from the listener state" do
      config =
        EdgeAgent.Receiver.init(
          profile: :local_loopback,
          ip: {0, 0, 0, 0, 0, 0, 0, 1},
          port: 4321
        )

      assert config.target_uri == "http://[::1]:4321/report"
    end
  end

  # A loopback envelope: reserves the LISTENER's challenge, then signs against
  # `target` (the canonical listener URI) binding that challenge. An explicit
  # `nonce` overrides the reservation (used where no loopback listener exists).
  defp loopback_signed_envelope(target, nonce \\ nil) do
    {pub, priv} = ed25519(@holder_seed)
    {:ok, thumb} = V1.Jwk.public_key_thumbprint_raw(pub, %{})
    {grant_compact, _issuer_pub} = EdgeAgent.DemoIssuer.signed_grant(thumb)
    {:ok, cast_arguments} = V1.Json.decode(@body)

    challenge = nonce || reserved_challenge(target)
    invocation_id = "00000000-0000-4000-8000-0000000000a1"

    report = %{
      grant_compact: grant_compact,
      operation: "report_external_materialization",
      method: "POST",
      target_uri: target,
      invocation_id: invocation_id,
      cast_arguments: cast_arguments,
      nonce: challenge
    }

    {:ok, %{proof: proof}} =
      BoundedAuthorityReportAdapter.sign_local_loopback_report(
        report,
        {EdgeAgent.Handle, {pub, priv}},
        %{}
      )

    {grant_compact, proof, invocation_id, challenge}
  end

  # A STANDARD envelope (valid dpop+jwt bytes over the configured https target).
  defp standard_signed_envelope do
    {pub, priv} = ed25519(@holder_seed)
    {:ok, thumb} = V1.Jwk.public_key_thumbprint_raw(pub, %{})
    {grant_compact, _issuer_pub} = EdgeAgent.DemoIssuer.signed_grant(thumb)
    {:ok, cast_arguments} = V1.Json.decode(@body)

    invocation_id = "00000000-0000-4000-8000-0000000000b2"
    nonce = "demo-standard-nonce-0002"

    report = %{
      grant_compact: grant_compact,
      operation: "report_external_materialization",
      method: "POST",
      target_uri: "https://receiver.local/report",
      invocation_id: invocation_id,
      cast_arguments: cast_arguments,
      nonce: nonce
    }

    {:ok, %{proof: proof}} =
      BoundedAuthorityReportAdapter.sign_report(report, {EdgeAgent.Handle, {pub, priv}}, %{})

    {grant_compact, proof, invocation_id, nonce}
  end

  defp envelope_headers(grant, proof, invocation_id, nonce) do
    [
      {"content-type", "application/json"},
      {"x-ba-grant", grant},
      {"x-ba-proof", proof},
      {"x-ba-invocation-id", invocation_id},
      {"x-ba-nonce", nonce}
    ]
  end

  defp ed25519(seed), do: :crypto.generate_key(:eddsa, :ed25519, seed)

  defp free_port(ip) do
    {:ok, socket} = :gen_tcp.listen(0, ip: ip, reuseaddr: true)
    {:ok, port} = :inet.port(socket)
    :gen_tcp.close(socket)
    port
  end

  defp wait_for_server(url) do
    Enum.reduce_while(1..200, :no_server, fn _, _acc ->
      case Req.get(url) do
        {:ok, %{status: _}} -> {:halt, :ok}
        _ -> {:cont, :waiting}
      end
    end)
  end
end
