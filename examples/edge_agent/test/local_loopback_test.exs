defmodule EdgeAgent.LocalLoopbackTest do
  @moduledoc """
  The local-loopback external-consumer smoke — the byte-distinct
  `ba+loopback-proof` flow end-to-end over REAL sockets on BOTH literal
  loopback families:

    1. **IPv4 happy path** — a Bandit listener bound to `{127, 0, 0, 1}`;
       `EdgeAgent.run_local_loopback/1` signs via
       `sign_local_loopback_report/3` and POSTs through Req; the receiver
       verifies via the profile's `check_envelope` with the target derived from
       its OWN bound listener → `200`.
    2. **IPv6 happy path** — the same flow against a listener bound to
       `{0, 0, 0, 0, 0, 0, 0, 1}` with the canonical `http://[::1]:PORT/report`
       target → `200`.
    3. **Cross-profile rejection** — a STANDARD `dpop+jwt` proof (valid over
       the configured https target) is rejected by the loopback receiver →
       `401`; a loopback proof is rejected by the STANDARD receiver → `401`;
       and `run_local_loopback/1` against a `localhost` URL fails closed at
       signing (no proof is even produced).
    4. **Wrong reserved nonce** — a loopback envelope presented with a
       different reserved nonce → `401`.
    5. **Replay** — a byte-identical second POST within the proof window →
       `401` (the nonce ledger; the profile's replay defense is mandatory on a
       no-TLS transport).

  The listener-derived target discipline: the receiver is started with the
  `target_uri` of its OWN bound address (the free port the test just bound),
  and the agent signs exactly that URL — never a Host header, never forwarding
  metadata.

  `async: false` — the nonce ledger is a named ETS table shared across receivers.
  """

  use ExUnit.Case, async: false

  alias BoundedAuthorityProtocol.V1

  @holder_seed <<2::256>>
  @body ~s({"record":{"region":"us-east","signal":"ok"}})

  # Binds a free port on `ip`, starts the profile receiver there, and returns
  # {live_url, listener_target} — the same canonical literal-loopback URI from
  # the LISTENER's own state.
  defp start_loopback_receiver(ip, opts \\ []) do
    start_supervised!(EdgeAgent.Receiver.NonceLedger)

    port = free_port(ip)
    target = "http://#{host(ip)}:#{port}/report"

    start_supervised!(
      {Bandit,
       plug: {EdgeAgent.Receiver, [profile: :local_loopback] ++ opts ++ [target_uri: target]},
       scheme: :http,
       ip: ip,
       port: port}
    )

    wait_for_server(target)
    {target, target}
  end

  defp host({127, 0, 0, 1}), do: "127.0.0.1"
  defp host({0, 0, 0, 0, 0, 0, 0, 1}), do: "[::1]"

  describe "the happy paths — real IPv4 and IPv6 loopback listeners" do
    test "IPv4: run_local_loopback/1 signs + POSTs and the profile receiver accepts (200)" do
      {url, target} = start_loopback_receiver({127, 0, 0, 1})
      _ = url

      assert {:ok, 200, "accepted"} = EdgeAgent.run_local_loopback(receiver_url: target)
    end

    test "IPv6: run_local_loopback/1 against a [::1] listener accepts (200)" do
      {_url, target} = start_loopback_receiver({0, 0, 0, 0, 0, 0, 0, 1})

      assert {:ok, 200, "accepted"} = EdgeAgent.run_local_loopback(receiver_url: target)
    end
  end

  describe "cross-profile rejection — the profiles never mix on the wire" do
    test "a STANDARD dpop+jwt proof is rejected by the loopback receiver (401)" do
      # Standard bytes carry typ dpop+jwt; the profile verifier reds them even
      # though the envelope is otherwise perfectly valid.
      {url, _target} = start_loopback_receiver({127, 0, 0, 1})

      {grant, proof, invocation_id, nonce} = standard_signed_envelope()

      assert {:ok, %{status: 401, body: "invalid"}} =
               Req.post(url,
                 headers: envelope_headers(grant, proof, invocation_id, nonce),
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

      {grant, proof, invocation_id, nonce} = loopback_signed_envelope(url)

      assert {:ok, %{status: 401, body: "invalid"}} =
               Req.post(url,
                 headers: envelope_headers(grant, proof, invocation_id, nonce),
                 body: @body
               )
    end

    test "run_local_loopback/1 against a localhost URL fails closed at signing" do
      # localhost is NOT a canonical literal-loopback spelling: BAP's profile
      # admission rejects it, and no proof is produced (nothing is POSTed).
      assert {:error, {:producer_error, :invalid}} =
               EdgeAgent.run_local_loopback(receiver_url: "http://localhost:4000/report")
    end
  end

  describe "the profile's own defenses — nonce and replay" do
    test "a wrong reserved nonce is rejected (401)" do
      {url, target} = start_loopback_receiver({127, 0, 0, 1})

      # Sign against the listener's target, but present a DIFFERENT reserved
      # nonce header: the profile verifier's {:required, nonce} binding reds.
      {grant, proof, invocation_id, _real_nonce} = loopback_signed_envelope(target)

      assert {:ok, %{status: 401, body: "invalid"}} =
               Req.post(url,
                 headers:
                   envelope_headers(grant, proof, invocation_id, "a-different-reserved-nonce"),
                 body: @body
               )
    end

    test "a replayed loopback envelope is rejected on the second request (401)" do
      {url, target} = start_loopback_receiver({127, 0, 0, 1})

      {grant, proof, invocation_id, nonce} = loopback_signed_envelope(target)

      assert {:ok, %{status: 200, body: "accepted"}} =
               Req.post(url,
                 headers: envelope_headers(grant, proof, invocation_id, nonce),
                 body: @body
               )

      assert {:ok, %{status: 401, body: "invalid"}} =
               Req.post(url,
                 headers: envelope_headers(grant, proof, invocation_id, nonce),
                 body: @body
               )
    end
  end

  # A loopback envelope hand-signed against `target` (the canonical listener URI).
  defp loopback_signed_envelope(target) do
    {pub, priv} = ed25519(@holder_seed)
    {:ok, thumb} = V1.Jwk.public_key_thumbprint_raw(pub, %{})
    {grant_compact, _issuer_pub} = EdgeAgent.DemoIssuer.signed_grant(thumb)
    {:ok, cast_arguments} = V1.Json.decode(@body)

    invocation_id = "00000000-0000-4000-8000-0000000000a1"
    nonce = "demo-loopback-nonce-0001"

    report = %{
      grant_compact: grant_compact,
      operation: "report_external_materialization",
      method: "POST",
      target_uri: target,
      invocation_id: invocation_id,
      cast_arguments: cast_arguments,
      nonce: nonce
    }

    {:ok, %{proof: proof}} =
      BoundedAuthorityReportAdapter.sign_local_loopback_report(
        report,
        {EdgeAgent.Handle, {pub, priv}},
        %{}
      )

    {grant_compact, proof, invocation_id, nonce}
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
