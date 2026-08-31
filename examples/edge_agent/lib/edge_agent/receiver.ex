defmodule EdgeAgent.Receiver do
  @moduledoc """
  The consumer side of the BA envelope — a Plug served by Bandit that verifies a
  `{grant, proof}` envelope via `BoundedAuthorityProtocol.V1.check_envelope/2`.

  This module depends ONLY on the public `bounded_authority_protocol` package —
  NEVER on `BoundedAuthorityReportAdapter`. That is the dependency-direction wall
  (`docs/consumer-integration.md` §1): the verifier consumes the published
  protocol package; the adapter is the holder-side signing glue the edge agent
  uses, invisible to the receiver. A consumer who coupled to the adapter would
  have built the wall backwards.

  ## The complete safe path (consumer-integration.md §4 + §8 + §9)

  ONE `with`, fail closed to a uniform `401`:

    1. `V1.Json.decode(raw_body)` — decode the request's RAW bytes into BAP's
       tagged `cast_arguments` (a BAP-strict decode catches Jason-valid-but-BAP-
       invalid bodies: duplicate keys, number bounds).
    2. `V1.check_envelope/2` — verify the grant + proof cryptographically against
       the published issuer key + the reconstructed expected request.
    3. Bind the verified envelope's `holder_thumbprint` to the configured
       identity key (§8) — defeats cross-identity replay of a captured envelope.
    4. Claim the nonce on the replay ledger (§9) — defeats same-identity replay
       within the proof window.

  Every failure collapses to the SAME `401 invalid` body (§5): an attacker learns
  nothing about which factor failed.

  ## Raw-body retention

  This minimal receiver reads the body directly via `Plug.Conn.read_body/1` — no
  `Plug.Parsers` competes for it (this pipeline has only the report route), so a
  `body_reader` is unnecessary here. consumer-integration.md §2's `body_reader`
  guidance applies to a pipeline that ALSO parses other routes behind
  `Plug.Parsers`; this example has no such competing parser.

  ## What the demo simplifies

  In production the "authenticated identity" (step 3) is established by a
  SEPARATE transport-auth layer (api_key, mTLS) and the ledger (step 4) is a
  durable unique constraint. This demo uses a configured identity key as a
  stand-in for the transport-auth layer and an ETS table for the ledger — enough
  to demonstrate BOTH obligations are present and non-vacuous, which is the point.
  """

  @behaviour Plug

  alias BoundedAuthorityProtocol.ApplicationProfile.LocalLoopbackHttp.V1, as: Loopback
  alias BoundedAuthorityProtocol.V1
  alias BoundedAuthorityProtocol.V1.Jwk
  alias EdgeAgent.Receiver.NonceLedger

  @loopback_ips [{127, 0, 0, 1}, {0, 0, 0, 0, 0, 0, 0, 1}]

  @impl true
  def init(opts) do
    # Resolve the trusted issuer + expected-identity keys ONCE at server start
    # (boot-validated), not per request: a malformed config fails loudly at boot
    # rather than as a 401 storm. The expected identity is overridable per
    # receiver instance (used by the wrong-identity tripwire test); the default is
    # the configured holder key (the demo's stand-in for the transport identity).
    #
    # Loopback mode (profile: :local_loopback) is BOUND to the listener: the
    # operator passes the ip/port the server actually binds (`ip:` / `port:`,
    # plus optional `path:`), the target is DERIVED from that listener state —
    # never from a client header and never hand-configured — and a non-loopback
    # `ip:` FAILS LOUDLY HERE at boot: a profile receiver on a routable
    # interface would accept loopback-scoped proofs over unauthenticated plain
    # HTTP from the network, which the profile exists to prevent.
    profile = Keyword.get(opts, :profile, :standard)

    {target_uri, loopback} =
      case profile do
        :standard ->
          {Keyword.get(opts, :target_uri, cfg(:target_uri)), false}

        :local_loopback ->
          if Keyword.has_key?(opts, :target_uri) do
            raise ArgumentError,
                  "the local-loopback receiver derives target_uri from its own listener (ip:/port:/path:); a hand-configured target_uri cannot be trusted"
          end

          ip = Keyword.fetch!(opts, :ip)
          port = Keyword.fetch!(opts, :port)
          path = Keyword.get(opts, :path, "/report")

          unless ip in @loopback_ips do
            raise ArgumentError,
                  "the local-loopback profile receiver may only bind the literal loopback interface (127.0.0.1 / ::1); got #{inspect(ip)}"
          end

          {"http://#{loopback_host(ip)}:#{port}#{path}", true}
      end

    %{
      profile: profile,
      loopback: loopback,
      issuer_key_id: cfg(:issuer_key_id),
      issuer: cfg(:issuer),
      audience: cfg(:audience),
      operation: cfg(:operation),
      target_uri: target_uri,
      clock_skew: cfg(:clock_skew),
      proof_max_age: cfg(:proof_max_age),
      trusted_issuer_key: public_key(cfg(:issuer_seed)),
      expected_identity_key: Keyword.get(opts, :expected_identity, public_key(cfg(:holder_seed)))
    }
  end

  defp loopback_host({127, 0, 0, 1}), do: "127.0.0.1"
  defp loopback_host({0, 0, 0, 0, 0, 0, 0, 1}), do: "[::1]"

  @impl true
  def call(%{method: "GET"} = conn, %{loopback: true} = _config) do
    # The profile's nonce reservation: the LISTENER mints the challenge the
    # signer must bind. Client-chosen nonces are not verifiable reservations —
    # on a no-TLS transport a captured client-chosen nonce can be replayed
    # first-use; a server-minted single-use challenge cannot (it is consumed
    # by the legitimate arrival before any replay reaches the ledger).
    challenge = NonceLedger.reserve_challenge()
    Plug.Conn.send_resp(conn, 200, challenge)
  end

  def call(conn, config) do
    # read_body/1 returns {:ok, body, conn} once the whole body is read,
    # {:more, partial, conn} when it exceeded Plug's length limit (an oversize
    # body for this demo — reject it), or {:error, reason} (a 2-tuple; the
    # original conn is all we have). Each branch threads the conn it actually
    # has so the 401 is written against the read-state Bandit expects.
    case Plug.Conn.read_body(conn) do
      {:ok, raw_body, conn} ->
        verify_and_respond(conn, raw_body, config)

      {:more, _partial, conn} ->
        Plug.Conn.send_resp(conn, 401, "invalid")

      {:error, _reason} ->
        Plug.Conn.send_resp(conn, 401, "invalid")
    end
  end

  defp verify_and_respond(conn, raw_body, config) do
    grant = first_header(conn, "x-ba-grant")
    proof = first_header(conn, "x-ba-proof")
    invocation_id = first_header(conn, "x-ba-invocation-id")
    nonce = first_header(conn, "x-ba-nonce")

    case verify(raw_body, grant, proof, invocation_id, nonce, config) do
      :ok -> Plug.Conn.send_resp(conn, 200, "accepted")
      :invalid -> Plug.Conn.send_resp(conn, 401, "invalid")
    end
  end

  # The complete safe path — ONE `with`, fail closed. A BAP-strict decode
  # failure, a check_envelope failure (STANDARD or the local-loopback profile,
  # per the receiver's configured profile), an identity-binding mismatch, AND a
  # replay ALL collapse to :invalid -> the uniform 401. nil grant/proof (a
  # header absent) hits the verifier's non-binary catch-all clause -> :invalid.
  #
  # In loopback mode the nonce is a RESERVED CHALLENGE: the presented value
  # must be one THIS receiver minted (GET) and not yet consumed — atomically
  # consumed HERE, before verification, so a captured request cannot be
  # replayed even once (first-use included). The standard profile keeps the
  # client-nonce + ledger model (§9) — its transport is TLS-authenticated.
  defp verify(raw_body, grant, proof, invocation_id, nonce, config) do
    with {:ok, cast_arguments} <- V1.Json.decode(raw_body),
         :ok <- maybe_consume_challenge(config.loopback, nonce),
         {:ok, facts} <-
           check_envelope(config.profile, grant, proof, %V1.ExpectedRequest{
             trusted_issuer: %V1.TrustedIssuer{
               key_id: config.issuer_key_id,
               public_key: config.trusted_issuer_key
             },
             issuer: config.issuer,
             audience: config.audience,
             method: "POST",
             target_uri: config.target_uri,
             invocation_id: invocation_id,
             operation: config.operation,
             cast_arguments: cast_arguments,
             evaluation_time: System.system_time(:second),
             clock_skew: config.clock_skew,
             proof_max_age: config.proof_max_age,
             nonce: {:required, nonce},
             bounds: V1.Bounds.maximum()
           }),
         :ok <- bind_and_dedupe(facts.holder_thumbprint, config.expected_identity_key, nonce) do
      :ok
    else
      _ -> :invalid
    end
  end

  defp maybe_consume_challenge(true, nonce) when is_binary(nonce),
    do: NonceLedger.consume_challenge(nonce)

  defp maybe_consume_challenge(true, _nonce), do: {:error, :unknown_challenge}
  defp maybe_consume_challenge(false, _nonce), do: :ok

  # The profile selection is EXPLICIT per receiver instance (boot-time), never
  # per request data: the standard verifier rejects ba+loopback-proof bytes and
  # the profile verifier rejects dpop+jwt bytes, each with its own admission
  # rules (the standard target is the configured https URI; the loopback target
  # is the listener-derived canonical http://127.0.0.1|[::1] URI).
  defp check_envelope(:standard, grant, proof, expected) do
    V1.check_envelope(%V1.Credentials{grant: grant, proof: proof}, expected)
  end

  defp check_envelope(:local_loopback, grant, proof, expected) do
    Loopback.check_envelope(%V1.Credentials{grant: grant, proof: proof}, expected)
  end

  # §8 identity binding + §9 nonce dedup folded into one step: both need the
  # configured identity's thumbprint, so compute it once. A thumbprint mismatch
  # (the envelope's holder is not the identity this transport authenticated)
  # rejects; then the nonce is atomically claimed (a replay rejects).
  defp bind_and_dedupe(holder_thumbprint, identity_raw_key, nonce) do
    with {:ok, identity_thumbprint} <- Jwk.public_key_thumbprint_raw(identity_raw_key, %{}) do
      cond do
        identity_thumbprint != holder_thumbprint -> {:error, :not_bound}
        not is_binary(nonce) -> {:error, :no_nonce}
        true -> NonceLedger.claim(identity_thumbprint, nonce)
      end
    end
  end

  defp first_header(conn, name) do
    case Plug.Conn.get_req_header(conn, name) do
      [value | _] -> value
      [] -> nil
    end
  end

  defp public_key(seed), do: elem(:crypto.generate_key(:eddsa, :ed25519, seed), 0)
  defp cfg(key), do: Application.fetch_env!(:edge_agent, key)

  @doc """
  Starts the receiver (the nonce-ledger GenServer + a Bandit server) for
  standalone `mix run --no-halt -e EdgeAgent.Receiver.start` use. ip/port default
  to config; pass `ip:` / `port:` to override. Pass `profile: :local_loopback`
  for the profile receiver — the plug then binds to the given (loopback-only)
  ip/port, derives its target from them, and mints the flow's reserved
  challenges on GET.
  """
  @spec start_link(keyword()) :: Supervisor.on_start()
  def start_link(opts \\ []) do
    ip = Keyword.get(opts, :ip, cfg(:receiver_ip))
    port = Keyword.get(opts, :port, cfg(:receiver_port))

    plug =
      case Keyword.get(opts, :profile, :standard) do
        :standard -> __MODULE__
        :local_loopback -> {__MODULE__, profile: :local_loopback, ip: ip, port: port}
      end

    children = [
      # Bandit takes :ip/:port/:scheme at the top level (since 0.7.6; the
      # nested :options key was removed then — under our ~> 1.0 constraint no
      # version accepts it).
      NonceLedger,
      {Bandit, plug: plug, scheme: :http, ip: ip, port: port}
    ]

    Supervisor.start_link(children, strategy: :one_for_one, name: __MODULE__.Supervisor)
  end

  @doc "Convenience for `mix run -e EdgeAgent.Receiver.start` — starts + returns :ok."
  @spec start() :: :ok
  def start do
    {:ok, _pid} = start_link([])
    :ok
  end
end
