defmodule EdgeAgent do
  @moduledoc """
  The edge-agent reference — the HOLDER role, played by a real (if minimal)
  application that calls `BoundedAuthorityReportAdapter.sign_report/3` and ships
  the envelope over HTTP.

  `run/0` is the one-shot loop the ROADMAP RA9 acceptance names: read a grant +
  holder key (config-driven), sign a proof over the configured report, POST the
  raw report body + the `{grant, proof}` envelope to the receiver URL. Run it with
  `mix run -e EdgeAgent.run` once the receiver (`EdgeAgent.Receiver.start`) is
  listening.

  ## The request-field contract (consumer-integration.md §3), edge side

  Both the edge and the receiver derive each bound field from the SAME source:

    * `method` — literal `"POST"`.
    * `target_uri` — the configured canonical URI (https, `Uri.normalize`-stable).
      Boot-time-consistent with the receiver because both read this config.
    * `invocation_id` — a fresh unique id the edge generates per report.
    * `operation` — the normative contract constant the issuer's grant authorizes.
    * `cast_arguments` — `V1.Json.decode(raw_report_body_bytes)` of the WHOLE
      body: BAP's tagged `Json.value()` form. The receiver decodes the SAME raw
      bytes with the SAME function — byte-agreement by construction.
    * `nonce` — a fresh nonce the edge generates per report.

  The raw report body rides as the HTTP request body; the envelope rides as
  `X-BA-Grant` + `X-BA-Proof` headers (presence of BOTH is the scheme
  discriminator — consumer-integration.md §2).

  ## What the demo simplifies

  In production the grant arrives issuer-signed out-of-band (the BA runtime), and
  the holder key lives behind an HSM/KMS-backed handle (see `EdgeAgent.Handle`).
  Here, `DemoIssuer` mints the grant from the configured demo issuer key and the
  holder keypair is derived from a seed, so the whole loop runs with zero external
  services.
  """

  import Bitwise

  alias BoundedAuthorityProtocol.V1

  @doc """
  Runs the edge agent once and returns `{:ok, status, body}` from the receiver
  (`200 accepted` on a clean verify, `401 invalid` on any failure), or
  `{:error, reason}` if the POST itself failed.

  Options:

    * `:receiver_url` — override the configured receiver URL (default:
      `config :edge_agent, :receiver_url`).

  """
  @spec run(keyword()) :: {:ok, non_neg_integer(), binary()} | {:error, term()}
  def run(opts \\ []) do
    holder = holder_keypair()
    {holder_pub, _holder_priv} = holder
    {:ok, holder_thumbprint} = V1.Jwk.public_key_thumbprint_raw(holder_pub, %{})

    # Prod: the grant arrives issuer-signed out-of-band. Demo: mint from config.
    {grant_compact, _issuer_pub} = EdgeAgent.DemoIssuer.signed_grant(holder_thumbprint)

    # The SAME typed cast_arguments the receiver reconstructs from the raw bytes
    # (consumer-integration.md §4): both sides V1.Json.decode the SAME body.
    raw_body = cfg(:report_body)
    {:ok, cast_arguments} = V1.Json.decode(raw_body)

    invocation_id = generate_invocation_id()
    nonce = generate_nonce()

    report = %{
      grant_compact: grant_compact,
      operation: cfg(:operation),
      method: "POST",
      target_uri: cfg(:target_uri),
      invocation_id: invocation_id,
      cast_arguments: cast_arguments,
      nonce: nonce
    }

    {:ok, %{grant: ^grant_compact, proof: proof}} =
      BoundedAuthorityReportAdapter.sign_report(report, {EdgeAgent.Handle, holder}, %{})

    post(
      Keyword.get(opts, :receiver_url, cfg(:receiver_url)),
      grant_compact,
      proof,
      raw_body,
      invocation_id,
      nonce
    )
  end

  @doc """
  Runs the edge agent once over the LOCAL-LOOPBACK profile — the byte-distinct
  `ba+loopback-proof` flow (`sign_local_loopback_report/3`) for a development
  listener on the literal loopback interface.

  The flow is challenge-first: GET the receiver's URL to obtain a
  LISTENER-RESERVED nonce (the receiver mints it; the agent never chooses it),
  sign the proof binding that challenge, then POST. The `target_uri` is the
  receiver's own canonical URL (`:receiver_url` — exactly
  `http://127.0.0.1:PORT/PATH` or `http://[::1]:PORT/PATH`), and the receiver
  verifies against the target derived from ITS OWN bound listener, never from
  client-supplied headers. Local-loopback HTTP is plain HTTP — no TLS
  confidentiality or server authentication, NOT equivalent to HTTPS.

  A non-canonical or non-loopback `:receiver_url` fails closed at signing
  (`{:producer_error, :invalid}` — BAP's profile admission).
  """
  @spec run_local_loopback(keyword()) ::
          {:ok, non_neg_integer(), binary()} | {:error, term()}
  def run_local_loopback(opts \\ []) do
    holder = holder_keypair()
    {holder_pub, _holder_priv} = holder
    {:ok, holder_thumbprint} = V1.Jwk.public_key_thumbprint_raw(holder_pub, %{})

    {grant_compact, _issuer_pub} = EdgeAgent.DemoIssuer.signed_grant(holder_thumbprint)

    raw_body = cfg(:report_body)
    {:ok, cast_arguments} = V1.Json.decode(raw_body)

    receiver_url = Keyword.get(opts, :receiver_url, cfg(:loopback_receiver_url))

    # The challenge is the LISTENER's: minted by the receiver (GET), consumed
    # atomically at verification. The agent signs it; it never mints a nonce.
    with {:ok, %{status: 200, body: nonce}} when is_binary(nonce) <- Req.get(receiver_url),
         invocation_id = generate_invocation_id(),
         report = %{
           grant_compact: grant_compact,
           operation: cfg(:operation),
           method: "POST",
           target_uri: receiver_url,
           invocation_id: invocation_id,
           cast_arguments: cast_arguments,
           nonce: nonce
         },
         {:ok, %{grant: ^grant_compact, proof: proof}} <-
           BoundedAuthorityReportAdapter.sign_local_loopback_report(
             report,
             {EdgeAgent.Handle, holder},
             %{}
           ) do
      post(receiver_url, grant_compact, proof, raw_body, invocation_id, nonce)
    end
  end

  defp post(url, grant, proof, body, invocation_id, nonce) do
    headers = [
      {"content-type", "application/json"},
      {"x-ba-grant", grant},
      {"x-ba-proof", proof},
      {"x-ba-invocation-id", invocation_id},
      {"x-ba-nonce", nonce}
    ]

    case Req.post(url, headers: headers, body: body) do
      {:ok, %{status: status, body: resp_body}} -> {:ok, status, resp_body}
      error -> error
    end
  end

  # A fresh UUID v4 per report — the invocation_id the proof binds (RFC 4122 v4:
  # 16 random bytes, version + variant nibbles set). BAP's verifier gates the
  # invocation_id through `valid_uuid?`, so the canonical UUID shape is required.
  defp generate_invocation_id do
    <<b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15>> =
      :crypto.strong_rand_bytes(16)

    versioned = (b6 &&& 0x0F) ||| 0x40
    varianted = (b8 &&& 0x3F) ||| 0x80

    <<b0, b1, b2, b3, b4, b5, versioned, b7, varianted, b9, b10, b11, b12, b13, b14, b15>>
    |> Base.encode16(case: :lower)
    |> format_uuid()
  end

  defp format_uuid(
         <<a::binary-size(8), b::binary-size(4), c::binary-size(4), d::binary-size(4),
           e::binary-size(12)>>
       ) do
    "#{a}-#{b}-#{c}-#{d}-#{e}"
  end

  # A fresh 16-byte nonce per report, base64url-encoded (no padding). The proof
  # binds it; the receiver's ledger dedupes on it.
  defp generate_nonce do
    :crypto.strong_rand_bytes(16) |> Base.url_encode64(padding: false)
  end

  defp holder_keypair, do: :crypto.generate_key(:eddsa, :ed25519, cfg(:holder_seed))
  defp cfg(key), do: Application.fetch_env!(:edge_agent, key)
end
