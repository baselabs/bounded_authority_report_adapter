# Consuming an envelope from this adapter

This guide is the verifier side of the contract: how any service consumes a `{grant, proof}`
envelope produced by `BoundedAuthorityReportAdapter.sign_report/3`. The verifier depends
**only on the public `bounded_authority_protocol` package**, never on this adapter.

> **Runnable reference:** the repository's `examples/edge_agent` app implements this whole
> contract end to end: a Plug receiver on Bandit (`EdgeAgent.Receiver`) that retains the raw
> body, runs the single `with` from §4, binds the holder to the configured identity (§8),
> and dedupes nonces (§9). Its tests run it over real HTTP.

## 1. What the adapter produces

`sign_report/3` returns `{:ok, %{grant: grant_compact, proof: proof_compact}}`: two compact
JWS strings. The grant is the issuer-signed grant the caller supplied, passed through
unchanged (`sign_report/3` never signs a grant; grant signing is the separate issuer-role
`sign_grant/3`). The proof is the holder's binding of that grant to one request, signed
through the holder's key handle.

## 2. Transport the envelope and retain the raw body

Carry the two compacts to the verifier over your transport. A simple wire shape, used by
the example app: two request headers, `X-BA-Grant` and `X-BA-Proof`, each holding one
compact string, plus `X-BA-Invocation-Id` and `X-BA-Nonce` for the per-request values.

**Retain the request body's raw bytes.** The verifier rebuilds `cast_arguments` by decoding
the raw body, not your HTTP framework's parsed map: parsing loses both the exact bytes and
the protocol's tagged structure. With `Plug.Parsers`, pass a `body_reader:` option at the
endpoint (a router-pipeline plug runs after parsing and sees an empty body), and make it
conditional on the report route so you do not keep a copy of every request body. A plug
with no parser in front of it can call `Plug.Conn.read_body/2` directly, as the example
receiver does.

## 3. The request-field contract

The proof binds a set of request fields; the verifier rebuilds the same values or the proof
is rejected. Both sides derive each field from the same source:

| Field | At signing time (holder) | At verification time (verifier) |
|---|---|---|
| `method` | the HTTP method sent | the HTTP method received |
| `target_uri` | the configured canonical URI of the endpoint | the same configured canonical URI |
| `invocation_id` | a fresh UUID the holder generates | read from the `X-BA-Invocation-Id` header |
| `operation` | the operation name the grant authorizes | the same constant for this endpoint |
| `cast_arguments` | `V1.Json.decode/2` of the raw body bytes sent | `V1.Json.decode/2` of the raw body bytes received |
| `nonce` | the request nonce | read from the `X-BA-Nonce` header |

Notes:

- **`target_uri` is configured, not derived from the request.** The `Host` header varies
  across proxies and load balancers and is client-controlled. Validate the configured value
  at boot: a target that is not HTTPS, or not already in the protocol's normalized form
  (lowercase host, no default port, no dot segments, no query), fails at signing time on
  the holder as `{:producer_error, :invalid}`, so surface it as a startup failure, not a
  stream of 401s.
  Keep the holder's and the verifier's configuration in sync.
- **`cast_arguments` is the whole body** decoded into the protocol's tagged `Json.value()`
  form with `BoundedAuthorityProtocol.V1.Json.decode/2`. Both sides decode the same bytes
  with the same function, so they agree by construction. Integers decode as
  `{:integer, n}`, strings as `{:string, s}`.
- **`operation` is part of the contract.** The issuer must mint grants for the same
  operation name the verifier expects; a mismatch fails closed.

## 4. Call the verifier: one `with`, fail closed

This module is the complete path, including the identity binding from §8. A verifier that
copies only the `check_envelope/2` call, without the binding, is open to cross-identity
replay. The `config` map carries the values your service configures and validates at boot.

```elixir
defmodule MyApp.EnvelopeVerifier do
  alias BoundedAuthorityProtocol.V1

  @doc """
  Verifies one request. `headers` is the request's headers as a map with lowercase names,
  `raw_body` the exact body bytes, and `identity_public_key` the raw Ed25519 public key of
  the identity your transport authenticated. Returns `{:ok, facts}` or `:invalid`.
  """
  def verify(raw_body, headers, identity_public_key, config) do
    with {:ok, grant} <- Map.fetch(headers, "x-ba-grant"),
         {:ok, proof} <- Map.fetch(headers, "x-ba-proof"),
         {:ok, invocation_id} <- Map.fetch(headers, "x-ba-invocation-id"),
         {:ok, nonce} <- Map.fetch(headers, "x-ba-nonce"),
         {:ok, cast_arguments} <- V1.Json.decode(raw_body),
         {:ok, facts} <-
           V1.check_envelope(
             %V1.Credentials{grant: grant, proof: proof},
             %V1.ExpectedRequest{
               trusted_issuer: %V1.TrustedIssuer{
                 key_id: config.issuer_key_id,
                 public_key: config.issuer_public_key
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
             }
           ),
         # Required (§8): bind the verified envelope to the authenticated identity.
         :ok <- bind_holder_to_identity(facts.holder_thumbprint, identity_public_key) do
      {:ok, facts}
    else
      # One uniform rejection; never say which check failed (§5).
      _any_failure -> :invalid
    end
  end

  # Returns :ok or {:error, _}, not a boolean: a boolean never matches `:ok <-`.
  defp bind_holder_to_identity(bound_holder_thumbprint, identity_public_key) do
    with {:ok, jwk} <- V1.Jwk.encode_public(identity_public_key, %{}),
         {:ok, thumbprint} <- V1.Jwk.thumbprint(jwk, %{}),
         {:ok, identity_thumbprint} <- Base.url_decode64(thumbprint, padding: false) do
      if identity_thumbprint == bound_holder_thumbprint, do: :ok, else: {:error, :not_bound}
    end
  end
end
```

The holder obtains the same tagged form before calling `sign_report/3`, by decoding the raw
body it is about to send with `V1.Json.decode/2`. The adapter takes `cast_arguments`
already in that form; it does not convert a map.

The test suite runs this module against a real envelope: it accepts the matching request,
and returns `:invalid` for a different identity, a different request body, and a missing
header. The proof binds the decoded body, so a change that decodes to the same value (extra
whitespace between JSON tokens, for example) is the same request.

## 5. Fail closed, uniformly and without values

Any failure is a rejection with the same response your other authentication failures use
(401 or its equivalent). The response must not distinguish a bad grant from a bad proof, a
wrong key, a malformed body or a decode failure. Telemetry, if you emit any, carries no
grant, proof or signature bytes.

`check_envelope/2` and `Json.decode/2` never raise on bad input; they return
`{:error, :invalid}`. A single `with` is therefore enough, provided the configured values
(the issuer public key and the rest) are validated at boot or decoded inside the `with`,
so a malformed configuration also ends in `:invalid` instead of a crash.

## 6. Running alongside an existing scheme

During a migration, requests may arrive under an existing authentication scheme or with an
envelope. Choose the path by the envelope's presence: both `X-BA-Grant` and `X-BA-Proof`
present means the envelope path; anything else takes the existing path, unchanged. The
remaining attack is availability, not bypass: stripping the envelope headers routes a
request to the existing path, where it has no valid credential and is rejected; adding a
stray envelope header routes a request to the envelope path, where it fails verification.
Requiring both headers keeps that surface small.

## 7. Record which scheme verified a request

If you persist verified requests, record which scheme verified each one (for example a
`signature_scheme` column holding `ba_protocol_v1`), set from the verified result in your
code and never from a header or body field, so a client cannot label its own request.

## 8. Bind the envelope to the authenticated identity (required)

`check_envelope/2` proves that some holder holds a valid grant bound to this request. It
does not prove that the holder is the identity your transport authenticated (an API key,
a client certificate, a session). Grant and proof travel with every request, so a captured
envelope can be replayed under a different authenticated identity. If your replay
protection is keyed by that identity, the replay does not collide with the original, and
the captured request is accepted once per identity.

The fix is the binding in §4. The grant names a holder key by its thumbprint (`cnf.jkt`);
each identity you authenticate has a holder key (Ed25519 for contract-major 1, P-256 for
`V3` credentials). After `check_envelope/2` succeeds, check that `facts.holder_thumbprint`
equals the RFC 7638 thumbprint of the authenticated identity's own key. A captured envelope
then verifies only for the identity the grant was issued to. Compute the thumbprint with
the protocol package's `V1.Jwk.encode_public/2` and `V1.Jwk.thumbprint/2` (for P-256 keys,
`V3.EcJwk`), and compare raw 32-byte values; do not hand-roll RFC 7638.

Do not accept envelopes without this binding.

## 9. Dedupe nonces (a replay ledger)

`check_envelope/2` checks that the proof's nonce equals the nonce you expect. It is
stateless and does not remember nonces, so a byte-identical captured request is accepted
again until `proof_max_age` expires. Keep a replay ledger, for example a unique constraint
on `(identity, nonce)`, and reject a nonce you have seen. This is the verifier's job, as
the §8 binding is.

## 10. The local-loopback profile (development listeners)

For a verifier serving plain HTTP on the literal loopback interface, the protocol defines a
byte-distinct sibling profile (`bap-application-proof/local-loopback-http/1`, protected
`typ: ba+loopback-proof`). The signer is the adapter's `sign_local_loopback_report/3`; the
verifier is `BoundedAuthorityProtocol.ApplicationProfile.LocalLoopbackHttp.V1.check_envelope/2`,
a separate function, not an option on the standard one. Each proof family rejects the
other's bytes, so a loopback listener never accepts a standard `dpop+jwt` proof and the
standard verifier never accepts a loopback proof.

Sections 2 to 9 apply unchanged, with three additions:

1. **The nonce is mandatory, and the listener chooses it.** Mint a fresh single-use
   challenge per request, hand it to the signer, and verify with
   `nonce: {:required, challenge}` while consuming the challenge atomically (for example
   `:ets.take/2`). The profile verifier rejects `:not_required`. A server-minted single-use
   challenge closes the first-use replay race that a client-chosen nonce leaves open on a
   transport without TLS.
2. **Derive the target from the listener, and refuse to boot otherwise.** The expected
   `target_uri` comes from the address your listener bound (`http://127.0.0.1:PORT/PATH`
   or `http://[::1]:PORT/PATH`), never from a `Host` or `X-Forwarded-*` header. A loopback
   receiver that starts on a routable interface is a configuration error; fail at boot.
3. **Say what it is.** Loopback HTTP has no confidentiality, no server authentication and
   no process isolation. It is a development convenience, not a substitute for HTTPS.
   Choose the profile when you construct the receiver, never per request.

The runnable version is the example receiver's `profile: :local_loopback` mode, driven by
`EdgeAgent.run_local_loopback/1`.
