# Framework and runtime integration

This guide is the verifier side of the contract: how any service consumes a `{grant, proof}`
envelope produced by `BoundedAuthorityReportAdapter.sign_report/3`. The verifier depends
**only on the public `bounded_authority_protocol` package**, never on this adapter.

> **Tested transport example:** the repository's `examples/edge_agent` app demonstrates the cryptographic transport stages: a Plug receiver on Bandit (`EdgeAgent.Receiver`) that retains the raw
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

## 4. Verify and bind identity

This module performs pure envelope verification and the identity binding from §8. It does not authorize or execute a request. A verifier that
copies only the `check_envelope/2` call, without the binding, is open to cross-identity
replay. The `config` map carries the values your service configures and validates at boot,
including the contract-major it accepts: 1 (Ed25519 keys, `BoundedAuthorityProtocol.V1`)
by default, or 3 (P-256 keys, `BoundedAuthorityProtocol.V3`). Both take the same input
structs.

```elixir
defmodule MyApp.EnvelopeVerifier do
  alias BoundedAuthorityProtocol.V1

  @doc """
  Verifies one request. `headers` is the request's headers as a map with lowercase names,
  `raw_body` the exact body bytes, and `identity_public_key` the public key of the identity
  your transport authenticated: a raw 32-byte Ed25519 key, or a 65-byte uncompressed P-256
  point for contract-major 3. Returns `{:ok, facts}` or `:invalid`.
  """
  def verify(raw_body, headers, identity_public_key, config) do
    with {:ok, protocol} <- protocol(config),
         {:ok, grant} <- Map.fetch(headers, "x-ba-grant"),
         {:ok, proof} <- Map.fetch(headers, "x-ba-proof"),
         {:ok, invocation_id} <- Map.fetch(headers, "x-ba-invocation-id"),
         {:ok, nonce} <- Map.fetch(headers, "x-ba-nonce"),
         {:ok, cast_arguments} <- V1.Json.decode(raw_body),
         {:ok, facts} <-
           protocol.check_envelope(
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

  defp protocol(%{contract_major: 3}), do: {:ok, BoundedAuthorityProtocol.V3}
  defp protocol(%{contract_major: 1}), do: {:ok, V1}
  defp protocol(config) when not is_map_key(config, :contract_major), do: {:ok, V1}

  defp protocol(_config), do: :error

  # Returns :ok or {:error, _}, not a boolean: a boolean never matches `:ok <-`.
  defp bind_holder_to_identity(bound_holder_thumbprint, identity_public_key) do
    with {:ok, jwk_module} <- jwk_module(identity_public_key),
         {:ok, jwk} <- jwk_module.encode_public(identity_public_key, %{}),
         {:ok, thumbprint} <- jwk_module.thumbprint(jwk, %{}),
         {:ok, identity_thumbprint} <- Base.url_decode64(thumbprint, padding: false) do
      if identity_thumbprint == bound_holder_thumbprint, do: :ok, else: {:error, :not_bound}
    end
  end

  # The RFC 7638 preimage follows the key type: OKP members for an Ed25519 key, EC members
  # for a P-256 point. A key of the other type then never matches the grant's thumbprint.
  defp jwk_module(<<_::binary-size(32)>>), do: {:ok, V1.Jwk}
  defp jwk_module(<<4, _::binary-size(64)>>), do: {:ok, BoundedAuthorityProtocol.V3.EcJwk}
  defp jwk_module(_other), do: {:error, :unsupported_key}
end
```

The holder obtains the same tagged form before calling `sign_report/3`, by decoding the raw
body it is about to send with `V1.Json.decode/2`. The adapter takes `cast_arguments`
already in that form; it does not convert a map.

The test suite runs this module against real envelopes of both contract-majors: it accepts
the matching request, and returns `:invalid` for a different identity (including a P-256
identity whose key differs from the holder's), a different request body, and a missing
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
present is the normal envelope form. **Any** envelope-specific header, including a partial,
empty or repeated grant/proof, selects the envelope path and must fail closed if malformed.
Only a request with no envelope-specific headers may enter the existing scheme, and only
on routes that explicitly permit that scheme. Never fall back to the existing scheme after
an envelope failure. On envelope-only routes, reject missing envelope headers too.
The selected route or registered client selects the contract-major at boot; never try
another verifier after rejection. The adapter also requires a grant of the selected major.

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

## 9. Reserve replay identities

`check_envelope/2` checks that the proof's nonce equals the nonce you expect. It is
stateless and does not remember nonces, so a byte-identical captured request is accepted
again until `proof_max_age` expires. The host must atomically reserve both the proof/challenge replay identity and the execution
identity `(trusted issuer, grant id, invocation id)` in shared durable storage. Keep a nonce
claim through its whole acceptance window plus skew. Keep the execution claim through grant
expiry plus the maximum allowed skew, or longer in an authoritative execution record. A
fresh proof and nonce must not execute the same invocation again. A uniqueness constraint
or equivalent atomic insert decides concurrent races; a read followed by a write does not.
A store timeout or uncertain result refuses execution. Key every claim by the trusted
security context, not a caller-selected identity. Identity binding is required separately.
See [Security](security.md#replay-and-first-arrival) for the first-arrival limit.

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
   `nonce: {:required, challenge}` and consume the challenge atomically after verification and host policy checks (for
   example `:ets.take/2` in a single-VM demonstration). The profile verifier rejects `:not_required`. A server-minted single-use
   challenge limits successful consumption to one arrival. It does not authenticate the
   first arrival: an interceptor can submit a captured valid request first and deny the
   legitimate sender. Single-use is not protection from first-arrival interception.
2. **Derive the target from the listener, and refuse to boot otherwise.** The expected
   `target_uri` comes from the address your listener bound (`http://127.0.0.1:PORT/PATH`
   or `http://[::1]:PORT/PATH`), never from a `Host` or `X-Forwarded-*` header. A loopback
   receiver that starts on a routable interface is a configuration error; fail at boot.
3. **Say what it is.** Loopback HTTP has no confidentiality, no server authentication and
   no process isolation. It is a development convenience, not a substitute for HTTPS.
   Choose the profile when you construct the receiver, never per request.

The runnable version is the example receiver's `profile: :local_loopback` mode, driven by
`EdgeAgent.run_local_loopback/1`.

## 11. Complete host admission before any effect

These obligations apply to all hosts: HTTP endpoints, message consumers, scheduled workers,
command handlers and embedded processes. Phoenix and Plug are examples of HTTP hosts,
not the boundary of supported integrations.

1. Authenticate the caller using the host's transport/session trust model. Select the
   accepted scheme, profile, expected operation, trusted issuer and canonical endpoint from
   host configuration or registered context. Bound sizes before parsing; reject repeated
   credential headers rather than collapsing them into a map.
2. Preserve the raw input before a framework parser consumes it. Decode it with the protocol's
   tagged JSON decoder and verify against the actual method and configured target. If host
   casting changes an argument, verify the value actually executed; do not verify one value
   and execute a differently cast one. JSON whitespace is not a signed byte identity: the
   proof binds typed values. Exact-content assertions bind exact bytes.
3. Bind verified holder facts to the authenticated identity's enrolled key.
4. Apply host authorization for that principal, operation and resource. Facts have
   `authorization: :not_evaluated`; a signature does not override access policy.
5. Check current grant/key revocation in the authority that owns it. Unavailable, stale or
   ambiguous state refuses admission. Coordinate this with policy and admission so a revoked
   grant cannot race a stale allow decision into an effect.
6. Atomically reserve challenge/proof and invocation replay identities as §9 specifies,
   then execute only under the resulting host admission. Couple admission and local effects
   transactionally; for external effects persist an execution state machine and recovery
   protocol. Verification facts are never a transferable execution credential.

In a Plug endpoint, install the raw-body reader with `Plug.Parsers`' `body_reader:` option
before parsers run. Keep retention limited to the protected routes and bounded total bytes;
handle `{:more, partial, conn}` as oversize or collect bounded chunks, never silently discard
chunks. An isolated route can read directly, as the example does. In Phoenix the endpoint
parser runs before router pipelines, so a router plug is too late to retain the raw body.
For queues, preserve the original payload and supply the registered operation and consumer
context rather than inventing HTTP identity from untrusted message fields. Bound custody
calls, backpressure and concurrency in every host.

The following HTTP entry point is a complete handoff: `authorize`, `revocation`, and `admit`
are required host functions, each returning `:ok` only on success. `admit` owns the shared
durable replay transaction and execution record; it cannot be replaced by a boolean pre-read.
The example app's tests supply a real local policy and ETS store, with authorization,
revocation, identity and replay refusals. Production storage must survive restarts.

<!-- doc-runtime: http -->

```elixir
defmodule MyApp.ReportPlug do
  @behaviour Plug
  @headers ["x-ba-grant", "x-ba-proof", "x-ba-invocation-id", "x-ba-nonce"]

  @impl true
  def init(config), do: config

  @impl true
  def call(%{method: "POST"} = conn, config) do
    case Plug.Conn.read_body(conn, length: 1_000_000) do
      {:ok, raw_body, conn} -> verify_and_admit(conn, raw_body, config)
      {:more, _partial, conn} -> Plug.Conn.send_resp(conn, 401, "invalid")
      {:error, _reason} -> Plug.Conn.send_resp(conn, 401, "invalid")
    end
  end

  def call(conn, _config), do: Plug.Conn.send_resp(conn, 401, "invalid")

  defp verify_and_admit(conn, raw_body, config) do
    with true <- conn.request_path == URI.parse(config.target_uri).path,
         true <- conn.query_string == "",
         {:ok, identity} <- Map.fetch(conn.assigns, :identity_public_key),
         {:ok, headers} <- envelope_headers(conn),
         {:ok, facts} <- MyApp.EnvelopeVerifier.verify(raw_body, headers, identity, config),
         :ok <- config.authorize.(facts, identity),
         :ok <- config.revocation.(facts),
         :ok <- config.admit.(facts, headers["x-ba-invocation-id"], headers["x-ba-nonce"]) do
      # Admission succeeded. The host executes only through its admitted execution record.
      Plug.Conn.send_resp(conn, 200, "accepted")
    else
      _ -> Plug.Conn.send_resp(conn, 401, "invalid")
    end
  end

  defp envelope_headers(conn) do
    Enum.reduce_while(@headers, {:ok, %{}}, fn name, {:ok, headers} ->
      case Plug.Conn.get_req_header(conn, name) do
        [value] when value != "" -> {:cont, {:ok, Map.put(headers, name, value)}}
        _ -> {:halt, :invalid}
      end
    end)
  end
end
```

Use the same admission boundary in non-HTTP hosts. Only the transport extraction changes;
policy, revocation and replay ownership do not. The [operations runbook](operations.md)
covers unavailable stores, key rotation, custody failures and incident response.

## 12. Sign and verify an action approval

An executing host sets the approval requirement and eligible approver roles as operation
policy. Prepare the request ID, immutable revision digest, subject, action and exact resource
set from the request the host intends to execute. The approver uses a plain signing-backend
signature. Carry the returned record bytes and assertion compact together.

This example uses the development key from the README. In production, the handle resolves
an immutable signing version from caller-owned custody. The relying party supplies its own
prepared request, enrolled key, trusted-key snapshot and current time.

```elixir
alias BoundedAuthorityProtocol.ActionApproval.V1, as: Approval

prepared = %{
  request_id: "urn:example:request:accessibility-review",
  revision_digest: :crypto.hash(:sha256, "prepared accessibility revision"),
  subject: "public documentation",
  action: "publish",
  resources: ["accessibility-summary", "navigation-guide"]
}

record = struct!(Approval.Record, Map.put(prepared, :approver_role, "reviewer"))
audience = "https://documentation.example"
issuer = "https://review.example"
approver = {MyApp.DevKey, {:reviewer, "reviewer-key-1"}}

{:ok, %{record: record_bytes, content_assertion: assertion}} =
  BoundedAuthorityReportAdapter.sign_action_approval(
    %{
      record: record,
      jti: "urn:example:approval:accessibility-review-1",
      iss: issuer,
      aud: audience,
      iat: now,
      nbf: now,
      exp: now + 60
    },
    approver
  )

{:ok, enrolled_key} = MyApp.DevKey.public_key({:reviewer, "reviewer-key-1"})

context =
  Map.merge(prepared, %{
    trust_domain: "documentation",
    audience: audience,
    roles: ["reviewer"],
    now: now,
    max_staleness: 30,
    max_lifetime: 60,
    bounds: %{},
    record_bounds: %{},
    snapshot: %{
      trust_domain: "documentation",
      suite: :eddsa,
      provenance: "configured-enrollment",
      as_of: now,
      entries: [
        %{
          issuer: issuer,
          key: %V1.HistoricalPublicKey{
            key_id: "reviewer-key-1",
            public_key: enrolled_key,
            valid_from: now,
            valid_before: :unbounded
          },
          roles: ["reviewer"]
        }
      ]
    }
  })

{:ok, %{trust: :not_evaluated}} = Approval.verify_eddsa(record_bytes, assertion, context)

Approval.verify_eddsa(record_bytes, assertion, %{context | resources: ["navigation-guide"]})
#=> {:error, :scope_mismatch}
```

For P-256, select `BoundedAuthorityReportAdapter.V3.sign_action_approval/3` and
`Approval.verify_es256/3` with an independently configured ES256 snapshot. Collapse any
presenter-facing verification failure to the same value-free refusal. Before committing
the effect or its durable intent, the host authenticates the executor and atomically checks
the current revision and claims both the assertion identity and the request revision.
