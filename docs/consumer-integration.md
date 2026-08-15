# Consuming an envelope from this adapter

This is the **universal consumer contract**: how any verifier consumes a `{grant, proof}` envelope
produced by `BoundedAuthorityReportAdapter.sign_report/3`. The verifier depends **only on the public
`bounded_authority_protocol` package** — never on this adapter (the dependency-direction wall).
verifier application's report path is the first instance; the contract is general.

> **Runnable reference:** [`examples/edge_agent/`](../examples/edge_agent/) implements this whole
> contract end-to-end — a `Plug`/Bandit receiver (`EdgeAgent.Receiver`) that retains the raw body,
> runs the one-`with` verify below, binds the holder to the configured identity (§8), and dedupes
> nonces (§9). It is the first runnable instance of this guide; read it alongside the prose.

## 1. What the adapter produces

`sign_report/3` returns `{:ok, %{grant: grant_compact, proof: proof_compact}}` — two compact-JWS
binary strings. The grant is the pass-through of the issuer-signed grant the caller supplied
(`sign_report/3` never signs the grant — grant signing is the separate issuer-role
instantiation `sign_grant/3`, ADR-0007, not part of this flow); the proof is the holder's
binding of that grant to the
report, signed via the holder key behind the `{module(), term()}` key-handle.

## 2. Transport the envelope + retain the raw body

Carry the two compacts to the verifier over your transport. The RECOMMENDED wire shape (verifier application
instance #1): two request headers, `X-BA-Grant` and `X-BA-Proof`, each one compact string. Presence
of BOTH is the scheme discriminator (a single header alone is neither a valid BA report nor the
legacy scheme — it falls to the legacy path and fails closed there).

**Retain the request body's RAW bytes.** `cast_arguments` reconstruction decodes the raw body (not
the HTTP framework's parsed map — parsing loses both the bytes and the tagged structure). With
`Plug.Parsers`, pass a `body_reader:` option at the ENDPOINT (where parsers live — a router-pipeline
plug runs *after* parsing and sees an empty body), **path-conditional to the report route** so an
unconditional reader doesn't stash a copy of every request on every pipeline (a per-request memory
amplifier).

## 3. The request-field contract

The proof binds a set of request fields; the verifier reconstructs the *same* values or the proof
rejects. Both sides derive each field from the SAME source:

| Field | At sign time (edge) | At verify time (consumer) |
|---|---|---|
| `method` | `"POST"` | literal `"POST"` |
| `target_uri` | the configured canonical report URI (https, `Uri.normalize`-stable) | the SAME configured canonical URI (boot-validated) |
| `invocation_id` | a unique id the edge generates | read from the `X-BA-Invocation-Id` header |
| `operation` | the normative contract operation constant (the value the issuer's grant authorizes) | the SAME constant |
| `cast_arguments` | `V1.Json.decode(raw_report_body_bytes)` of the WHOLE body | `V1.Json.decode(raw_request_body_bytes)` of the SAME raw bytes |
| `nonce` | the report nonce | read from the report-nonce header |

Notes:
- **`target_uri`** is a *configured canonical value*, not derived from the request `Host` (which
  varies across proxies/LBs). Boot-validate it: a non-`Uri.normalize`-stable / non-https value fails
  at SIGN time on the edge; surface it as a loud startup failure, not a 401 storm. The single-
  environment round-trip test cannot catch edge↔verifier config drift — operations must keep them
  in sync.
- **`cast_arguments`** is the WHOLE report body decoded into BAP's public tagged `Json.value()`
  tuple form via `BoundedAuthorityProtocol.V1.Json.decode/1` — the only public way to obtain it.
  Both sides decode the SAME raw bytes with the SAME function ⇒ byte-agreement by construction.
  (`definition_version` is an integer ⇒ its tagged form is `{:integer, n}`, not a string.)
- **`operation`** is a *normative* contract constant: this guide declares it AND the issuer's grant-
  issuance flow must mint it. A mismatch fails closed (401) — so the prod coordination between this
  constant and the issued grant is a contract the issuer must honor.

## 4. Call the verifier — ONE `with`, fail closed (the COMPLETE safe path)

This is the canonical example. It is **not** optional: it includes the identity binding (§8) — a
consumer copy-pasting only the crypto-verify (without the binding) ships a verifier open to
cross-identity replay. Bind the verified envelope to the authenticated identity in the SAME `with`.

```elixir
# raw_body: the request's RAW bytes (retained via the endpoint body_reader). The whole verify is
# ONE `with`: a BAP-strict decode failure (Jason-valid-but-BAP-invalid body — duplicate keys,
# number bounds), a check_envelope failure, AND an identity-binding mismatch ALL collapse to
# {:error, _} -> :invalid. Decode any configured bytes (the issuer public key) NON-BANG inside
# the `with` (or boot-validate them) so a malformed config also fails closed. Do NOT use a bare
# `{:ok, x} = Json.decode(...)` match — it raises on a decode failure (500), breaking the
# uniform-reject posture.
with {:ok, cast_arguments} <- BoundedAuthorityProtocol.V1.Json.decode(raw_body),
     {:ok, facts} <-
       BoundedAuthorityProtocol.V1.check_envelope(
         %BoundedAuthorityProtocol.V1.Credentials{grant: grant, proof: proof},
         %BoundedAuthorityProtocol.V1.ExpectedRequest{
           trusted_issuer: %BoundedAuthorityProtocol.V1.TrustedIssuer{
             key_id: <configured issuer kid>,
             public_key: <configured 32-byte issuer public key>
           },
           issuer: <configured issuer URI>,
           audience: <configured audience>,
           method: "POST",
           target_uri: <configured canonical report URI>,
           invocation_id: <from X-BA-Invocation-Id>,
           operation: <the normative contract operation constant>,
           cast_arguments: cast_arguments,
           evaluation_time: System.system_time(:second),
           clock_skew: <configured>,
           proof_max_age: <configured>,
           nonce: {:required, <from the report-nonce header>},
           bounds: BoundedAuthorityProtocol.V1.Bounds.maximum()
         }
       ),
     # REQUIRED (§8): bind the verified envelope to the AUTHENTICATED identity, not just "some
     # holder." returns :ok | {:error, _} — NOT a boolean (a `?`-suffix boolean never matches
     # :ok <- and rejects EVERY request). See §8 for the thumbprint helper.
     :ok <- bind_holder_to_identity(facts.holder_thumbprint, authenticated_identity) do
  :ok       # the envelope verifies AND is bound to this identity — accept
else
  _ -> :invalid   # reject (your uniform auth-failure body; no discrimination between causes)
end
```

On the edge side, the agent obtains the SAME typed form BEFORE calling `sign_report/3`:
`cast_arguments = V1.Json.decode(raw_report_body_bytes)` (the adapter takes `cast_arguments` already
typed as `Json.value()`; it does not type a raw map). The contract is symmetric.

## 5. Fail closed — uniform, value-free

`{:error, :invalid}` ⇒ reject (401 or your surface's uniform auth-failure status). **Collapse every
BA failure to the SAME closed body your other auth failures use** — the response must not
discriminate "bad grant" from "bad proof" from "wrong key" from "malformed body" from "decode
failure." An attacker learns nothing about which factor failed. Telemetry, if any, is value-free
(an org/tenant id only — no grant/proof/signature bytes).

`BoundedAuthorityProtocol.V1.check_envelope/2` and `Json.decode/1` are total (rescue-wrapped), so a
single `with` is sufficient for the decode + verify closure — PROVIDED struct construction (decoding
the configured issuer key, etc.) is also inside the `with` or boot-validated, so a malformed config
collapses to `:invalid` rather than raising.

## 6. Transition / coexistence with a legacy scheme

During a transition, reports may arrive under the legacy scheme OR the BA scheme. Discriminate by
the BA envelope's presence (both `X-BA-Grant` + `X-BA-Proof` ⇒ BA path; otherwise the legacy path,
unchanged). The legacy path stays byte-for-byte intact — a legacy reporter sees zero change. The
strongest attack class here is availability, not bypass: a MITM who strips BA headers off a BA
report routes it to the legacy path (where it has no legacy signature ⇒ reject); a MITM who injects
a stray BA header onto a legacy report routes it to BA (⇒ `:invalid` ⇒ reject). "Both present ⇒ BA"
minimizes the injection surface. Both cases fail closed.

## 7. Provenance

Record which scheme verified a durable row (a `signature_scheme` column carrying `ba_protocol_v1`
vs the legacy value), set by the plug from a crypto-verified assign — never from a wire/body field
(a reporter cannot self-label). A future verifier knows which envelope signed each row.

## 8. Bind the envelope to the authenticated identity (REQUIRED — cross-identity replay)

`check_envelope` verifies the grant + proof cryptographically — it proves *some* holder holds a
valid grant bound to the report. It does NOT prove the holder is the identity your transport
authenticated (the api_key / reporter / tenant). A captured envelope (the grant + proof ride every
report as headers) is **replayable under a different authenticated identity**: the verifier accepts
the valid envelope, and if your replay-protection is keyed to the transport identity (e.g. a per-org
nonce ledger), it does not collide cross-identity → the captured envelope is accepted once per
identity, writing the original body into the replaying identity's scope. This is a real
cross-tenant/cross-identity authorization gap; the transport-authenticated identity must be bound
to the verified capability.

**The binding (DPoP-shaped):** the grant is issued to a holder key thumbprint (`cnf.jkt`); the
identity you authenticate (the reporter) holds an Ed25519 key. Bind them: after `check_envelope`
succeeds, assert the grant's bound holder thumbprint (`EnvelopeFacts.holder_thumbprint`) equals the
thumbprint of the authenticated identity's own key. Then a captured envelope verifies ONLY for the
identity whose key the grant was issued to — a replay under a different identity's api_key is
rejected (different key ⇒ thumbprint mismatch ⇒ `:invalid` ⇒ the uniform reject). This restores
parity with a body-signature scheme (which is bound to the reporter's key by construction).

```elixir
# bind_holder_to_identity/2 returns :ok | {:error, _} (NOT a boolean — a `?`-suffix boolean
# never matches :ok <- and rejects every request). The thumbprint helper is the PUBLIC
# BoundedAuthorityProtocol.V1.Jwk.public_key_thumbprint_raw(raw_key, %{}) — do NOT roll your
# own RFC-7638 thumbprint; use this one so the comparison is raw-32-byte to raw-32-byte.
defp bind_holder_to_identity(bound_holder_thumbprint, identity) do
  with {:ok, identity_raw_key} <- identity_ed25519_raw_key(identity),
       {:ok, identity_thumbprint} <-
         BoundedAuthorityProtocol.V1.Jwk.public_key_thumbprint_raw(identity_raw_key, %{}) do
    if identity_thumbprint == bound_holder_thumbprint, do: :ok, else: {:error, :not_bound}
  end
end
```

verifier application instance #1 implements this: the reporter's stored Ed25519 key (the same one the S1 body-
signature verifies against) IS the BA holder key, and `ReportSignature` asserts
`facts.holder_thumbprint == Jwk.public_key_thumbprint_raw(reporter_raw_key, %{})` (a cross-
identity-replay tripwire proves it red). A consumer that does NOT bind the envelope to the
authenticated identity carries the cross-identity-replay gap — do not enable BA without this binding.

## 9. Dedupe nonces (a replay ledger is a consumer obligation)

`check_envelope` checks the proof's nonce EQUALS the expected nonce (`nonce_matches?/2` →
`secure_equal/2`) — it is **stateless and does NOT dedupe**. So a byte-identical captured request
(same identity, valid signature, binding passes) is accepted AGAIN until `proof_max_age` expires —
same-identity replay within the proof window. The consumer MUST keep a replay ledger (a unique
constraint on `(identity, nonce)` — verifier application keys it `(org_id, nonce)`) and reject a seen nonce.
Nonce uniqueness is NOT something the protocol package does for you; it is a consumer obligation,
alongside the §8 identity binding.


