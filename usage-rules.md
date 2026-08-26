# Usage rules

1. Treat `sign_report/3` output as a cryptographic artifact, not an authorization decision.
   The envelope proves the holder signed THIS report under THAT grant — whether the action
   is allowed is the verifier's authority decision ([consumer integration
   §8](docs/consumer-integration.md)).
2. The private key never enters this library. You hold it behind a `{module, term}` key
   handle implementing the `BoundedAuthorityReportAdapter` behaviour (`sign/2`,
   `public_key/1`, `thumbprint/1`, `key_identity/1`, `signing_identity/1`). If you find
   yourself passing key bytes INTO the adapter, the integration is wrong — see
   [Getting started](docs/getting-started.md).
3. `sign_grant/3`'s role gate is declaration-rejection, NOT cryptographic role separation.
   A handle whose `signing_identity/1` does not resolve `{:issuer, _, _}` is rejected with
   `:invalid_key_handle` BEFORE `sign/2` is called — but a handle that consistently lies
   (returns `:issuer` while holding a holder key) passes the gate. Key-role separation is
   a custody property, not something this gate adds to. (ADR-0006/0007.)
4. Never trust caller-supplied `key_id` or `public_key` content. `sign_anchor/3` and
   `sign_key_transition/3` resolve BOTH key identifiers from ONE atomic `key_identity/1`
   snapshot on the handle — a caller-supplied `:current_key_id` is ignored. Keep it that
   way: a caller-named kid over a differently-signed anchor is the forgery that shape
   enables.
5. Pin `:issued_at` (and `:anchored_at`) when the verifier's evaluation time is far from
   your wall clock. The default is `System.system_time(:second)` — replayed tests and
   offline flows against a pinned `evaluation_time` need the explicit option, or the
   proof falls outside `proof_max_age`.
6. `cast_arguments` must be BAP's tagged `Json.value()` form, produced by
   `BoundedAuthorityProtocol.V1.Json.decode/1` of the SAME raw bytes on BOTH sides. A
   raw map is rejected; feeding the two sides DIFFERENT bytes (or a re-encoding, instead
   of the original bytes) is the divergence this rule prevents — same bytes + same
   deterministic decode is byte-agreement by construction
   ([consumer integration §3–§4](docs/consumer-integration.md)).
7. Consumer-side identity binding and nonce-ledger replay protection are obligations, not
   options. This library signs; the consuming verifier must bind the holder thumbprint to
   its own identity source and dedupe nonces ([consumer integration
   §8/§9](docs/consumer-integration.md)).
8. Errors are closed atoms — there is no value-echoing. `{:producer_error, :invalid}` is
   exactly that tuple; key ids, message bytes, and report content never appear in an
   error. Do not wrap losses into logs by inspecting inputs on failure — the atoms are
   the whole story ([Errors](docs/errors.md)).
9. A signature that does not verify against the resolved public key is `:signing_failed`
   — the wrong-key guard runs on EVERY object. If your handle signs with a different key
   than `public_key/1` reports, you get a red, never a false success. Fix the handle,
   never the guard.
10. Attach telemetry BEFORE the first production sign if you want the custody alarm:
    `[:bounded_authority_report_adapter, :sign, :stop]` with `result_class:
    :signing_failed` is the custody-misconfiguration signal. Metadata is value-free;
    never extend it with key material ([Telemetry](docs/telemetry.md)).
11. Pin the protocol dependency and treat a version bump as a reviewed change — the
    dependency-direction wall pins the locked version, and a silent `mix deps.update`
    crosses an unreviewed protocol span (ADR-0010).
12. Production handles never come from this library. The `{pub, priv}` reference handle
    in the source repo's `test/support/` is TEST-ONLY and deliberately not shipped in the
    package — shipping it would pave the road to exactly the custody failure the separate
    key-handle contract exists to prevent (design C5, ADR-0014).

See [Getting started](docs/getting-started.md), [Errors](docs/errors.md),
[Telemetry](docs/telemetry.md), and
[Consumer integration](docs/consumer-integration.md) for the long forms.
