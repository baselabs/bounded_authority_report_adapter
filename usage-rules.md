# Usage rules

1. Treat `sign_report/3` output as a cryptographic artifact, not an authorization decision.
   The envelope proves the holder signed this request under that grant; whether the action
   is allowed is the verifier's decision ([consumer integration
   §8](docs/consumer-integration.md)).
2. The private key never enters this library. Keep it behind a `{module, term}` key handle
   implementing the `BoundedAuthorityReportAdapter` behavior (`sign/2`, `public_key/1`,
   `thumbprint/1`, and as needed `key_identity/1` and `signing_identity/1`). If you find
   yourself passing key bytes into the adapter, the integration is wrong; see
   [Getting started](docs/getting-started.md).
3. `sign_grant/3` signs only for a handle whose `signing_identity/1` declares
   `{:issuer, _, _}`; any other handle gets `:invalid_key_handle` before `sign/2` is called.
   The adapter cannot check that the declaration is true: a handle that returns `:issuer`
   for a holder's key passes. Keep issuer keys in issuer custody, or pass the
   `:role_attestation` option so the role must also be backed by a role attestation that
   `BoundedAuthorityProtocol.RoleAttestation.V1.verify_attestation/2` accepts.
4. Never trust caller-supplied key ids or public keys. `sign_anchor/3`,
   `sign_key_transition/3` and `sign_content_assertion/3` read the key id and public key
   from one `key_identity/1` call, and `sign_grant/3` from one `signing_identity/1` call;
   a key id in the input (`:key_id`, `:current_key_id`) is ignored. Keep it that way: an
   object that names one key while signed by another is the forgery that shape enables.
5. Set `:issued_at` (and `:anchored_at`) when the verifier's evaluation time is far from
   your wall clock. The default is `System.system_time(:second)`; tests and offline flows
   that verify at a fixed `evaluation_time` need the option, or the proof falls outside
   `proof_max_age`.
6. `cast_arguments` must be the protocol's tagged `Json.value()` form, produced by
   `BoundedAuthorityProtocol.V1.Json.decode/2` from the same raw bytes on both sides. A
   raw map is refused (`{:producer_error, :invalid}`). Decoding different bytes on the two
   sides, or a re-encoding instead of the bytes sent, is the mismatch this rule prevents
   ([consumer integration §3 and §4](docs/consumer-integration.md)).
7. Identity binding and a nonce ledger are verifier obligations, not options. This library
   signs; the verifier must bind the holder thumbprint to the identity it authenticated
   and reject a nonce it has seen ([consumer integration §8 and
   §9](docs/consumer-integration.md)).
8. Errors are closed atoms with no values. `{:producer_error, :invalid}` is exactly that
   tuple; key ids, message bytes and report content never appear in an error. Do not add
   them back by logging the inputs on failure ([Errors](docs/errors.md)).
9. A signature that does not verify against the handle's public key is `:signing_failed`;
   the check runs on every object. If your handle signs with a different key than
   `public_key/1` reports, you get an error, never a bad signature. Fix the handle.
10. Attach telemetry before the first production signing call if you want the custody
    alarm: `[:bounded_authority_report_adapter, :sign, :stop]` with
    `result_class: :signing_failed`. Metadata carries no values; never extend it with key
    material ([Telemetry](docs/telemetry.md)).
11. Review protocol upgrades. This package declares a range of compatible
    `bounded_authority_protocol` releases; your application's `mix.lock` decides which one
    you run. Read the protocol's changelog before moving that lock.
12. Production handles never come from this library. The reference handles in the source
    repository's `test/support/` hold private keys in memory, are test-only, and are not
    shipped in the package.
13. The local-loopback profile is an explicit decision, never an inference.
    `sign_local_loopback_report/3` is the only way to produce `ba+loopback-proof` bytes;
    there is no profile option on `sign_report/3`, and nothing detects the transport for
    you. The nonce is mandatory, only canonical `http://127.0.0.1` and `http://[::1]`
    targets sign, and the verifying host owns the nonce, replay control and the expected
    target. Loopback HTTP is not equivalent to HTTPS; see
    [Recipes](docs/recipes.md#recipe-the-local-loopback-development-listener).
14. A content assertion is not authorization. `sign_content_assertion/3` takes the twelve
    fields listed in its documentation, with raw 32-byte digests, and a handle with
    `key_identity/1`. It does not read the content, consume a role attestation or resolve
    trust. The consumer verifies with
    `BoundedAuthorityProtocol.ContentAssertion.V1.verify_assertion/2`, supplying the
    expected identifiers, digests, trusted key, time and bounds, and keeps its own state
    if it must reject replays or check a lineage.

See [Getting started](docs/getting-started.md), [Errors](docs/errors.md),
[Telemetry](docs/telemetry.md) and
[Consumer integration](docs/consumer-integration.md) for the long forms.
