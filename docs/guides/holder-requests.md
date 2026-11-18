# Holder requests

A holder proof binds the issuer's grant to the holder key, operation, method, canonical
endpoint, typed arguments, invocation id, nonce and proof time. The adapter signs the
proof and preserves the supplied grant. It does not verify the grant's issuer trust,
authorize its use or contact a verifier. See the [first integration](getting-started.md).

## Typed arguments and transport

Decode raw request bytes with `BoundedAuthorityProtocol.V1.Json.decode/2` before signing.
The receiver decodes the bytes it receives and executes those verified typed values.
Whitespace that decodes to the same JSON value has the same binding; a changed value
fails. Never verify an input then execute a differently cast map. Exact-byte content
identity belongs to [content assertions](content-assertions.md).

The target URI is an already canonical configured endpoint, never a client-supplied Host
header. Choose the [suite](key-custody.md#signature-suites) and accepted profile at boot.
A fresh proof cannot authorize a wider operation than the issuer's grant.

## Execution identity

Generate a canonical lowercase dashed UUID for each invocation. Retries reuse that id and
consult the host execution record; changing the nonce or proof must not repeat an effect.
Pure verification retains nothing. The host reserves nonce and invocation replay identities
atomically after identity, policy and revocation checks, as described in
[framework integration](framework-integration.md#11-complete-host-admission-before-any-effect).

Run the [holder request notebook](../notebooks/holder-request.livemd) for successful
verification, changed-context refusal, another holder and malformed input.
