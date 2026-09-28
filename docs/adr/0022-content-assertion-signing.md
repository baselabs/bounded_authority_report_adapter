# 22. Typed content-assertion signing and candidate qualification

Date: September 27, 2026

## Status

Accepted; released in 0.9.0 over BAP 0.7.0 (September 28, 2026). The ADR-0010
prerequisite named in Decision 6 was retired by
[ADR-0023](0023-pin-follows-bap-releases.md): BARA follows published BAP releases.

## Context

BAP's standalone `bap-content-assertion/1` profile defines a signed binding to
exact content and profile digests with explicit lineage fields and time bounds.
It owns the wire format, validation, deterministic signing input and verification.
BARA owns key-handle signing; consumers own content semantics, trusted-key
selection, durable lineage state and final policy decisions.

OBSERVED before 0.9.0: `rg -n 'bounded_authority_protocol' mix.exs mix.lock` resolved
BARA's exact dependency to BAP 0.6.0. That resolved `SigningInput` source lists
existing object kinds without content assertion. With this extension present,
`MIX_ENV=test mix compile --warnings-as-errors` exits 1 because
`BoundedAuthorityProtocol.ContentAssertion.V1.ContentAssertion.__struct__/1`
is unavailable in the resolved package. BAP 0.7.0, published September 28, 2026,
carries the API; 0.9.0 pins it and the default build compiles.

## Decision

1. Add `sign_content_assertion/3` to the existing major-1 signer. Its caller map
   supplies `jti`, `iss`, `aud`, `sub`, `profile`, `profile_digest`,
   `content_digest`, `gen`, `prev`, `iat`, `nbf`, and `exp`. Digests remain raw
   32-byte values. BAP fixes `v`; the signer supplies `attestor_key_id` from one
   atomic `key_identity/1` snapshot. Caller identity aliases cannot replace it.
2. Build the public typed `ContentAssertion` struct. Delegate semantic validation
   and bytes to BAP's `assertion_signing_input/2`. Sign through the existing shared
   signing tail, verify the returned signature against the snapshot public key,
   and assemble through this profile's `assemble_compact/3`, forwarding the same
   bounds to producer and assembler.
3. Keep this artifact role-agnostic. Grant signing's declaration and role-attestation
   gates retain their existing scope. Do not add schema parsing, content hashing,
   trusted-key lookup, agreement semantics, transport or business policy here.
4. Return `%{content_assertion: compact}`. Options must be a plain map; malformed
   options fail before signing. Missing or wrongly typed input members
   yield `:invalid_content_assertion`; malformed handles yield `:invalid_key_handle`;
   signer or wrong-key failures yield `:signing_failed`; BAP rejections yield
   `{:producer_error, :invalid}`. Telemetry adds only the closed object atom
   `:content_assertion`; the input error maps to `:invalid_input` without values.
5. Qualify preliminary source behavior using the actual compiled BAP candidate
   modules and BARA dependencies in a fresh Elixir VM, compiling BARA source in
   memory and running focused tests with real Ed25519 keys. Do not copy an
   application, replace released dependency declarations, substitute mocks, or
   infer immutable package compatibility from this working-tree check.
6. Before release, freeze the BAP corpus and qualify every independent SDK;
   identify exact immutable BAP and BARA candidates and retain their checksums
   and native verification receipts; produce assertions through the real BARA
   signer and consume them through an independent verifier. Update the released
   dependency in the repository's coordinated pin/lock/wall-test discipline
   (ADR-0023), run its declared gates on the exact candidate, and obtain owner
   approval for that release.

## Acceptance boundaries

The focused source tests cover signer-owned identity, exact BAP-produced bytes,
wrong-key signing, rotation after the atomic snapshot, every required member,
producer rejection before signing, signature tampering, and value-free telemetry.
Their executed receipt must identify the actual candidate bytes and command;
the test definitions themselves do not certify anything. At release the default
build pins the published BAP 0.7.0, `mix ci` passes on the release tree, and the
real signer's output is verified by an independent non-Elixir verifier against the
published packages.
