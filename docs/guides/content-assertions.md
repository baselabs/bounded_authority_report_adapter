# Content assertions

`sign_content_assertion/3` signs the exact-byte digest of content plus issuer, audience,
subject, profile, profile digest, generation, predecessor and validity window. Its result
is `{:ok, %{content_assertion: compact}}`. It neither reads content nor grants authority.
The consumer computes its own digest from the bytes it has and verifies the assertion
with `BoundedAuthorityProtocol.ContentAssertion.V1.verify_assertion/2` and explicitly
trusted historical public keys and context.

Generation 1 uses an all-zero predecessor. Later assertions link to the exact prior
assertion digest; lineage and application interpretation belong to the consumer. The
profile digest identifies semantics; it is not an instruction to fetch or execute code.
A valid assertion is evidence of the stated content binding, not permission to use it.
Select the suite before signing or verifying. The Ed25519 signer uses `key_identity/1`.
`BoundedAuthorityReportAdapter.V3.sign_content_assertion/3` uses `key_snapshot/1` to
capture an immutable P-256 signing reference. Verify its output with
`BoundedAuthorityProtocol.ContentAssertion.ES256.V1.verify_assertion/2`.
The ES256 backend hashes the exact JWS input once with SHA-256 and returns raw
`r || s`. The signer normalizes low-S and verifies the compact against the captured
key. A suite change starts a new lineage.

Run the [content notebook](../notebooks/content-assertions.livemd) for the Ed25519
content workflow. See [action approvals](framework-integration.md#12-sign-and-verify-an-action-approval)
for a signed content profile.
