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
This profile uses Ed25519 and the `key_identity/1` callback; the V3 surface has no content
assertion signer. Run the [content notebook](../notebooks/content-assertions.livemd) for
success, changed bytes, changed context and invalid input.
