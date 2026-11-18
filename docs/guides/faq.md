# FAQ

## Is a verified envelope authorization?

No. Facts have `authorization: :not_evaluated`. The host owns policy, identity binding,
current revocation, replay admission and execution. See [framework integration](framework-integration.md).

## Does the adapter verify anything?

It self-verifies each signature it produces against the resolved public key and can verify
an Ed25519 issuer-role attestation. It is not a general credential verifier; the protocol
package supplies that API.

## Can a holder declare itself an issuer?

A callback can declare `:issuer`; the adapter cannot determine whether that declaration
is authorized. Keep issuer keys in issuer custody. Receivers trust independently enrolled
issuer keys. An optional Ed25519 attestation adds a check against an explicitly trusted
attestor; V3 refuses that option.

## Do single-use challenges prevent interception?

They allow only one consumption. An interceptor can arrive first and deny the legitimate
sender. Use authenticated confidential transport and appropriate local isolation.

## Are all errors atoms?

No. Signing errors include atoms and `{:producer_error, :invalid}`. The thumbprint helper
returns `{:error, :invalid}`. Doctor helpers return reports or strings/nil; see [errors](errors.md).

## Can I put private bytes in the opaque handle?

Do not. Opaque means the adapter does not inspect the reference, not that it secures key
bytes in that reference. Use an immutable reference to custody behind callbacks.

## Which earlier major can I upgrade from?

1.x is the first stable major. The [upgrade guide](upgrading.md) covers the pre-1.0
transitions and the 1.0 stability boundary; no released earlier stable major exists.
