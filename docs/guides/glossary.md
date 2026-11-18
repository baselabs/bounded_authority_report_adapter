# Glossary

| Term | Meaning |
|---|---|
| Grant | Issuer-signed constraints binding operations and context to a holder public-key thumbprint. |
| Holder proof | Holder signature over a grant and expected request binding. |
| Envelope | Unchanged issuer grant plus holder proof; not an execution credential. |
| Handle | Callback module plus opaque reference into caller-owned custody. |
| Issuer role | A callback declaration checked locally, not independent issuer authorization. |
| Trusted issuer | Public key and context enrolled by the verifier's host through its trust model. |
| Facts | Pure verification evidence against supplied trust and context, with no live authorization. |
| Invocation | Host execution identity that remains stable across retries and fresh proofs. |
| Nonce | Proof/challenge replay identity whose successful consumption the host records atomically. |
| Anchor | Signed consumption-chain boundary evidence; no live replay reservation. |
| Key transition | Historical key lineage evidence; not automatic rotation or revocation. |
| Content assertion | Signature binding an exact content digest and lineage to expected context. |
| Contract major | Explicit suite/wire contract: Ed25519 major 1 or ES256 major 3 here. |
| ES256 | ECDSA on P-256 using SHA-256 and canonical low-S raw signatures on the wire. |
