# Cheatsheet

| Task | Entry point / requirement |
|---|---|
| Sign holder request | `BoundedAuthorityReportAdapter.sign_report/3`; preserve grant, return grant and proof. |
| Sign issuer grant | `BoundedAuthorityReportAdapter.sign_grant/3`; `signing_identity/1` declares issuer. |
| Sign anchor / rotation | `sign_anchor/3` / `sign_key_transition/3`; immutable `key_identity/1`. |
| Sign content | `sign_content_assertion/3`; exact content digest, explicit profile and lineage. |
| Use ES256 | Explicit `BoundedAuthorityReportAdapter.V3` module; raw 64-byte signature. |
| Use loopback | Explicit `sign_local_loopback_report/3`; mandatory server challenge. |
| Compute thumbprint | `public_key_thumbprint/1` returns `{:ok, <<_::256>>}` or `{:error, :invalid}`. |
| Diagnose handle | Doctor `check/3` or `check/4`; inspect fatal/advisory lists, not message wording. |
| Observe signing | Attach to signing start/stop; only object and result class as metadata. |
| Execute request | Host authenticates, verifies/binds, authorizes, checks live revocation, atomically admits and executes. |

All signing options accept a map or unique-key keyword list; absent options mean `%{}`.
Unknown keys, nil and malformed values fail closed. Use [errors](errors.md),
[custody](key-custody.md) and [operations](operations.md) for the complete contract.
