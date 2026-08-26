# Errors

Every entry point returns either `{:ok, map}` or `{:error, reason}` where `reason` is a
closed atom (or one fixed tuple). There is no value-echoing: no key ids, no message
bytes, no report content ever appear in an error — an atom is the whole story.

The four error sets are identical except for their per-object input atom:

| Entry point | Input atom | @type |
|---|---|---|
| `sign_report/3` | `:invalid_report` | `sign_error/0` |
| `sign_anchor/3` | `:invalid_anchor` | `anchor_sign_error/0` |
| `sign_grant/3` | `:invalid_grant` | `grant_sign_error/0` |
| `sign_key_transition/3` | `:invalid_transition` | `transition_sign_error/0` |

## The shared atoms

| Atom | Meaning | What to check | Recovery |
|---|---|---|---|
| `:invalid_key_handle` | The handle is malformed (`{module, term}` shape, defined module), or a handle callback (`public_key/1`, `key_identity/1`, `signing_identity/1`) rejected, returned an invalid value (e.g. a non-32-byte public key), or exited/raised. For `sign_grant/3` this ALSO covers the C1 role gate: a handle that does not resolve `{:issuer, _, _}`. | The handle module implements the full `BoundedAuthorityReportAdapter` behaviour; the handle term is what its callbacks expect; (grants) the handle really is the issuer's. | Fix the handle wiring. This is never caller-input — it is your key custody configuration. |
| `:signing_failed` | The `sign/2` callback rejected, violated its `{:ok, binary} \| {:error, term}` contract, returned a non-64-byte signature, OR the signature did not verify against the resolved public key (the wrong-key guard). | Whether `public_key/1`/`key_identity/1` describe the SAME key `sign/2` actually uses; whether the HSM/KMS call is healthy. | Fix the custody side. A sustained rate of this is the custody-misconfiguration alarm — see [Telemetry](telemetry.md). |
| `{:producer_error, :invalid}` | The protocol's producer or assembler rejected the signing input — a bound or field constraint (bad URI shapes, out-of-bounds sizes, a self-transition, a non-`Json.value()` `cast_arguments`). | The input map against the entry point's `@type` and the protocol's V1 field contracts; `cast_arguments` is the tagged form from `V1.Json.decode/1`. | Fix the caller's input. |

## The per-object input atoms

| Atom | Meaning | What to check | Recovery |
|---|---|---|---|
| `:invalid_report` | A required `report` field is missing or malformed (`grant_compact`, `operation`, `method`, `target_uri`, `invocation_id`, `cast_arguments`, `nonce`), or `cast_arguments` is `nil`. | The map against `report()` in the moduledoc; `cast_arguments` is BAP's tagged form, never a raw map. | Fix the report fields. |
| `:invalid_anchor` | An `anchor_input` content field is missing, or `chain_hash` is not 32 bytes (the zero hash only fits `sequence == 0`). | `anchor_id`, `chain_id`, `sequence`, `chain_hash`. | Fix the anchor fields. |
| `:invalid_grant` | A `grant_input` field is missing/malformed, the time window is inverted, `holder_thumbprint` is not a raw 32-byte thumbprint, or `operations` is empty. | `issuer`, `grant_id`, `audiences`, `issued_at`/`not_before`/`expires_at`, `holder_thumbprint` (raw, from `V1.Jwk.public_key_thumbprint_raw/2`), `operations`. | Fix the grant fields. |
| `:invalid_transition` | A `transition_input` field is missing, or `next_public_key` is not a 32-byte Ed25519 key. | `transition_id`, `chain_id`, `effective_at`, `next_key_id`, `next_public_key`. | Fix the transition fields. |

## Where the atoms live

Each set is a `@type` on `BoundedAuthorityReportAdapter`
(`sign_error/0`, `anchor_sign_error/0`, `grant_sign_error/0`, `transition_sign_error/0`)
— dialyze your caller against them. A doc-currency test (this file ↔ the `@type`s) runs
in the library's suite, so a table row and a type cannot drift apart silently.
