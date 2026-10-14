# Errors

Every entry point returns either `{:ok, map}` or `{:error, reason}`, where `reason` is a
closed atom or the one fixed tuple `{:producer_error, :invalid}`. Errors carry no values:
no key ids, no message bytes, no input content.

Each entry point has one input atom; the others are shared:

| Entry point | Input atom | Error type |
|---|---|---|
| `sign_report/3` | `:invalid_report` | `sign_error/0` |
| `sign_local_loopback_report/3` | `:invalid_report` | `sign_error/0` |
| `sign_anchor/3` | `:invalid_anchor` | `anchor_sign_error/0` |
| `sign_grant/3` | `:invalid_grant` | `grant_sign_error/0` |
| `sign_key_transition/3` | `:invalid_transition` | `transition_sign_error/0` |
| `sign_content_assertion/3` | `:invalid_content_assertion` | `content_assertion_sign_error/0` |

Every set also contains `:invalid_key_handle`, `:signing_failed` and
`{:producer_error, :invalid}`. `grant_sign_error/0` adds `:invalid_role_attestation`.

The `BoundedAuthorityReportAdapter.V3` entry points return the same atoms with the same
meanings, for P-256 keys; the differences are listed under [The V3 surface](#the-v3-surface).

## The shared errors

| Atom | Meaning | What to check | Fix |
|---|---|---|---|
| `:invalid_key_handle` | The handle is not a `{module, term}` pair; a handle callback the entry point needs (`public_key/1`, `key_identity/1` or `signing_identity/1`) is missing, failed, raised, threw or exited; or it returned an invalid value: an Ed25519 public key that is not 32 bytes or that the protocol's strict rule refuses (small-order, non-canonical, not on the curve), or an empty key id. For `sign_grant/3` it also means the handle did not declare the `:issuer` role. | The handle module implements the callbacks the entry point uses; the handle term is what those callbacks expect; for grants, the key really is the issuer's. | Fix the handle or the key-store connection. It is configuration, never caller input. |
| `:signing_failed` | `sign/2` failed, raised, threw or exited; returned something other than `{:ok, <<_::512>>}`; or returned a signature that does not verify against the public key the handle reported (the wrong-key guard). | Whether `public_key/1` and the identity callbacks describe the same key `sign/2` uses; whether the HSM or KMS call is healthy. | Fix the custody side. A sustained rate of this error is the custody alarm; see [Telemetry](telemetry.md). |
| `{:producer_error, :invalid}` | The protocol package refused to produce or assemble the signed object: a value violated a protocol rule or a bound. Examples: a target URI that is not canonical, an invocation id that is not a canonical UUID, a `cast_arguments` value that is not the protocol's tagged form, a digest of the wrong size, an inverted time window, a key transition to the same key. | The input values against the protocol's field rules; `cast_arguments` comes from `BoundedAuthorityProtocol.V1.Json.decode/2`. | Fix the input. |

## The input errors

The adapter checks input shape only: required fields are present and have the right basic
type. The protocol package checks values (digest sizes, time-window order, identifier
grammar, selectors) and reports them as `{:producer_error, :invalid}`. A field of the
right type but the wrong value is not one of these errors.

Each input atom also covers malformed options: every entry point takes its options as a
map or as a keyword list, and anything else is the entry point's input atom: a list that is
not a keyword list with unique atom keys (for example `[:bounds]`, or `:bounds` given
twice), or a value such as `nil`, an atom, a number, a tuple or a binary. Calling an entry
point without the options argument means `%{}`.

| Atom | Meaning | What to check | Fix |
|---|---|---|---|
| `:invalid_report` | The report is not a map; `grant_compact`, `operation`, `method`, `target_uri` or `invocation_id` is missing or not a string; `cast_arguments` is missing or `nil`; `nonce` is neither `nil` nor a string; or `grant_compact` is not a grant of the entry point's contract-major (major 1 for `sign_report/3`, major 3 for `V3.sign_report/3`). For `sign_local_loopback_report/3`, also a missing, empty or non-string `nonce`. | The map against the `report()` (or `local_loopback_report()`) type; the grant's major. | Fix the report fields, or use the entry point that matches the grant. |
| `:invalid_anchor` | The input is not a map; `anchor_id`, `chain_id` or `chain_hash` is missing or not a binary; or `sequence` is missing or not a non-negative integer. | The map against `anchor_input()`. | Fix the anchor fields. |
| `:invalid_grant` | The input is not a map; `issuer`, `grant_id` or `holder_thumbprint` is missing or not a binary; `issued_at`, `not_before` or `expires_at` is missing or not an integer; `audiences` is missing, empty, improper or not all strings; or `operations` is missing, empty or not a list. | The map against `grant_input()`. | Fix the grant fields. |
| `:invalid_role_attestation` | The `:role_attestation` option of `sign_grant/3` is malformed (including an explicit `nil`); the protocol package's `BoundedAuthorityProtocol.RoleAttestation.V1.verify_attestation/2` rejected it (attestor signature, subject, self-attestation, window containment, `now` outside `[nbf, exp)`); or the attested role is not `"issuer"`. On the `V3` surface, any `:role_attestation` option. | The compact is a `bap-role-attestation/1` attestation for the handle's own key; the attestor key and its validity window are the ones you trust; `now` is the time you mean. | Fix the attestation or the trusted attestor key. The subject always comes from the handle, never from the option. |
| `:invalid_content_assertion` | The options are neither a plain map nor a keyword list with unique keys (a struct is refused too), or a `sign_content_assertion/3` input field (`jti`, `iss`, `aud`, `sub`, `profile`, `profile_digest`, `content_digest`, `prev` as binaries; `gen`, `iat`, `nbf`, `exp` as integers) is missing or of the wrong type. | The map against `content_assertion_input()`; the options' shape. | Fix the input or the options. |
| `:invalid_transition` | The input is not a map; `transition_id`, `chain_id` or `next_key_id` is missing or not a binary; `effective_at` is missing or not an integer; or `next_public_key` is not a 32-byte binary (major 1) or a 65-byte P-256 point on the curve (`V3`). | The map against `transition_input()`. | Fix the transition fields. |

## The V3 surface

`BoundedAuthorityReportAdapter.V3`'s entry points use the atoms above, with P-256 rules:

- `:invalid_key_handle` when a public key is not a 65-byte uncompressed SEC1 P-256 point
  on the curve (an Ed25519 key included).
- `:signing_failed` also when `sign/2` returns a DER signature or a raw signature whose
  `r` or `s` is out of range. A high-S signature is not an error; the adapter converts it.
- `:invalid_report` when `grant_compact` is not a contract-major-3 grant.
- `:invalid_role_attestation` from `V3.sign_grant/3` whenever `:role_attestation` is
  present in the options: that surface has no role-attestation gate and refuses the option
  rather than ignore it. `V3`'s `grant_sign_error/0` type lists it.

## Where the error types live

Each set is a type on `BoundedAuthorityReportAdapter`: `sign_error/0`,
`anchor_sign_error/0`, `grant_sign_error/0`, `transition_sign_error/0` and
`content_assertion_sign_error/0`, with matching types on `BoundedAuthorityReportAdapter.V3`
for its four entry points. The test suite checks this page against the major-1 types.

## Local-loopback notes

`sign_local_loopback_report/3` uses `sign_error/0` unchanged. The adapter checks that the
nonce is present and a non-empty string; the protocol package checks the profile's rules.
A nonce over the bounds or not valid UTF-8, and a `target_uri` that is not a canonical
literal-loopback HTTP URI, are `{:producer_error, :invalid}`. The adapter never rewrites
the URI.
