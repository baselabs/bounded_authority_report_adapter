# 6. Universal companion-signer scope

Date: 2026-08-10

## Status

Accepted. Records the scope decision that the 2026-08-10 universal-reframe (user
directive) settled; supersedes the narrow "holder-side proof-signer" framing in
ADR-0001/0002 (those are reconciled in place, not abandoned).

## Context

ADR-0001 framed this library as "the holder-side signer" and ADR-0002 as
"signs ONLY the proof." Both were written against the verifier application consumer
pattern (one app's topology). The 2026-08-10 alignment work surfaced that this
library is better understood — and must be designed — as BAP's **universal
companion signer**: BAP produces the signing input for every protocol object
(proof, grant, boundary anchor, key transition) and refuses to sign; this library
takes a key-handle + a BAP signing input and signs it, usable by whichever party
holds the right key.

The narrow framing was correct *for RA1's envelope flow* but wrong as the library's
identity. Anchoring it to one app's topology (verifier application can't sign; the runtime is
issuer-only) would cripple the library to fit a deployment that, if wrong, is the
deployment's job to fix — not the public library's.

## Decision

1. **The library signs BAP protocol objects via the shared pattern** — resolve the
   key(s) from the handle, produce the BAP signing input, sign via the handle, verify
   the signature against the resolved key, assemble via BAP. The signing tail
   (`sign_via_handle → verify_signature → assemble_compact`) is the universal primitive;
   every object flows through it.
2. **Instantiations:** proof signing (`sign_report/3`, RA1); boundary-anchor signing
   (`sign_anchor/3`, RA4). The pattern generalizes; grant/key-transition signing are
   named extensions.
3. **Key-identifier sourcing:** the signing key's identifiers (`public_key`, and for
   anchors the signed-header `key_id`) come from the **handle**, never from caller input —
   so the signed key-identifiers are consistent with the key `sign/2` actually used.

## The grant-signing pre-commitment (load-bearing)

Grant signing is a named future extension, **not** unconstrained. A grant is the
issuer's authority assertion; ADR-0002's C1 correction is that the **holder** signing a
grant inverts the authority model. Therefore any future `sign_grant` slice:

- is **issuer-role-only** — invoked with an issuer key, never a holder key in the
  grant+proof envelope flow; and
- carries a tripwire (the `CountingKeyHandle` form, `sign_report_test.exs:120-132`) that
  gates holder-key grant-signing **red**.

Without this pre-commit, a future implementer could recreate C1 inside this library.
Grant signing is **design-gated** on this role reconciliation, not merely schedule-deferred.

## Consequences

- The library is "hand-in-glove" with BAP: BAP produces the bytes for any protocol
  object; this library signs them. New objects land as new `sign_*` functions sharing the
  tail, each with its own validation + tripwires.
- ADR-0001's "the adapter is the HOLDER" is reconciled to "the holder is one
  role/instantiation"; the 3-role table remains correct for the envelope flow.
- ADR-0002's "proof-only" is sharpened to an envelope-flow property ("in the envelope,
  the holder signs the proof, not the grant"), not a library-wide prohibition.
- The key-handle contract gains an **optional** `key_identity/1` callback
  (`@optional_callbacks`), required only by `sign_anchor/3` *(Amended 2026-08-15:
  and, since RA8, by `sign_key_transition/3` — ADR-0009)*, which resolves
  `{key_id, public_key}` as ONE atomic snapshot (defense-in-depth: a rotation
  race cannot split `kid` from `public_key`; any `sign/2`-vs-snapshot mismatch is
  caught by the `verify_signature` guard).
