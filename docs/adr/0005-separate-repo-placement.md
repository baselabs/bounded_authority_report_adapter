# 5. Separate-repo placement

Date: 2026-08-10

## Status

Accepted. Records strategy §4; in force since the scaffold. Authored
retroactively when the ADR gap was flagged by the 2026-08-10 alignment audit.

## Context

The holder-side signing code (ADR 0001) has to live *somewhere*. Four candidate
homes were considered: inside a verifier, inside BAP (the
protocol package), inside the runtime (the issuer service), or a new repo. The
first three each collapse an invariant the bounded-authority model depends on.

## Decision

A new composable library — `bounded_authority_report_adapter` — is the holder's
home. The rejected alternatives, each with the invariant it breaks:

- **Not in a verifier.** A verifier must never sign.
  Putting the signer in the verifier app puts the holder key in the app's
  memory, collapsing the invariant that a compromised app cannot forge authority.
- **Not in BAP.** BAP is a pure verifier — it produces signing inputs but refuses
  to hold keys or sign (its charter). Folding signing into BAP would force every
  verifier (including third parties) to carry signing code they do not need.
- **Not in the runtime.** The runtime is a server; the whole point is the
  reporter signs *locally* on the edge, without a round-trip to the authority.

## Consequences

- The cost (a repo for a modest amount of code) buys the invariant: once the
  signing key is in the verifier app, extracting it is a re-architecture,
  not a refactor.
- The adapter is small, single-purpose, and reusable by any holder
  that needs to sign protocol objects — "BAP produces the bytes, this adapter signs
  them, hands back the envelope."
- The dependency-direction wall (ADR 0003) holds symmetrically on both sides:
  verifiers do not depend on this adapter, and this adapter depends only on BAP.
