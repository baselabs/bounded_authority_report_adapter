# Strategy — Bounded Authority Report Adapter

**Status:** Governing — reconciled 2026-08-24 to the shipped API and public package (original
2026-08-09 draft) · **Companion to:** `docs/charter.md` (the what),
`docs/ROADMAP.md` (the build order). This doc carries the *how* and *why* of the
engineering + release posture.

## 1. Release posture: public package, private source repository

The owner superseded the original private-not-Hex posture on 2026-08-20 (ADR
0004). `bounded_authority_report_adapter` 0.2.1 is public on Hex and consumes the
public `bounded_authority_protocol` Hex package. The adapter is pre-1.0 and every
release remains responsible for its own compatibility, conformance, provenance,
security, and clean-consumer evidence.

The GitHub source repository is still private even though the package metadata
points to it. That is an explicit incomplete source/registry alignment state, not
a public-source claim: anonymous source, tag, changelog, and documentation links
must be verified together before the repository is described as public. The
alignment work belongs to its own owner row and visibility/rule confirmation.
The `bounded_authority` runtime remains private/commercial and is not a library
dependency.

## 2. "Public" terminology

"Public" now means the actual registry and portable-contract boundary: BAP and
BARA are available from Hex. It does not mean their APIs are 1.0-stable, and it
does not make the private BA runtime public. Statements about public source must
remain separate until the source repository's visibility and immutable release
identities are aligned.

## 3. Dependencies — the edge-path constraint

The adapter's dependency graph is deliberately minimal and one-directional:

```
bounded_authority_report_adapter
        │
        └──► bounded_authority_protocol   (public Hex dep; the ONLY runtime dep)
```

- **The adapter depends only on the public protocol package.** This is the
  ROADMAP B2 acceptance clause ("the adapter depends only on the public protocol
  package on the edge path — no private runtime dependency"). The
  dependency-direction wall in verifier application (`dependency_direction_test.exs`) forbids
  verifier application from depending on anything that signs; this adapter is the thing that
  signs, so it lives outside verifier application and depends only on BAP.
- **The runtime (`bounded_authority`) is NOT a dependency.** The adapter signs
  with a holder key it already holds; it does not call the runtime at sign time.
  Grant issuance + revocation are out of band (the runtime talks to the verifier, not to this adapter).
- **No transport libs.** `replicant`/`capstan` stay free of protocol code; this
  adapter is called by the edge agent, not embedded in the transport.

A dependency-direction test in this repo's suite will prove the "only BAP"
constraint structurally (mirroring verifier application's wall).

## 4. Why a separate repo (not a module in verifier application or in BAP)

This is the most-asked design question, so stated plainly:

- **Not in verifier application:** verifier application must never sign (the dependency-direction wall).
  Putting the signer in the verifier app puts the holder key in the app's
  memory, collapsing the invariant that a compromised app cannot forge
  authority. B1 codified this; B2 honors it by living outside verifier application.
- **Not in BAP:** BAP is a pure verifier — it produces signing inputs but
  refuses to hold keys or sign (its charter). Folding signing into BAP would
  force every verifier (including third parties) to carry signing code.
- **Not in the runtime:** the runtime is a server; the whole point is the
  reporter signs *locally* on the edge, without a round-trip to the authority.
- **Therefore: a new composable lib.** Its single job is "BAP produces the
  bytes, this adapter signs them, hands back the envelope." Small, single-purpose,
  reusable by any BaseLabs edge agent that needs to sign application reports.

The cost (a repo for a small amount of code) buys the invariant. The invariant
is load-bearing: once the signing key is in the app, extracting it is a
re-architecture, not a refactor.

## 5. Cryptographic posture

- **Ed25519** for holder proofs + grants (matches BAP's `alg: EdDSA` closed
  header). The private key is held by the edge agent; only the public key +
  signatures cross the boundary.
- **Deterministic signing inputs** from BAP (`proof_signing_input`,
  `boundary_anchor_signing_input`, `grant_signing_input`,
  `key_transition_signing_input`) — the adapter does NOT construct canonical
  bytes itself; it calls BAP and signs what BAP returns. This keeps the wire
  format owned by the protocol package (single source of truth) and makes the
  adapter a thin glue layer across all four instantiations. In the
  `sign_report/3` flow the grant arrives issuer-signed as input and the
  adapter signs only the proof; grant signing is the issuer-role
  instantiation's concern (`sign_grant/3`, ADR-0007) (charter §2/§4).
- **`assemble_compact`** frames the signed result. The adapter does not roll its
  own envelope format.
- **Key custody** is the edge agent's responsibility (how it loads/secures the
  private key). This adapter takes a key handle + a report and returns an
  envelope; it does not mandate a key store.

## 6. Release cadence

- **0.2.x is public** — pre-1.0; compatibility follows the package's declared
  pre-1.0 policy and every change must retain conformance and release evidence.
- **1.0.0** — cut only when the public API, consumer evidence, source identity,
  and release operations meet the owner repository's 1.0 acceptance contract.
- Package publication and source-repository visibility are separate operations;
  neither may be inferred from the other.

## 7. Relationship to the sibling repos' release gates

This adapter inherits no release gate from BAP or the runtime — each repo runs
its own. But the adapter's conformance test is *defined by* BAP's published
vectors: if a reviewed BAP release changes the consumed surface in a way this
adapter's output no longer matches, the adapter's test goes red. That coupling
is intentional; the BAP Hex requirement and resolved lock in this repository
are the explicit identities that gate an adapter bump.
