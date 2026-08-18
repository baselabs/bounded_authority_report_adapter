# Strategy — Bounded Authority Report Adapter

**Status:** Governing — reconciled 2026-08-15 to the shipped API (original
2026-08-09 draft) · **Companion to:** `docs/charter.md` (the what),
`docs/ROADMAP.md` (the build order). This doc carries the *how* and *why* of the
engineering + release posture.

## 1. Repo posture: private, not hex-published

**Decision (owner directive 2026-08-09):** this is a **private BaseLabs GitHub
repo**, consumed via private git dep, **not published to hex.**

The rationale matches the sibling repos:
- `bounded_authority_protocol` is private because its API is still being tuned
  against the first real consumers; publishing to hex signals a stability
  contract that does not yet hold.
- `bounded_authority` (runtime) is private because it is a service, not a library.
- **This adapter** is private for the same reason as the protocol package: it is
  a new library whose API will be exercised + tuned by the first consumers
  (verifier application's report path first), and publishing prematurely would freeze a
  shape that should still be malleable.

**Hex publication is deferred** until the adapter has been consumed across the
BaseLabs projects that need it, the conformance round-trip is stable, and the
API has survived at least one external (non-Elixir) consumer's re-implementation
against the documented format. Flipping private → public later costs nothing
structurally (the git dep stays valid); publishing-then-revoking costs
reputation + semver.

## 2. "Public" terminology — the inter-repo API, not the registry

When the docs (this repo's charter, BAP's docs, verifier application's ADRs) call
`bounded_authority_protocol` "public," that means **the API contract between
BaseLabs repos that depend on it — NOT hex-published, NOT available to the
world.** It is fetched via a private git dep. The same sense applies to this
adapter: its surface is an inter-repo API for BaseLabs consumers. Do not
`mix hex.publish` either package.

## 3. Dependencies — the edge-path constraint

The adapter's dependency graph is deliberately minimal and one-directional:

```
bounded_authority_report_adapter
        │
        └──► bounded_authority_protocol   (private git dep; the ONLY dep)
                   │
                   └──► (standard hex deps: :crypto, etc.)
```

- **The adapter depends only on the public protocol package.** This is the
  ROADMAP B2 acceptance clause ("the adapter depends only on the public protocol
  package on the edge path — no private runtime dependency"). The
  dependency-direction wall in verifier application (`dependency_direction_test.exs`) forbids
  verifier application from depending on anything that signs; this adapter is the thing that
  signs, so it lives outside verifier application and depends on nothing private except BAP.
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

- **0.x** — pre-1.0; breaking changes allowed between minor bumps (SemVer
  pre-1.0 freedom). The API tunes against the first consumers.
- **1.0.0** — cut when (a) the conformance round-trip is stable, (b) at least
  one non-Elixir consumer has re-implemented against the documented format
  successfully, and (c) the checkpoint-ack probe has resolved (landed or
  formally deferred).
- **No hex publish before 1.0.0.** Private git deps throughout.

## 7. Relationship to the sibling repos' release gates

This adapter inherits no release gate from BAP or the runtime — each repo runs
its own. But the adapter's conformance test is *defined by* BAP's published
vectors: if BAP's vectors change in a way this adapter's output no longer
matches, the adapter's test goes red. That coupling is intentional (the adapter
tracks BAP's wire format); the BAP pin in `mix.exs` is the explicit ref that
gates when an adapter bump is required.
