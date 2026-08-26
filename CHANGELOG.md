# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Pre-1.0, `0.x` minor bumps may carry
breaking changes (SemVer §4).

## [Unreleased]

### Documentation

- Reconcile the governing charter, strategy, contributor guide, and examples to the live release
  state: 0.2.1 and its source are public, it consumes BAP from Hex, and the separate BA runtime
  remains a private commercial application that is never public-Hex-published and is not privately
  Hex-distributed because no paid private-package subscription exists. A future private BA release
  requires an active subscription and fresh approval for that exact release and destination.
- Remove private-consumer identifiers and deployment-specific topology from the tracked public
  surface and rewritten repository history; harden the hash-based gate over tracked files, commit
  messages, historical paths, every reachable commit snapshot, merge content, and annotated-tag
  messages.

### Added

- `mix bounded_authority_report_adapter.doctor --handle MyApp.HolderKey [--ref term]
  [--live]` — the handle-contract preflight (read/probe only, no side effects):
  FATAL on an unloaded module, a missing required callback (`sign/2`,
  `public_key/1`, `thumbprint/1`), or a `public_key/1` that does not return a
  32-byte key for the ref; ADVISORY on the operation-blocking optional callbacks
  (`key_identity/1` absent blocks anchors/transitions, `signing_identity/1`
  absent blocks grants) and, with `--live`, a wrong-key probe that signs a
  DOCTOR-GENERATED synthetic message and runs the adapter's own verify guard
  before the first real signing call. Every fatal check is RED-proven by a
  scratch module missing exactly that thing. Plus an invocation-id guidance
  section in getting-started (the UUID grammar gate and the
  fails-far-from-the-cause trap).
- Igniter installer: `mix bounded_authority_report_adapter.install --module MyApp.HolderKey`
  scaffolds a starter key-handle (all five callbacks present so the behaviour compiles
  clean; every body raises until you wire your custody store — nothing key-shaped is
  ever uncommented FOR you), imports the dep into the consumer's `.formatter.exs`, and
  carries the which-callback-matters-for-which-operation contract as comments.
  `:igniter` (~> 0.8) is an OPTIONAL dependency (unscoped, so consumer builds order it
  before this package and the real task compiles; without it the file compiles to a
  fallback task that raises with the one-line remedy). Smoke-verified end-to-end in a
  scratch consumer: install → wire a dev key → sign_report → check_envelope green.
- Governance surface: [CONTRIBUTING.md](CONTRIBUTING.md) (the per-file floor, the
  surgical-pathspec discipline, red-first + mutation-proof expectations, the bump
  policy pointer), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) (Contributor Covenant v2.1,
  the canonical text with the reporting contact substituted),
  [docs/upgrading.md](docs/upgrading.md) (per-version notes newest-first + the **1.0
  stability contract**: the public surface enumerated — the four signing functions and
  their return shapes, the four closed error sets, the key-handle behaviour, the
  telemetry surface, the dependency posture — with reserved break-rights and the
  frozen-wire-formats statement), and an enriched
  [SECURITY.md](SECURITY.md) (security invariants restated from the charter for
  reporting, a report-content checklist, acknowledgment ≤7 days + weekly status as a
  best-effort cadence, not an SLA). All four shipped in the package and extras.

- [Recipes](docs/recipes.md) and a [security model](docs/security.md), shipped in the
  package and indexed: compile-paste-verified integration shapes for a network-HSM handle
  (with the timeout-to-safe_callback exit-catch posture), a KMS handle (why
  `key_identity/1` must be ONE atomic version snapshot), and a condensed Plug consumer;
  plus the porting note for non-Elixir holders (the spec's signing-input and compact
  sections by durable identity, the conformance corpus as the oracle — closes the
  "signing beyond Elixir" residual as documentation, not a second-language SDK). The
  security doc's named misuses each state the consequence: caller-supplied key ids,
  skipped identity binding, no nonce ledger, trusting the C1 declaration as role
  separation, value-carrying telemetry, and shipping the test-support handle.
- Doc-currency tripwires (`test/docs_currency_test.exs`) + the regression-pinned
  Livebook: the round-trip notebook now commits its expected cell outputs
  (`persist_outputs`; verdicts and counts pinned — volatile bytes like thumbprints
  and sizes deliberately excluded and annotated). The tripwire suite diffs
  docs/errors.md's atoms against the lib's error `@type`s both directions (generic
  scans — a future atom the docs don't cover reds), resolves every backticked
  `fun/arity` in usage-rules.md against the adapter's exports and behaviour callbacks
  (arity-exact), checks the README Documentation index against the ex_doc extras both
  directions, and pins the getting-started dep requirement to the current version.
  Mutation-proven: a deleted atom row, a renamed function, a novel lib atom, a
  callback-arity drift, and an index-only link each red the suite. On landing, the
  identifier pass surfaced a doc inconsistency (usage-rules said
  `V1.Json.decode/1`; the shipped call shape is /2) — fixed in both guides.
- Core DX guides, shipped in the package and indexed from the README:
  [usage-rules.md](usage-rules.md) (12 flat rules, exact identifiers, reasons folded
  in — the C1-gate-is-declaration-rejection rule leads), [docs/errors.md](docs/errors.md)
  (all four closed-atom error sets as atom → meaning → what to check → recovery, authored
  to be mechanically checkable against the `@type`s), and
  [docs/getting-started.md](docs/getting-started.md) (first sign in minutes with a
  self-contained dev handle, then the path to a production handle).
- Value-free sign telemetry: the four signing entry points now emit a closed two-event
  surface (`[:bounded_authority_report_adapter, :sign, :start|:stop]`) with monotonic
  duration and atoms-only metadata (`object` in `[:report, :anchor, :grant,
  :key_transition]`; `result_class` in `[:ok, :invalid_input, :invalid_key_handle,
  :signing_failed, :producer_error]` — never key ids, message bytes, report content, or
  error values). The emitters are shape-validated (off-shape emissions are refused with
  `{:error, :telemetry_invalid}` instead of emitted — the mechanical value-free
  guarantee, tripwire-proven by planting a key id into the metadata and watching the
  stop event vanish), telemetry never alters a signer's return, and a raise inside the
  signer still propagates. `docs/telemetry.md` documents the event/class tables, the
  alerting guidance, and the attach example; a docs-parity test diffs the tables
  against the emitter's closed sets. Adds `:telemetry` (~> 1.3, zero transitive deps)
  as the first runtime dependency besides the protocol package itself.
- Library gate battery, parity-pinned between `mix ci` and the CI workflow's gate job:
  a coverage floor (`mix test --cover`, threshold pinned one display-hundredth under the
  measured 76.79% — Mix compares the raw ratio, so 76.78 is the tightest flake-free pin), dialyzer
  (PLT + analysis under `:test` so `test/support/` is analyzed), doc warnings
  (`mix docs --warnings-as-errors`), and the library's own dependency audits
  (`mix hex.audit` + `mix deps.audit` via mix_audit, both dev/test-only). Each gate is
  mutation-proven red-capable, and the CI advisory parity test now pins the full battery
  step order in both orchestration surfaces — dropping any one battery step reds parity.
- CI compatibility matrix: both workflow jobs now run a three-cell Elixir/OTP matrix
  (1.18.4/27.3.4.14, 1.19.5/28.5.0.3, 1.20.2/29.0.3 — the protocol sibling's proven
  lanes, `fail-fast: false`), with every cell running the identical battery. `mix ci`
  stays pinned to the local asdf lane and is documented as such in the workflow. The
  parity test pins the exact cells per job and that setup-beam consumes the matrix
  variables — a dropped lane reds (a lane that never runs looks green by absence).
  Validated with actionlint only (Actions billing-blocked; the limitation is stated in
  the commit). The dead git-pin-era "configure git for private deps" steps were already
  removed with the gate battery.
- `scripts/check_package.exs` — the shipped-artifact gate (pattern: the protocol sibling's
  package check, adapted): builds the exact Hex archive, unpacks it, asserts the payload
  census against the expected file set exactly in BOTH directions (a stale `files:`
  allowlist and an accidental inclusion both red), pins the outer metadata (version and
  requirement read from the live project config, so the pin never drifts on a bump),
  compiles the unpacked package in :prod, and compiles + smoke-runs a minimal consumer
  against the UNPACKED artifact — a self-implemented key handle, a
  sign_report → check_envelope positive, and a tampered-request negative. Mutation-proven:
  dropping a shipped file from the allowlist reds the census; a corrupted consumer reds
  its compile. Runs as a `mix ci` + workflow gate step; scratch-cleaned per run.
- Guard against silent protocol-version drift: the dependency-direction wall now pins the
  resolved `mix.lock` version (mutation-proven, including the `0.1.20` prefix-extension
  case), an exact identity invariant ties the wall's requirement floor to its locked-version
  attribute, and the edge-agent example asserts its lock resolves the protocol at the
  same version as the library's (a split between them would put the two CI jobs on
  different protocol spans).
- `scripts/check-bap-drift.sh` — a read-only, one-command ecosystem drift check (locked
  version vs hex.pm releases vs the authority runtime's pin vs protocol main, with the
  release span's `lib/` delta classified). A probe for audit and bump sessions, not a
  gate.

### Changed

- Fixed every Ed25519 signing call site to `:crypto.sign/4`'s documented contract —
  `:eddsa` with digest `:none` and the curve in the key list. The previous form passed
  the curve (`:ed25519`) in the digest slot, which the runtime tolerates but OTP 29's
  typespec rejects — the new dialyzer gate surfaced it as 35 findings across the
  test-support fixtures and the edge example (zero in `lib/`). Signatures are
  byte-identical under both forms (probed first: both verify), and the full suite is
  green after the sweep. The one intentional contract-violating fixture keeps its
  violation under a narrowly-scoped `@dialyzer` annotation.
- Removed the vestigial "configure git for private deps" CI steps and comments from both
  workflow jobs: the protocol package has been consumed from public Hex since 0.2.0 and
  neither project lock carries a git dependency.
- Re-align the protocol dependency to `bounded_authority_protocol` 0.1.2 (`~> 0.1.2`),
  the authority runtime's pin (ADR-0010 Decision 3 re-alignment, not a BARA-ahead bump).
  The release span's `lib/` delta is conformance tooling only
  (`conformance/{cli,report}.ex` — zero `V1.*` change to the consumed surface),
  `priv/conformance` is unchanged, and the protocol package's own `mix.exs` carries a
  version-line-only change. The wall's requirement + locked-version attributes, both
  project locks, and the drift-guard mutation fixtures (plain drift `0.1.3`, prefix
  extension `0.1.20`) moved in the same commit.
- ADR-0010 amended with a Hex-era mapping (Decision 6): the substrate moved to Hex
  consumption on 2026-08-20; the decision records how each policy term (BA's pin, the
  `lib/`-empty gate, the same-commit bump discipline, RA2-at-version) maps onto release
  tags and the now-mechanical wall clauses. ADR-0013's one-vector scope reaffirmed.
- Independent full-range review hardened the drift probe to withhold release verdicts on a
  malformed Hex response and to select only BA's `:bounded_authority_protocol` ref; both paths
  now have executable regressions. The review also replaced the compatible-version and
  duplicated-predicate guard checks with exact shared predicates, each tamper-proven RED.

### Security

- The edge example now fails both `mix ci` and its GitHub job on Hex advisories in its own lock.
  Bandit moved from vulnerable 1.12.4 to 1.12.5, which fixes HIGH
  `GHSA-xj8g-532w-jv94` and MEDIUM `GHSA-x3gh-xhj4-3vq8`. The two orchestration
  commands are independently mutation-proven by the parity test.

## [0.2.1] — 2026-08-20

### Fixed

- Reference the repository's `examples/` (Livebook demo and edge-agent app) in prose rather than by
  relative link, since `examples/` is not shipped in the package — removes the dangling
  documentation links from the published README and consumer-integration guide.

## [0.2.0] — 2026-08-20

First public release on Hex.

### Added

- Holder-side companion signer for the Bounded Authority Protocol, with four instantiations of one
  shared signing tail: `sign_report/3` (holder proof), `sign_anchor/3` (boundary anchor),
  `sign_key_transition/3` (key transition), and `sign_grant/3` (grant, structurally gated to an
  issuer-role handle so a holder cannot mint a capability).
- Key-handle custody contract: the private key never enters the library; callers pass a
  `{module, ref}` handle implementing the signing callbacks against their own key store, and every
  sign path verifies its output against the public key before returning.
- Conformance round-trip against the protocol package's published oracle vectors, and a
  dependency-direction wall proving the adapter depends only on `bounded_authority_protocol`.
- A runnable edge-agent example and a self-contained Livebook demo (issuer → holder → verifier).

### Changed

- Consume `bounded_authority_protocol` from its Hex release (`~> 0.1.1`) rather than a source
  dependency.

## [0.1.0]

Internal genesis of the companion signer and its four signing instantiations, developed against a
source dependency on the protocol package prior to the protocol's first Hex release.
