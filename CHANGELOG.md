# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once a 1.0.0 is cut. Until then, 0.x versions may carry breaking changes between
minor bumps (pre-1.0 freedom per SemVer).

## [Unreleased]

### Added — 2026-08-09 scaffold

- Project scaffolded (`mix new --sup`, then trimmed to a library): mix.exs wired
  with `bounded_authority_protocol` as a private git dep (ref
  `4c64be36ada1c167214471847d4061ea5ff63c56`), Apache-2.0 license, NOTICE,
  BAP-family `.gitignore` + `.formatter.exs`.
- `lib/bounded_authority_report_adapter.ex` — the top-level module documenting
  the adapter's role (signs, does not verify; holds a holder key, is not the
  runtime; is a composable lib, not a transport).
- `test/bounded_authority_report_adapter_test.exs` — the scaffold's one
  load-bearing assertion: the protocol package's `V1` module is reachable +
  `check_envelope/2` is exported (the edge-path dependency contract).
- `docs/charter.md`, `docs/strategy.md`, `docs/ROADMAP.md` — the authority
  model, the private-dep + release posture, and the build arc.

### Added — RA1 (2026-08-09) envelope signing

- `sign_report/3` — binds an issuer-signed grant to a application report by producing a
  holder proof, returning `{grant, proof}`. The adapter signs ONLY the proof via
  BAP's `proof_signing_input` + `assemble_compact`; the grant arrives
  issuer-signed and passes through untouched.
- Holder key never enters the adapter: callers supply a `{module(), term()}`
  key-handle callback (`sign/2`, `public_key/1`, `thumbprint/1`).
- Wrong-key verify (`:crypto.verify` against the resolved holder public key
  before assemble) and exit/throw containment on the key-handle callback, so a
  misconfigured signer fails as `:signing_failed` — not a silent false-success
  or a crash.
- `test/bounded_authority_report_adapter/sign_report_test.exs` — 13 round-trip
  + tripwire tests.

### Added — RA2 (2026-08-09) conformance round-trip

- `test/bounded_authority_report_adapter/conformance_roundtrip_test.exs` +
  `test/support/bounded_authority_report_adapter/conformance/vector_case.ex` —
  makes BAP's published `grant-holder-proof.json` vector the oracle: every
  published ENVELOPE case verifies via `check_envelope/2` and every GRANT-TIME
  case via `verify_grant/3`, matching each declared `expected_verdict`. An
  adapter-coherent round-trip (`sign_report/3` → `check_envelope/2`) verifies
  green against a freshly issuer-signed grant.
- Defect-injection RED proofs (signature flip, `ba_req` tamper, seven published
  `tamper_verdicts`), data-driven per declared `expected_verdict`,
  exhaustive-coverage guard.

### Added — RA3 (2026-08-10) dependency-direction wall

- `test/bounded_authority_report_adapter/dependency_direction_test.exs` — a
  two-clause structural proof that the adapter depends only on
  `bounded_authority_protocol` (declared + pinned + locked; no forbidden dep;
  no runtime-internal namespace), scanning both `lib/` and `test/support/`.
- Mutation-proven in every scanned dir + the real adapter module; dep-removal
  and form-precise regex RED proofs.

### Added — RA4 (2026-08-10) boundary-anchor signing

- `sign_anchor/3` — signs a `BoundaryAnchor` via the shared companion-signer tail
  (`sign_via_handle` → `verify_signature` → `assemble_compact`), returning a compact
  that round-trips through `verify_historical_anchor/3`. The second instantiation of
  the library's universal companion-signer role (ADR-0006).
- Both key identifiers (`public_key`, `key_id`) are resolved from the key-handle —
  never trusted from the caller — so the signed anchor header's `kid` + key
  fingerprint are consistent with the key `sign/2` used. `key_identity/1` resolves both
  as ONE atomic snapshot (defense-in-depth: prevents a rotation race from splitting
  `kid` from `public_key`); it is an optional `@callback` (`@optional_callbacks`),
  so proof-only handles need not implement it.
- `sign_report/3` refactored onto the same shared tail; the wrong-key verify guard
  now covers both the proof and anchor paths.
- `test/bounded_authority_report_adapter/sign_anchor_test.exs` — 12 tripwires
  (round-trip, wrong-key, key_id-from-handle, exit containment, no-canonical-bytes
  fork, defect injection, closed-atom errors).

### Added — RA5 (2026-08-10) universal consumer-integration guide

- `docs/consumer-integration.md` — the universal contract any verifier uses to consume a
  `{grant, proof}` envelope from `sign_report/3` via the PUBLIC `check_envelope/2`, WITHOUT
  depending on this adapter. Covers transport, the request-field contract (`cast_arguments =
  V1.Json.decode(raw_body)` on both sides), the one-`with` fail-closed verify, the REQUIRED
  identity binding (§8 — bind the verified envelope to the authenticated reporter so a captured
  envelope can't replay cross-identity), and the nonce-dedup obligation (§9). verifier application's report
  path is instance #1.
- README reframe: corrected the stale "holder-side signing adapter" intro to the ADR-0006
  "universal companion signer" framing + a pointer to the guide.

### Added — example Livebook (2026-08-11) self-contained round-trip demo

- `examples/report_envelope_roundtrip.livemd` — a Livebook that runs the full capability
  round-trip in one notebook (issuer → holder/sign → verifier), with no database, no Docker, and
  no other project running. Doubles as a plain-English explainer of the three-role model (with a
  mermaid sequence diagram) for readers unfamiliar with signing authorities. Verified: ✅ verify,
  tamper-reject, wrong-key-reject.
- The same round-trip is CI-covered by RA1's `sign_report_test.exs`; the notebook is the human
  view, not a CI gate.

### Added — RA8 (2026-08-12) key-transition signing

- `sign_key_transition/3` — the 4th instantiation of the universal companion-signer tail
  (ADR-0006; recorded in ADR-0009). Signs a `KeyTransition` (the current retiring key's
  assertion of its successor), returning `%{key_transition: compact}`, verifiable via
  `BoundedAuthorityProtocol.V1.verify_key_transition/4`.
- **Role-agnostic, mirroring `sign_anchor/3` — NOT `sign_grant/3`.** The current key's
  identity is resolved atomically via the existing `key_identity/1` callback; there is NO
  issuer-role gate (a transition is a historical-key operation, verified via
  `HistoricalPublicKey`). The C1 gate stays grant-only, exactly as ADR-0007 §Decision 4
  scoped it. A fresh-context design-adversarial pass reversed the first draft (which had
  gated on `:issuer`): the draft's "ADR-0006 §grant-signing pre-commitment generalized"
  was a phantom citation, and the verify contract is anchor-shaped. The rejected alternative
  is recorded in full in ADR-0009.
- `current_{key_id, public_key}` come from the atomic `key_identity/1` snapshot;
  `next_{key_id, public_key}` + content are caller-supplied. `next_public_key` is pre-checked
  for 32 bytes (the adapter's public-key guard); a self-transition is rejected by BAP's
  `distinct_fingerprints`.
- `test/bounded_authority_report_adapter/sign_key_transition_test.exs` — 10 tests: the
  round-trip through `verify_key_transition/4` + wrong-key, atomic-snapshot drift,
  no-canonical-bytes-fork, defect-injection, self-transition, missing-field, non-32-byte
  next key, exiting handle, and roleless-handle rejection. Wrong-key + racing tripwires
  are mutation-proven (disabling `verify_signature` drives them RED). Four transition
  handles in `test_handles.ex`.
- The four named companion-signer instantiations are complete (proof, anchor, grant,
  key-transition).

### Added — RA9 (2026-08-11) edge-agent reference app

- `examples/edge_agent/` — a runnable mix app (its own project; the adapter is a
  `path: "../.."` dep) that signs a application report via `sign_report/3` and POSTs it over HTTP (Req)
  to a receiver (a Plug on Bandit) that verifies via `check_envelope/2`. The proof the adapter
  works in a real deployment. The receiver implements the complete consumer contract — raw-body
  decode, the one-`with` `check_envelope`, the §8 identity binding, the §9 nonce-dedup replay
  ledger — and depends ONLY on `bounded_authority_protocol`, never on this adapter (the
  dependency-direction wall, from the consumer side).
- `examples/edge_agent/test/edge_agent_test.exs` — the end-to-end round-trip through real HTTP,
  plus the four rejection classes (tampered proof, stranger's proof, wrong identity, replayed
  nonce). The §8 binding and §9 ledger are mutation-proven non-vacuous.
- CI gains an `example` job compiling + testing the app, so a broken example is caught at the
  gate, not at provision time.
- ROADMAP RA10 (cross-language verifier) narrowed: out of BARA's scope — a cross-language
  verifier validates BAP's portable format (anchored to BAP's conformance corpus), not this
  adapter; BARA's involvement is none. See `docs/ROADMAP.md`.
- `AGENTS.md` (new, repo-root) — the operational doc for AI coding agents editing this repo:
  the dependency wall, the two-project build + dual CI, the per-file floor (with the example-app
  test-file-warning nuance), the transport posture (Req/Bandit, incl. the Bandit ≥1.12 top-level
  options gotcha), and the read-BAP-first-hand / verify-before-citing mandate (closes the gap that
  let two phantom citations — "Req per repo-root AGENTS.md" + "BAP ADR-0014/0015" — reach a prior
  handoff). `docs/consumer-integration.md` + the example README cross-reference it; the parent
  README Development section is refreshed (test count, dual-app note).


