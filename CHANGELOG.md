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
  fingerprint are consistent with the key `sign/2` used. `key_id/1` is an optional
  `@callback` (`@optional_callbacks`); proof-only handles need not implement it.
- `sign_report/3` refactored onto the same shared tail; the wrong-key verify guard
  now covers both the proof and anchor paths.
- `test/bounded_authority_report_adapter/sign_anchor_test.exs` — 12 tripwires
  (round-trip, wrong-key, key_id-from-handle, exit containment, no-canonical-bytes
  fork, defect injection, closed-atom errors).
