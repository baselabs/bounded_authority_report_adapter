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

### Not yet implemented

- The signing API (grant/proof envelope assembly via BAP's
  `grant_signing_input` / `proof_signing_input` / `assemble_compact`). Lands in
  the first build slice (B2-RA-01).
- The conformance round-trip against BAP's published vectors.
- The dependency-direction proof test.
