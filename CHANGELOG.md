# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Pre-1.0, `0.x` minor bumps may carry
breaking changes (SemVer §4).

## [Unreleased]

### Added

- Guard against silent protocol-version drift: the dependency-direction wall now pins the
  resolved `mix.lock` version (mutation-proven, including the `0.1.10` prefix-extension
  case), an exact identity invariant ties the wall's requirement floor to its locked-version
  attribute, and the edge-agent example asserts its lock resolves the protocol at the
  same version as the library's (a split between them would put the two CI jobs on
  different protocol spans).
- `scripts/check-bap-drift.sh` — a read-only, one-command ecosystem drift check (locked
  version vs hex.pm releases vs the authority runtime's pin vs protocol main, with the
  release span's `lib/` delta classified). A probe for audit and bump sessions, not a
  gate.

### Changed

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
