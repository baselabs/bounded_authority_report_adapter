# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Pre-1.0, `0.x` minor bumps may carry
breaking changes (SemVer §4).

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
