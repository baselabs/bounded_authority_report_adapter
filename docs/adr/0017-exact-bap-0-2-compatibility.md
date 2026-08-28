# ADR-0017: Exact BAP 0.2 compatibility line

- Status: Accepted
- Date: 2026-08-27

## Context

The published BARA 0.3.0 package requires `bounded_authority_protocol ~> 0.1.2`.
The authority suite's recertified runtime line selects BAP 0.2.0 exactly. A consumer
cannot solve BARA 0.3.0 together with exact BAP 0.2.0, even though BAP's 0.2.0 release
does not change the V1 wire contract or public runtime API.

The verified `v0.1.2..v0.2.0` BAP span has no `lib/` diff. BAP 0.2.0 records zero
wire, bound, verdict, or SDK behavior change. Its conformance corpus remains revision 1
with 283 cases; provenance/index digests rotate as part of the release tooling change.

## Decision

1. BARA depends on `bounded_authority_protocol == 0.2.0`. Root, example, package,
   dependency-wall, and documentation identities move together. BARA does not vendor
   BAP, retain parallel BAP versions, or rely on a consumer override.
2. BARA's public signing API remains unchanged: `sign_report/4`, `sign_anchor/3`,
   `sign_grant/3`, and `sign_key_transition/3` continue to sign BAP-owned deterministic
   inputs through caller-owned, non-exporting key handles.
3. BARA retains no issuer authority beyond the already explicit issuer-role grant
   handle. Revocation, replay, decisions, effects, transport, persistence, and key
   custody remain outside this package.
4. The successor is version 0.4.0. Although runtime and wire behavior remain stable,
   replacing `~> 0.1.2` with the disjoint exact `== 0.2.0` line is an observable
   package-resolution compatibility break. A patch release would understate it.
5. Publication requires clean resolution to one BAP 0.2.0 line, all four producer
   round-trips through BAP 0.2.0, meaningful negative cases, the complete owner gate
   battery, a clean packaged consumer, and immutable Git/Hex identity verification.

## Rejected alternatives

- A 0.3.1 patch: rejected because the dependency solver contract is not patch-compatible
  for consumers retaining BAP 0.1.x.
- `~> 0.2.0`: rejected because the suite's owner contracts require the recertified exact
  BAP identity, not an unreviewed later 0.2.x selection.
- Vendoring, dual BAP lines, or consumer overrides: rejected because they conceal rather
  than resolve the authority-suite identity conflict.
- New BARA verification or authority behavior: rejected because BAP 0.2.0 does not
  require it and BARA's sole responsibility remains caller-key-handle signing.

## Failure modes and proofs

- Resolver drift: dependency wall, both lockfiles, and a clean exact-pin consumer.
- Producer drift: report, anchor, grant, and key-transition verification through BAP
  0.2.0.
- Vacuous rejection tests: decoded-byte signature corruption plus wrong-holder,
  widened-request, malformed-signature, and provider-failure cases.
- Artifact/source drift: reproducible package checksum tied to source commit, immutable
  tag, and Hex release identities.
