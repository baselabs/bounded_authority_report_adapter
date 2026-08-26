# Security policy

## Supported versions

The latest published `0.x` line is supported. After 1.0, the supported-versions policy is
the stability contract's ([upgrading.md](docs/upgrading.md) § The 1.0 stability contract).
Wire compatibility is governed by the protocol package's contract-major discipline — this
library's releases track it.

## Security invariants (what a report is measured against)

Restated from the charter's boundary invariants, for reporting:

- The library never solicits, processes, or retains private key material — custody lives
  entirely behind the caller's key-handle callbacks (the contract; a handle that embeds
  key bytes in its term has chosen that posture itself — see
  [security.md](docs/security.md) § Trust boundaries).
- Every signature is verified against the handle-resolved public key before success — a
  wrong-key sign is `:signing_failed`, never a false success.
- Errors are closed atoms and telemetry metadata is value-free: neither channel can carry
  key material, message bytes, or report content. A defect that leaks values into either
  channel is a security defect, not a cosmetic one.
- Key identity (`key_id` + `public_key`) is resolved from ONE atomic handle snapshot on
  anchors and transitions; caller-supplied key ids are ignored.
- The library depends only on the public protocol package — never the authority runtime,
  never a transport, never an HTTP client/server (enforced by the dependency-direction
  wall).

## Reporting a vulnerability

Use GitHub's private vulnerability-reporting / security-advisory flow for
`baselabs/bounded_authority_report_adapter`. Do not open a public issue containing an
exploit, credential, private key, or unreleased vulnerability detail.

A report should include:

- the affected version or commit;
- the violated property (the invariant above, in your own words);
- a minimal, VALUE-FREE reproduction (no real keys, no production report content);
- the expected security outcome.

We will acknowledge reports within 7 days and send status updates at least weekly until
resolution, coordinating disclosure through the private advisory. This is a best-effort
cadence from a small maintainer team, not a contractual SLA — urgent disclosures are
handled faster when marked as such.
