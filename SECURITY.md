# Security policy

## Supported versions

Security fixes land in the latest release of the current major. Version 1.0.0 is released;
the [stability contract](docs/guides/upgrading.md#stability-contract) has applied since that release.
Wire compatibility follows the protocol package's contract-major discipline.

## Security invariants (what a report is measured against)

The properties a report is measured against (the long form is the
[security model](docs/guides/security.md)):

- The library never solicits, processes, or retains private key material: custody lives
  entirely behind the caller's key-handle callbacks (the contract; a handle that embeds
  key bytes in its term has chosen that posture itself: see
  [security.md](docs/guides/security.md) § Trust boundaries).
- Every signature is verified against the handle-resolved public key before success: a
  wrong-key sign is `:signing_failed`, never a false success.
- Errors use closed atoms or the fixed tuple `{:producer_error, :invalid}`. Telemetry
  metadata is value-free. Neither channel can carry key material, message bytes or report
  content. A defect that leaks values into either
  channel is a security defect, not a cosmetic one.
- Key identity (`key_id` and `public_key`) comes from one handle call for grants, anchors,
  key transitions and content assertions; caller-supplied key ids are ignored.
- Required runtime dependencies are the public protocol package and telemetry; Igniter
  is optional installer support. The library excludes the authority runtime, transport
  libraries and HTTP clients or servers (enforced by the dependency-direction
  wall).

## Reporting a vulnerability

Report privately through GitHub: open the repository's
[Security tab](https://github.com/baselabs/bounded_authority_report_adapter/security) and
choose **Report a vulnerability**, or go straight to
[the private report form](https://github.com/baselabs/bounded_authority_report_adapter/security/advisories/new)
(you need to be signed in to GitHub). Only you and the maintainers see the report. Do not
open a public issue containing an exploit, credential, private key, or unreleased
vulnerability detail.

A report should include:

- the affected version or commit;
- the violated property (the invariant above, in your own words);
- a minimal, VALUE-FREE reproduction (no real keys, no production report content);
- the expected security outcome.

## Verifying a release (supply-chain provenance)

Every `kci/<sha>` qualification run builds and checks the exact Hex archive, records its
SHA-256 in `SHA256SUMS`, and calls the reusable supply-chain workflow for build-provenance
and CycloneDX SBOM attestations. Publication verifies the rebuilt archive against that
attestation and reads both package and documentation bytes back from Hex. The release
operator then tags the exact source commit and attaches the archive, `SHA256SUMS` and
`release.cdx.json` to this repository's GitHub release `v<version>`. No workflow runs on a tag.
To verify the files downloaded from that GitHub release:

```sh
# 1. Download the GitHub release files and compare checksums:
gh release download v<version> --repo baselabs/bounded_authority_report_adapter \
  --pattern '*.tar' --pattern SHA256SUMS --pattern '*.cdx.json'
sha256sum -c SHA256SUMS

# 2. Bind the archive to the qualification signer and exact source commit:
gh attestation verify bounded_authority_report_adapter-<version>.tar \
  --repo baselabs/bounded_authority_report_adapter \
  --signer-workflow baselabs/bounded_authority_report_adapter/.github/workflows/supply-chain.yml \
  --source-digest <commit> --deny-self-hosted-runners

# 3. Cross-check against hex.pm's published checksum for the release
#    (hex.pm shows the archive checksum on the version page: it must
#    equal the SHA-256 in SHA256SUMS for the same bytes).
```

Locally, before any release, `mix ci` runs the same reproducibility gate the
workflow uses: two cache-isolated builds of the exact archive must agree byte
for byte.

## Acknowledgment

We will acknowledge reports within 7 days and send status updates at least weekly until
resolution, coordinating disclosure through the private advisory. This is a best-effort
cadence from a small maintainer team, not a contractual SLA: urgent disclosures are
handled faster when marked as such.
