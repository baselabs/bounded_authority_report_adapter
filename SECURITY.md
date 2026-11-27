# Security policy

## Supported versions

Security fixes land in the latest release of the current major. See the
[package on Hex](https://hex.pm/packages/bounded_authority_report_adapter) for available versions.
The [stability contract](docs/guides/upgrading.md#stability-contract) has applied since 1.0.0.
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

For releases published using workload identity, the `kci/<sha>` run builds and checks
the Hex package and HTML docs archives. It records the package checksum and calls the
reusable supply-chain workflow for build-provenance and CycloneDX SBOM attestations.
Publication verifies the qualified package attestation before upload. Read-back compares
the served archives byte for byte and checks that the docs' `release.json` names the exact
release commit. The release operator tags that commit and attaches the archives,
`SHA256SUMS` and `release.cdx.json` to the GitHub release
`baselabs_bounded_authority_report_adapter-v<version>`.

Set `version` to the release version and `commit` to the full commit identified by the
release tag. Run these commands in a directory for the downloaded archives.

```sh
version=VERSION
commit=FULL_COMMIT_SHA

gh release download "baselabs_bounded_authority_report_adapter-v${version}" \
  --repo baselabs/bounded_authority_report_adapter \
  --pattern '*.tar' --pattern '*-docs.tar.gz' --pattern SHA256SUMS --pattern '*.cdx.json'
sha256sum -c SHA256SUMS

gh attestation verify "bounded_authority_report_adapter-${version}.tar" \
  --repo baselabs/bounded_authority_report_adapter \
  --signer-workflow baselabs/bounded_authority_report_adapter/.github/workflows/supply-chain.yml \
  --source-digest "$commit" --deny-self-hosted-runners

curl -fsS "https://hex.pm/api/packages/bounded_authority_report_adapter/releases/${version}" \
  | jq -er .checksum
```

Compare the checksum returned by Hex with the package archive's entry in `SHA256SUMS`.

Locally, before any release, `mix ci` runs the same reproducibility gate the
workflow uses: two cache-isolated builds of the exact archive must agree byte
for byte.

## Acknowledgment

We will acknowledge reports within 7 days and send status updates at least weekly until
resolution, coordinating disclosure through the private advisory. This is a best-effort
cadence from a small maintainer team, not a contractual SLA: urgent disclosures are
handled faster when marked as such.
