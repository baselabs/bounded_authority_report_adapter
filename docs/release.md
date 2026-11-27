# Release runbook

How a release of `bounded_authority_report_adapter` goes from a commit on `master` to Hex.
Each release checks compatibility, examples, documentation and artifact provenance.
Publishing is irreversible after Hex's one-hour revert window.

The publication workflow publishes new versions of existing Hex.pm packages only and
refuses a package name the registry has never had. A first publication is the owner's decision.

Throughout, `X.Y.Z` is the version being released and `SHA` is the release commit.

## 1. The release commit

One commit on `master` carries:

- `@version "X.Y.Z"` in `mix.exs`;
- the CHANGELOG's `## Unreleased` heading replaced by `## [X.Y.Z]: YYYY-MM-DD`,
  with a nonempty release entry and no unreleased entries above it;
- the upgrading notes for anything a caller must change;
- the install lines in the README and `docs/guides/getting-started.md` (`~> X.Y`), every notebook's exact
  `Mix.install` pin and version assertion, and the landing page's Hex badge
  (`site/index.html`). The docs-currency and Livebook tests fail until these agree with
  `mix.exs`.

When the release also moves the protocol range (for example, the 1.0.0 move from `~> 0.9.1` to `~> 1.0`), the same
commit edits:

- the requirement in `mix.exs`;
- `@protocol_requirement`, `@protocol_floor` and `@protocol_ceiling` in
  `test/bounded_authority_report_adapter/dependency_direction_test.exs` (every other probe
  derives from them);
- `mix.lock` and `examples/edge_agent/mix.lock`, resolved from Hex (`mix deps.update
  bounded_authority_protocol` in both projects);
- `@protocol_refuses_integral_float_selectors` in
  `test/bounded_authority_report_adapter/selector_float_refusal_test.exs`, and any new
  certified corpus in `test/bounded_authority_report_adapter/conformance_corpus_test.exs`
  (both files mark the line);
- the CHANGELOG line "The protocol dependency moves from `x` to `y`", which documents the dependency boundary.

## 2. Gates before publication

Run each and keep its output.

1. **The locked protocol is the attested protocol** (when the lock moved). The lock's outer
   checksum must equal the registry's and the protocol release's attested `SHA256SUMS`:

   ```sh
   grep '"bounded_authority_protocol"' mix.lock
   curl -s https://hex.pm/api/packages/bounded_authority_protocol/releases/P.Q.R | jq -r .checksum
   ```

2. **Qualification and landing.** Land `SHA` with
   the maintainer-controlled landing process. A `kci/**` push runs the complete
   qualification suite; `qualified` must be green before `master` moves to that exact
   commit. Contributors prepare commits; maintainers own landing and publication.
3. **Publication authorization.** The release maintainer obtains authorization to dispatch
   `publish.yml` from `master`, with `release_commit` set to the full qualified SHA.
   Both the actor and the triggering actor must be allowlisted. The upload job alone uses
   the `publish` environment and can exchange a package-scoped workload token.
4. **Supply-chain attestation of `SHA`.** The same `kci/**` qualification run builds and
   inspects the exact package and HTML docs archives. It records the package checksum,
   generates the release SBOM, and calls `supply-chain.yml` after the gates pass.
   The reusable workflow holds the attestation permissions. `qualified` requires both jobs.
   Actions retains qualification archives and release evidence for seven days.
5. **The qualified archives are published.** Publication verifies the package attestation
   against the signer workflow and source digest before upload. The shared Hex action checks
   qualification, the archive files and checksums, the stamped changelog, and registry state
   before it exchanges a short-lived workload token. It refuses an existing version tag,
   a retired release, or differing registry bytes. If publication needs a retry, dispatch
   the same commit with `qualification_run` set to the original CI run ID. The action
   preserves matching uploads and completes missing archives.
   Public read-back requires both served archives to match the qualified bytes and the docs'
   `release.json` to name `SHA`. It prepares `release-assets` with the archives, checksums and
   release SBOM. The separate `published-livebooks` job then runs every notebook unchanged
   against that release.

## 3. Publish and tag

6. After the gates above, the authorized release operator dispatches `publish.yml` and reads the run to
   completion. The workflow creates no tag or GitHub release. Hex's one-hour revert window starts at publication.
7. After the read-back, the release operator compares the publication's archive with the
   registry, creates `baselabs_bounded_authority_report_adapter-vX.Y.Z` on the commit named in the
   served docs' `release.json`, and creates the GitHub release with both archives,
   `SHA256SUMS` and `release.cdx.json`. Consumers obtain those files
   from that GitHub release. No workflow runs on a tag or creates a GitHub release.

## 4. Read-back, within the hour

8. Download the package and docs archives, checksums and SBOM from the GitHub release.
   The registry checksum must equal the attested archive digest:

   ```sh
   gh release download baselabs_bounded_authority_report_adapter-vX.Y.Z \
     --repo baselabs/bounded_authority_report_adapter \
     --pattern '*.tar' --pattern '*-docs.tar.gz' --pattern SHA256SUMS --pattern '*.cdx.json'
   sha256sum --check SHA256SUMS
   gh attestation verify bounded_authority_report_adapter-X.Y.Z.tar \
     --repo baselabs/bounded_authority_report_adapter \
     --signer-workflow baselabs/bounded_authority_report_adapter/.github/workflows/supply-chain.yml \
     --source-digest SHA --deny-self-hosted-runners
   curl -s https://hex.pm/api/packages/bounded_authority_report_adapter/releases/X.Y.Z | jq -r .checksum
   ```

9. HexDocs renders the release: `https://hexdocs.pm/bounded_authority_report_adapter/X.Y.Z`.
10. A fresh consumer compiles: `mix new` a scratch project, add
    `{:bounded_authority_report_adapter, "~> X.Y"}`, then `mix deps.get && mix compile`.
11. Every notebook runs unchanged from Hex: the `published-livebooks` job of `publish.yml`
    waits until the Hex repository serves `X.Y.Z`, then runs
    `elixir scripts/check_livebooks.exs --published`, which installs `== X.Y.Z`, checks version
    and registry origin, and compares every semantic output. The job holds no key. Read its
    result as part of the read-back.
12. `examples/edge_agent` runs against the published package: in a scratch copy, replace
    the `path: "../.."` dependency with `"~> X.Y"`, then `mix deps.get && mix test`.

If any read-back fails inside the hour, a release maintainer obtains authorization before reverting the
publication, then fixes the release and starts again from step 1. After the hour, fix
forward as `X.Y.(Z+1)`.
