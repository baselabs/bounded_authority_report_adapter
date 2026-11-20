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
- the CHANGELOG's `[Unreleased]` section renamed to `[X.Y.Z]: YYYY-MM-DD`;
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
3. **Publication authorization.** The release maintainer obtains publication authorization for dispatching
   `publish.yml` from `master`, with no inputs, in environment `publish`. Only accounts allowlisted in the workflow may be
   both the actor and triggering actor. The workflow refuses any other ref, installs
   the exact toolchain and pinned Hex client, fetches with `mix deps.get --check-locked`,
   and refuses an existing version tag or a retired Hex release. It relies on the default-branch
   ruleset for qualification and does not rerun CI.
4. **Supply-chain attestation of `SHA`.** The same `kci/**` qualification run builds and
   inspects the exact package archive, records its checksum, generates its release SBOM,
   and calls `supply-chain.yml` after the gates pass. Only the reusable attestation job
   holds signing permissions; it runs no project code. `qualified` needs both jobs.
5. **The inspected archive is the published archive.** `publish.yml` builds HTML docs
   with warnings as errors and fixed tar/gzip metadata, builds and inspects the Hex package,
   and verifies its qualification attestation with the signer workflow and source digest.
   It collects the qualification checksum and SBOM alongside the matching archive.
   The upload step verifies both archive checksums and uploads only missing bytes through
   the Hex APIs. `HEX_API_KEY` exists only in that step's environment, in a directory with
   no `mix.exs`; project and dependency code do not run in the process holding it.
   A held response is incomplete. After approval on Hex, dispatch again from `master`: an
   identical existing package is left in place, missing uploads are completed, and a differing
   package or a retired version is refused. Docs are a rendering of the package and an ExDoc
   build is not byte-stable, so docs are never compared by bytes: the docs archive carries
   `release.json` naming the package, version and commit that built it, and served docs must
   name this package and version and the dispatched commit or its ancestor on `master`. That
   commit is the published commit. The workflow never replaces a package or served docs, and
   succeeds only after an unkeyed read-back proves the package matches and the docs are served.
   Read-back saves the served docs archive in the `release-assets` bundle. A separate job,
   `published-livebooks`, then runs every notebook unchanged against the release. It
   has no environment and no key; qualification never installs this package from Hex,
   because a version commit names a release Hex does not serve yet.

## 3. Publish and tag

6. After the gates above, the authorized release operator dispatches `publish.yml` and reads the run to
   completion. The workflow creates no tag or GitHub release. Hex's one-hour revert window starts at publication.
7. After the read-back, the release operator compares the publication's archive with the
   registry, creates `vX.Y.Z` on the published commit that the served docs' `release.json`
   names, and creates the GitHub release
   with the archive, `SHA256SUMS` and `release.cdx.json`. Consumers obtain all three files
   from that GitHub release. No workflow runs on a tag or creates a GitHub release.

## 4. Read-back, within the hour

8. Download the archive, checksum and SBOM from this repository's GitHub release `vX.Y.Z`.
   The registry checksum must equal the attested archive digest:

   ```sh
   gh release download vX.Y.Z --repo baselabs/bounded_authority_report_adapter \
     --pattern '*.tar' --pattern SHA256SUMS --pattern '*.cdx.json'
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

## 5. Evidence commit

13. Add the release's row to the registry-checksum ledger (the table in the CHANGELOG's
    `[0.9.1]` section), with the checksum read back in step 8, and record the gate outputs
    in the commit message.
