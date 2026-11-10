# Release runbook

How a release of `bounded_authority_report_adapter` goes from a commit on `master` to Hex.
Every gate is a command whose output is recorded in the release's evidence commit. Steps
marked ★ are the owner's: pushing the tag and publishing. Publishing is irreversible after
Hex's one-hour revert window.

Throughout, `X.Y.Z` is the version being released and `SHA` is the release commit.

## 1. The release commit

One commit on `master` carries:

- `@version "X.Y.Z"` in `mix.exs`;
- the CHANGELOG's `[Unreleased]` section renamed to `[X.Y.Z] — YYYY-MM-DD`;
- the upgrading notes for anything a caller must change;
- the install lines in the README and `docs/getting-started.md` (`~> X.Y`), the Livebook's
  `Mix.install` line and version sentence, and the landing page's Hex badge
  (`site/index.html`). The docs-currency and Livebook tests fail until these agree with
  `mix.exs`.

When the release also moves the protocol range (for 1.0: `~> 0.9.1` to `~> 1.0`), the same
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
- the CHANGELOG line "The protocol dependency moves from `x` to `y`", which the Livebook
  test reads.

## 2. Gates before the tag

Run each and keep its output.

1. **The locked protocol is the attested protocol** (when the lock moved). The lock's outer
   checksum must equal the registry's and the protocol release's attested `SHA256SUMS`:

   ```sh
   grep '"bounded_authority_protocol"' mix.lock
   curl -s https://hex.pm/api/packages/bounded_authority_protocol/releases/P.Q.R | jq -r .checksum
   ```

2. **Local CI.** `MIX_ENV=test mix ci` exits 0.
3. **CI on `SHA`.** `gh run watch <run-id> --exit-status` for the CI run of the release
   commit exits 0.
4. **Supply-chain attestation of `SHA`.** Run the workflow on the release commit while it
   is the head of `master` (the evidence artifact is named after the head commit) and wait
   for it:

   ```sh
   gh workflow run supply-chain.yml --ref master -f ref=SHA
   gh run watch <run-id> --exit-status
   gh run download <run-id> --name release-evidence-SHA --dir evidence
   (cd evidence && sha256sum --check SHA256SUMS)
   gh attestation verify evidence/bounded_authority_report_adapter-X.Y.Z.tar \
     --repo baselabs/bounded_authority_report_adapter
   ```

5. **The archive you would publish is the attested archive.** In a clean checkout of
   `SHA`:

   ```sh
   mix deps.get
   mix hex.build --output /tmp/bounded_authority_report_adapter-X.Y.Z.tar
   sha256sum /tmp/bounded_authority_report_adapter-X.Y.Z.tar
   ```

   The digest must equal the one in `evidence/SHA256SUMS`. If it does not, stop.

## 3. Tag and publish

6. ★ Push the tag: `git tag -a vX.Y.Z SHA -m "X.Y.Z" && git push origin vX.Y.Z`. The tag's
   supply-chain run must attest the same digest as step 4.
7. ★ Publish from the clean checkout of `SHA`: `mix hex.publish`. The one-hour revert
   window starts.

## 4. Read-back, within the hour

8. The registry checksum equals the attested digest:

   ```sh
   curl -s https://hex.pm/api/packages/bounded_authority_report_adapter/releases/X.Y.Z | jq -r .checksum
   ```

9. HexDocs renders the release: `https://hexdocs.pm/bounded_authority_report_adapter/X.Y.Z`.
10. A fresh consumer compiles: `mix new` a scratch project, add
    `{:bounded_authority_report_adapter, "~> X.Y"}`, then `mix deps.get && mix compile`.
11. The Livebook runs from Hex: its `Mix.install` cell installs `~> X.Y.Z`, and every cell
    returns its pinned output.
12. `examples/edge_agent` runs against the published package: in a scratch copy, replace
    the `path: "../.."` dependency with `"~> X.Y"`, then `mix deps.get && mix test`.

If any read-back fails inside the hour: ★ `mix hex.publish --revert X.Y.Z`, fix, and start
again from step 1. After the hour, fix forward as `X.Y.(Z+1)`.

## 5. Evidence commit

13. Add the release's row to the registry-checksum ledger (the table in the CHANGELOG's
    `[0.9.1]` section), with the checksum read back in step 8, and record the gate outputs
    in the commit message.
