# Contributing

Preserve the public signing contract: custody stays behind caller-owned callbacks, errors
contain no caller values, and telemetry uses only closed object/result classes. Private key
material must never enter a handle term. Test helpers do not ship in the package.

## Environment and boundaries

Use Elixir 1.18 through 1.20 on Erlang/OTP 27 through 29. Exact toolchains are in
`.tool-versions`; OTP 27 is required for `:json`. CI reads it only through the shared
toolchain reader, `scripts/toolchain.sh`. Its primary outputs and `beam_lanes` supply
every supported pair; setup checks the installed versions with `--installed`.
The library and `examples/edge_agent` are separate Mix projects. Transport dependencies
belong only to the example.

Required runtime dependencies are the public protocol and telemetry; Igniter is optional.
`test/bounded_authority_report_adapter/dependency_direction_test.exs` enforces this boundary.
Call only documented protocol APIs. The resolved source and typespecs are authoritative;
`test/bounded_authority_report_adapter/protocol_private_api_test.exs` checks the call sites.
Before changing the protocol requirement, run `bash scripts/check-bap-drift.sh` and update
both locks, version notes, examples and tests together.

## Validation

Before running the reproducibility check in `mix ci`, install the version in
`.github/actions/hex-publish/hex-version` in [`baselabs/.github`](https://github.com/baselabs/.github)
at the commit pinned by the `hex-qualification` job in `.github/workflows/ci.yml`. Run
`mix local.hex VERSION --force` from a directory without `mix.exs`, substituting the
version from that file. The check fetches the pin with `curl` at the commit specified in
the checkout's CI workflow and checks the running Hex version against it.

```sh
mix deps.get --check-locked
MIX_ENV=test mix ci
elixir scripts/check_livebooks.exs --local
python3 scripts/check_doc_links.py doc
```

`mix ci` checks formatting, compilation, lint, tests with coverage, Dialyzer, docs, links,
advisories, package contents and reproducibility, notebooks and the example app. It runs
checks in order and exits non-zero if any step failed. Some failures allow later checks to
run; read all output. CI runs the supported toolchain matrix and the local notebook mode; `publish.yml` runs the
notebooks unchanged against Hex after package and docs read-back.

Every authored Elixir fence is discovered recursively with a CommonMark parser and executed.
HTTP examples execute in the example app, which supplies Plug. No compile-only fragments
or fictional custody services are accepted. Standalone notebooks must generate their own
keys, assert success and refusal, persist semantic outputs and clean up. Their registry,
exact release pins, API coverage, source links and rendered links are checked. New guards
include a case demonstrating that the intended violation is rejected.

Public API changes update typespecs, executed examples, errors and migration notes in the
same change. Tests use real cryptography and real services. Do not add private product names,
internal coordination, secrets or environment files to public sources.

## Releases

Contributors commit changes for maintainer review. Only maintainers land qualified commits
and run publication or site deployment. Hex publication takes the full qualified commit
and uploads its archives using workload identity.
See the [release runbook](https://github.com/baselabs/bounded_authority_report_adapter/blob/master/docs/release.md).
Never publish or tag as part of a contribution.
Report vulnerabilities through [SECURITY.md](SECURITY.md).

## Maintainer checks

Install the tracked hooks with `bash scripts/install-hooks.sh`. Local confidential-identifier
checks require an ignored owner policy; contributors without it get an inactive notice.
See the [maintainer checks](https://github.com/baselabs/bounded_authority_report_adapter/blob/master/docs/maintainer-checks.md)
for activation, coverage and the standalone guard tests. Public CI uses only synthetic identifiers.
