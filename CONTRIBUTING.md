# Contributing

Preserve the public signing contract: custody stays behind caller-owned callbacks, errors
contain no caller values, and telemetry uses only closed object/result classes. Private key
material must never enter a handle term. Test helpers do not ship in the package.

## Environment and boundaries

Use Elixir 1.18 through 1.20 on Erlang/OTP 27 through 29. Exact toolchains are in
`.tool-versions`; OTP 27 is required for `:json`. The library and `examples/edge_agent`
are separate Mix projects. Transport dependencies belong only to the example.

Required runtime dependencies are the public protocol and telemetry; Igniter is optional.
`test/bounded_authority_report_adapter/dependency_direction_test.exs` enforces this boundary.
Call only documented protocol APIs. The resolved source and typespecs are authoritative;
`test/bounded_authority_report_adapter/protocol_private_api_test.exs` checks the call sites.
Before changing the protocol requirement, run `bash scripts/check-bap-drift.sh` and update
both locks, version notes, examples and tests together.

## Validation

```sh
mix deps.get --check-locked
MIX_ENV=test mix ci
elixir scripts/check_livebooks.exs --local
elixir scripts/check_livebooks.exs --published
python3 scripts/check_doc_links.py doc
```

`mix ci` checks formatting, compilation, lint, tests with coverage, Dialyzer, docs, links,
advisories, package contents and reproducibility, notebooks and the example app. It runs
checks in order and exits non-zero if any step failed. Some failures allow later checks to
run; read all output. CI runs the supported toolchain matrix and both notebook modes.

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
and run publication or site deployment. Never publish or tag as part of a contribution.
Report vulnerabilities through [SECURITY.md](SECURITY.md).
