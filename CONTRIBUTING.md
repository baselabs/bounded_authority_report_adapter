# Contributing

Contributions must preserve the invariants the repository exists to hold: the
dependency-direction wall, closed-atom errors, value-free telemetry and test-only status of
`test/support/` (nothing there ships). Required runtime dependencies are the public protocol
package and telemetry, with optional Igniter installer support. Authority-runtime and
transport dependencies are excluded from the library.

## Protocol API and dependency boundary

Call only documented protocol functions. Build calls from the resolved dependency's
struct definitions and `@spec`s: `mix.lock` identifies the release, and
`deps/bounded_authority_protocol/` contains its source. Prose and examples do not replace
those definitions.

`test/bounded_authority_report_adapter/protocol_private_api_test.exs` rejects calls to a
protocol function marked `@doc false` or any function in a protocol module marked
`@moduledoc false`. It reads the resolved dependency's compiled docs and scans `lib/`,
`scripts/`, `examples/` and `test/`, including notebook cells. Its static scan covers
remote calls, pipes and captures; it does not resolve `apply/3` or variable-module calls.
Those calls must obey the same documented-API rule.

The **dependency-direction wall** keeps the library independent of the private authority
runtime, transport libraries, HTTP clients and HTTP servers.
`test/bounded_authority_report_adapter/dependency_direction_test.exs` checks `mix.exs`
and `mix.lock` for the named forbidden packages (`bounded_authority`, `replicant` and
`capstan`) and scans `lib/` and `test/support/` for runtime-internal namespace references.
It also checks the protocol requirement and resolved version. The package-boundary check
in `scripts/check_package.exs` enforces the complete direct runtime dependency allowlist:
protocol, telemetry and optional Igniter. Adding an HTTP client or server as a direct
runtime dependency in the library's `mix.exs` fails the package check; the wall test does
not classify arbitrary HTTP package names.

The wall does not scan `examples/`. The example application is a separate Mix project and
may declare transport dependencies in `examples/edge_agent/mix.exs`. Keep them there;
adding them to the library's manifest violates the library's dependency boundary. See
[example-app conventions](examples/edge_agent/README.md#development-notes-gotchas-specific-to-this-app).

## Supported environments

Use Elixir 1.18 through 1.20 on Erlang/OTP 27 through 29. OTP 25 and 26 are excluded
because the protocol's codecs require the `:json` module introduced in OTP 27.
`config/config.exs` and `examples/edge_agent/config/config.exs` each enforce the OTP set
for their own project. Both Mix projects declare `elixir: "~> 1.18"`; that requirement
admits later Elixir 1.x releases, while the tested support set is 1.18, 1.19 and 1.20.

CI is Linux-only, with one lane per supported OTP major in each job. The repository's
`.tool-versions` pins Elixir 1.20.2 and OTP 29.0.3 for the default development lane.
Change both projects' Mix ranges and supported OTP sets, `.tool-versions` and the CI
lanes in one commit. Windows contributors use WSL2 and keep the clone inside the WSL
filesystem, rather than on a Windows-mounted drive.

## Before a pull request

Run the per-file floor on EVERY file you touched, from the project that owns it: the
library at the repo root, the example app from `examples/edge_agent/`:

```sh
mix format
MIX_ENV=test mix compile --warnings-as-errors   # :test includes test/support
mix credo --strict
mix test
```

In `.github/workflows/ci.yml`, `gate` checks the library and `example` checks
`examples/edge_agent`, alongside toolchain discovery and the final `qualified` gate. The one-command whole-repo check, `mix ci`, runs both jobs'
checks on the current toolchain, with the example section delegated to
`scripts/ci_example.exs`. The library's tests run once with coverage, rather than CI's
separate `mix test` and `mix test --cover` steps. The alias does not reproduce Actions'
checkout, setup-beam, Hex-client installation, PLT caching or compatibility matrix.

It runs the checks in order and exits non-zero if any step failed. Some failing steps end
the run at once; others, the test suite among them, record the failure and let the later
steps run, so read the whole output:

```sh
MIX_ENV=test mix ci
```

`MIX_ENV=test` matters: a bare compile runs in `:dev` and misses warnings in
`test/support/`, which only compiles under `:test`, and `mix ci` refuses to run in any
other environment.

## Tests

Changes to a public contract include its typespecs, examples, error reference and migration
notes. Regression tests should demonstrate both acceptance and refusal with real cryptography
and real services. New documentation guards must reject the violation they claim to detect.

## Protocol dependency bumps

`mix.exs` declares `bounded_authority_protocol` as a range with a security floor; `mix.lock`
records the release inside that range this repository builds against. Any release inside the
range is acceptable: Dependabot proposes each new protocol release and CI decides, and the
example app's lock follows the library's (its parity test fails otherwise).

Moving the floor or crossing the ceiling is a deliberate change. One commit edits the
requirement in `mix.exs`, the dependency wall's three range attributes
(`@protocol_requirement`, `@protocol_floor`, `@protocol_ceiling`; every other probe in the
wall derives from them), both locks, and the Livebook's version sentence, and the CHANGELOG
says the requirement "moves from `x` to `y`", with the `lib/` delta classified as compatible,
corrective, or breaking.

Before planning a protocol upgrade or claiming the checkout matches the latest protocol,
run `bash scripts/check-bap-drift.sh`. This read-only probe compares the local requirement
and lock with hex.pm's latest stable release and the protocol repository's remote `main`
and release-tag refs. It can compare `lib/` changes when the relevant commits are already
available in a sibling protocol checkout. It does not fetch or write to either repository,
and withholds verdicts that depend on unavailable inputs. It is a probe, not a gate,
and is not part of `mix ci`.

## Releases

A release follows the [release runbook](https://github.com/baselabs/bounded_authority_report_adapter/blob/master/docs/release.md): the release commit, the gates
before publication (`kci/**` qualification and landing, the supply-chain attestation,
and an archive checksum equal to the attested one), then the owner dispatches `publish.yml`
from `master` in environment `publish`. That workflow builds and inspects the package and
docs and uploads those exact bytes. Infra verifies the registry read-back within Hex's
one-hour revert window and tags the published commit afterward.

## Docs

Docs for a capability ship in the same change as the capability. These checks keep them
honest:

- `test/doc_samples_test.exs` runs every Elixir code block in the README and guides, and
  every example in the API docs, and checks each `#=> value` line. A block that cannot
  run as written is marked `<!-- doc-sample: fragment -->`, said to be a fragment in the
  text, and must still compile with its free variables bound as parameters. Custodian-specific
  fragments are compiled without substituting for a remote custodian. The Plug recipe runs in
  `examples/edge_agent/test/plug_recipe_test.exs`.
- The generative tests in `test/bounded_authority_report_adapter/keyword_options_test.exs`
  draw from the run's random seed; a failure prints it, and `mix test --seed N` repeats it.
- `test/docs_currency_test.exs` checks error meanings, references, install snippets and
  required contributor guidance.
- `test/docs_contract_test.exs` checks all public type docs and function result contracts
  against compiled documentation and typespecs.
- `test/public_prose_test.exs` checks tracked public text.
- `scripts/check_livebook.exs`, run with `elixir` outside a Mix project, installs the
  public Hex release in a temporary cache and checks every pinned notebook output.
- `test/bounded_authority_report_adapter/livebook_walkthrough_test.exs` runs the Livebook
  and compares each cell's value with the output pinned under it; edit a cell and you
  re-pin its output in the same commit.

If you rename an API, fix the docs in the same commit; the suite tells you which ones.
