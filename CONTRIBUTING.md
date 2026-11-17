# Contributing

Contributions must preserve the invariants the repository exists to hold: the
dependency-direction wall, closed-atom errors, value-free telemetry and test-only status of
`test/support/` (nothing there ships). Required runtime dependencies are the public protocol
package and telemetry, with optional Igniter installer support. Authority-runtime and
transport dependencies are excluded from the library.

## Before a pull request

Run the per-file floor on EVERY file you touched, from the project that owns it: the
library at the repo root, the example app from `examples/edge_agent/`:

```sh
mix format
MIX_ENV=test mix compile --warnings-as-errors   # :test includes test/support
mix credo --strict
mix test
```

Then the one-command whole-repo check (both projects, every gate, the local parity of CI).
It runs the steps in order and exits non-zero if any step failed. Some failing steps end the
run at once; others, the test suite among them, record the failure and let the later steps
run, so read the whole output:

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

## Releases

A release follows the [release runbook](https://github.com/baselabs/bounded_authority_report_adapter/blob/master/docs/release.md): the release commit, the gates
before the tag (local and remote CI, the supply-chain attestation, and an archive
checksum equal to the attested one), the release tag and publication, and the registry
read-back within Hex's one-hour revert window.

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
- `test/docs_currency_test.exs` checks error meanings, references and install snippets.
- `test/docs_contract_test.exs` checks all public type docs and function result contracts
  against compiled documentation and typespecs.
- `test/public_prose_test.exs` checks tracked public text.
- `scripts/check_livebook.exs`, run with `elixir` outside a Mix project, installs the
  public Hex release in a temporary cache and checks every pinned notebook output.
- `test/bounded_authority_report_adapter/livebook_walkthrough_test.exs` runs the Livebook
  and compares each cell's value with the output pinned under it; edit a cell and you
  re-pin its output in the same commit.

If you rename an API, fix the docs in the same commit; the suite tells you which ones.
