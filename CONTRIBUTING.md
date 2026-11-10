# Contributing

Contributions must preserve the invariants the repository exists to hold: the
dependency-direction wall (the library depends only on the public protocol package — never
the authority runtime, never a transport), the closed-atom error discipline, the value-free
telemetry surface, and the test-only status of `test/support/` (nothing there ships).

## Before a pull request

Run the per-file floor on EVERY file you touched, from the project that owns it — the
library at the repo root, the example app from `examples/edge_agent/`:

```sh
mix format
MIX_ENV=test mix compile --warnings-as-errors   # NOT bare mix compile — it skips test/support
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

## Commits

Surgical pathspecs — `git commit -o <files>` or explicit paths, never `git add -A`
(process state and tool directories must never ride in a commit). Single tree on
`master`; no feature branches unless the maintainer asks. Never `git stash`.

## Tests and gates

- New behavior ships red-first: write the test, watch it fail for the intended reason,
  then make it green.
- A new gate must be proven RED by a named mutation before it counts (plant the
  contract violation, confirm the gate fires, restore). A gate that cannot go red is a
  rubber stamp — several of this repo's tests exist specifically to mutation-prove
  their own gates.
- Behavior-CHANGING work greps the tests for the OLD contract before changing it.

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

A release follows the [release runbook](docs/release.md): the release commit, the gates
before the tag (local and remote CI, the supply-chain attestation, and an archive
checksum equal to the attested one), the owner's tag and publish, and the registry
read-back within Hex's one-hour revert window.

## Docs

Docs for a capability ship in the same change as the capability. Three tests keep them
honest:

- `test/doc_samples_test.exs` runs every Elixir code block in the README and guides, and
  every example in the API docs, and checks each `#=> value` line. A block that cannot
  run as written is marked `<!-- doc-sample: fragment -->`, said to be a fragment in the
  text, and must still compile with its free variables as stub parameters. The HSM and
  KMS recipes run against a real local signer; the Plug recipe runs in
  `examples/edge_agent/test/plug_recipe_test.exs`.
- The generative tests in `test/bounded_authority_report_adapter/keyword_options_test.exs`
  draw from the run's random seed; a failure prints it, and `mix test --seed N` repeats it.
- `test/docs_currency_test.exs` checks the error tables, the function references and the
  install snippets against the code.
- `test/bounded_authority_report_adapter/livebook_walkthrough_test.exs` runs the Livebook
  and compares each cell's value with the output pinned under it; edit a cell and you
  re-pin its output in the same commit.

If you rename an API, fix the docs in the same commit; the suite tells you which ones.
