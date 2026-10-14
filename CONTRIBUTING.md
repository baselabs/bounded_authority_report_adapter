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
holds the exact version this repository builds against (ADR-0023 and its October 6, 2026
amendment). Moving the lock, even inside the range, is a deliberate, reviewed change: the
wall test pins the locked version, and a bare `mix deps.update` reds the gate by design.
Moving the floor or the ceiling also edits the requirement and the wall's range attributes.
Every move updates BOTH locks in ONE commit, with the span enumerated and its `lib/` delta
classified per the pin-bump policy (ADR-0023, in the repository's `docs/adr/`; the ADRs are
repository documentation and are not shipped in the package).

## Docs

Docs for a capability ship in the same change as the capability. Three tests keep them
honest:

- `test/doc_samples_test.exs` runs every Elixir code block in the README and guides, and
  every example in the API docs, and checks each `#=> value` line. A block that cannot
  run as written is marked `<!-- doc-sample: fragment -->` and said to be a fragment in
  the text.
- `test/docs_currency_test.exs` checks the error tables, the function references and the
  install snippets against the code.
- `test/bounded_authority_report_adapter/livebook_walkthrough_test.exs` runs the Livebook
  and compares each cell's value with the output pinned under it; edit a cell and you
  re-pin its output in the same commit.

If you rename an API, fix the docs in the same commit; the suite tells you which ones.
