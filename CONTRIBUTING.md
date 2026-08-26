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

Then the one-command whole-repo check (both projects, every gate, aborts at the first red
step — the local parity of CI):

```sh
mix ci
```

`MIX_ENV=test` matters: a bare compile runs in `:dev` and misses warnings in
`test/support/`, which only compiles under `:test`.

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

A `bounded_authority_protocol` version bump is a deliberate, reviewed change — the wall
test pins the locked version, and a bare `mix deps.update` reds the gate by design. Every
bump moves the requirement + both wall attributes + both locks in ONE commit, with the
span's `lib/` delta classified per the pin-bump policy (ADR-0010, in the repository's
`docs/adr/`; the ADRs are repo documentation and are not shipped in the package).

## Docs

Docs for a capability ship in the same landing as the capability. The doc-currency
tripwire (`test/docs_currency_test.exs`) diffs the shipped guides against the code — if
you rename an API, fix the docs in the same commit; the suite will tell you which ones.
