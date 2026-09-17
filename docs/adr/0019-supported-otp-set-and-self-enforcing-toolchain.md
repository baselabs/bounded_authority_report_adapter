# ADR 0019: The supported-OTP set and the self-enforcing toolchain

- Status: Accepted
- Date: 2026-09-16

## Context

The repository built on whatever toolchain happened to be on PATH. The only
declarations were the `elixir: "~> 1.18"` requirement in `mix.exs` (which Mix
checks, but which says nothing about Erlang/OTP), `.tool-versions` (a dev-lane
convention with no enforcement), and a CI matrix whose three lanes were chosen
by hand — nothing tied them together, and nothing refused a foreign OTP major
before poisoned `_build`/PLT state produced phantom errors.

The owner settled two governing points (2026-09-16 dispatch): the supported
Elixir line stays a RANGE in `mix.exs` (this audit enforces what is declared —
supported minors 1.18/1.19/1.20), and the supported-OTP set is DISCOVERED by
probe, never assumed. Probes run 2026-09-16:

- asdf `list all elixir`: 1.18.x builds on otp-25/26/27 (plus 1.18.4-otp-28);
  1.19.x on otp-26/27/28; 1.20.x on otp-27/28/29.
- Official docker tags exist for the boundary pairs: `elixir:1.18.4-otp-25`
  (200), `elixir:1.19.5-otp-26` (200), `elixir:1.19.6-otp-26` (200).
- bob (`repo.hex.pm`→`builds.hex.pm`) has ubuntu-24.04 builds through OTP 29
  (the `erlef/setup-beam` substrate for any lane).

Image existence is necessary, NOT sufficient — discovery also probes what
actually compiles. Both lower majors FAILED the compile probe:

- docker `elixir:1.18.4-otp-25` and `elixir:1.19.6-otp-26`, `MIX_ENV=test mix
  compile` on a repo copy — identical failure:
  `** (UndefinedFunctionError) function :json.decode/1 is undefined (module
  :json is not available)` in `test/support/.../local_profile_case.ex`.
- Direct probe: `code:ensure_loaded(json)` → `{error,nofile}` on OTP 25 and
  26. The `json` module enters stdlib in OTP 27.

The reason is structural, not test-only: `bounded_authority_protocol` 0.4.0's
own runtime decodes through `:json` (`deps/bounded_authority_protocol/lib/
bounded_authority_protocol/v1/json.ex:73` — every codec: compact_jws, jwk,
boundary_anchor, key_transition), so the signing path itself cannot run on
25 or 26. The stack's true floor is OTP 27.

The audit's initial image-availability reading ({25..29}, then {26..29}) was
corrected BY the compile probes — the discovery discipline working as
intended.

## Decision

1. The supported-OTP set is **{27, 28, 29}** — every OTP major on which the
   dependency stack compiles for a supported Elixir minor (1.18/1.19/1.20).
   **OTP 25 and 26 are excluded** with the probe evidence above. The set is
   re-probed whenever the Elixir line or the protocol pin moves; it is
   discovered, not decided.
2. Both mix projects (library and `examples/edge_agent`) enforce the set
   themselves: `config/config.exs` raises at config load — before compilation
   and before dependency resolution — when
   `to_string(:erlang.system_info(:otp_release))` is outside the set. The
   library's `config/` is NOT in the package `files:` allowlist: the assert
   governs THIS repository's builds, never a consumer's (the exact-set census
   in `scripts/check_package.exs` keeps it that way).
3. **Lockstep quadruple**: the `mix.exs` Elixir range, the config assert's
   set, `.tool-versions` (the dev lane, asdf), and the CI matrix lanes move
   together in ONE commit. Divergence in either direction — a lane outside
   the set, a supported major without a lane — is a defect.
4. The CI matrix carries one lane per supported major — 1.18/27.3.4.14,
   1.19/28.5.0.3, 1.20.2/29.0.3 — the three lanes the matrix already ran;
   this ADR moves them from hand-chosen to lockstep-bound to the enforced
   set.

## Rejected alternatives

- **Including OTP 25/26** (the raw image-availability set): the dependency
  stack cannot compile there; a lane that cannot go green is not support,
  and pretending otherwise would make the lockstep rule meaningless.
- **A single-version pin** (e.g. `elixir: "1.20.2"`): rejected by the settled
  owner policy — a supported range, not a re-decided single-version lock.
- **Enforcement via a CI-only guard**: rejects foreign toolchains only after
  the push; the incident class (silent foreign-toolchain compiles poisoning
  local state) happens before CI ever sees it.
- **`.tool-versions` as the enforcement surface**: it is a dev-lane hint,
  not a gate — asdf warns, Mix never sees it.

## Failure modes and proofs

- `system_info(:otp_release)` returns a CHARLIST; `to_string/1` is mandatory
  or the assert raises on every run regardless of the running major.
- Proofs recorded 2026-09-16: (a) `MIX_ENV=test mix compile` green on the dev
  lane (1.20.2/29) for both projects; (b) docker `elixir:1.17.3-otp-27` on a
  repo COPY refuses with Mix's own targets error — "You're trying to run
  :bounded_authority_report_adapter on Elixir v1.17.3 but it has declared in
  its mix.exs file it supports only Elixir ~> 1.18"; (c) the foreign-major
  refusal runs on the OFFICIAL images `elixir:1.18.4-otp-25` and
  `elixir:1.19.6-otp-26` (in-range Elixirs on majors outside the set): the
  assert raises its exact message at config load before any compilation;
  additionally the gate itself is mutation-proven (a copy with 29 removed
  from the set raises at `Config.__eval__!`); (d) docker `elixir:1.19.6-otp-28`
  compiles the final dependency set green on a repo COPY — the non-dev
  supported lane pre-validated locally. All refusal legs run on throwaway
  copies so the main tree's `_build` never sees a foreign toolchain.
