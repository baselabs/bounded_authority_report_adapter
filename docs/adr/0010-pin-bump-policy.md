# 10. Pin-bump policy (when BARA may pin BAP ahead of BA)

Date: 2026-08-17

## Status

Accepted. Records the pin-alignment rationale behind the v0.1.0 bump (`5782634`,
2026-08-12) and EXTENDS it with new policy: that bump verified the empty-`lib/`
condition (quoted in its commit message) but did NOT enumerate the span's surface
classes — and its own class list was wrong both ways (it claimed conformance-corpus
growth that had not happened, and missed the span's largest class, the birth of
`sdks/`). The surface-enumeration gate and the `sdks/`/test-tooling allowances in
Decision 2.2 are NEW in this ADR, not a formalization of prior practice. Extends —
does not supersede — ADR-0003 (whose Consequences cover the BAP→BARA coupling
direction and are silent on BA alignment). Authored retroactively when the
2026-08-17 alignment audit ranked the ungoverned policy the repo's #1 ADR gap;
until now it lived only as the dependency-direction test's rationale comment + a
CHANGELOG paragraph.

## Context

BARA compiles against `bounded_authority_protocol` (BAP) at a pinned git ref
(`mix.exs`). BA (the authority runtime) also pins BAP. The default posture:
**BARA's pin is BA's pin** — BA is the authority layer that validates the
protocol surface, and a BARA-ahead pin couples the adapter to a surface the
authority layer has not yet validated.

The v0.1.0 bump broke from that default: BAP cut an internal reference tag
(`v0.1.0` = `c65d3bea`, 73 commits over BA's then-pin `4c64be3`) explicitly for
internal consumer pinning, and `git diff --stat 4c64be3..c65d3bea -- lib/` was
EMPTY — the V1 signing/verifying surface BARA compiles against was bit-identical.
What the span actually carried (verified at the BAP repo, not from the bump
commit's own enumeration): ADRs 0009–0014 (`docs/`, 17 files), the birth of the
cross-language `sdks/` (54 files — the span's largest class: Python +
TypeScript verifier SDKs), CI, and packaging/prose files — and, despite the bump
commit's claim, **zero** conformance-corpus changes (the corpus under `priv/`
was byte-identical at both pins). What waiting for BA would actually have held
back was BARA's ADR citations, not its corpus.

The question recurs, and the next span looks different: at authoring (a dated
observation of the sibling checkout, 2026-08-17), BAP main had advanced a
further 96 commits past BARA's pin — still zero `lib/` changes, but the span
grows `sdks/` further (Rust added; Python + TypeScript extended), grows the
conformance corpus itself for the first time (`priv/`, 12 files — the class that
most changes the next bump's verification), and touches BAP-internal
`test/conformance` tooling. Pin distances are moving targets: derive them from
the repos, never cite them from prose.

## Decision

1. **Default: alignment.** BARA's BAP pin tracks BA's pin. A BARA-ahead bump is
   an exception, not a preference.
2. **The exception is verifiability-gated, in two parts.** BARA may pin ahead of
   BA ONLY when, for the span `<ba-pin>..<bara-pin>`:
   1. `git diff --stat <ba-pin>..<bara-pin> -- lib/` is **EMPTY** (zero V1
      `lib/` changes — no contract surface the authority layer would need to
      validate), AND
   2. every top-level surface class the span touches is **enumerated in the bump
      commit and classified allowed**. Allowed classes (this ADR's NEW extension
      of the prior "docs/corpus-only" language — the v0.1.0 bump never
      enumerated classes at all): `docs/` (ADRs, design notes), the conformance
      corpus (corpus growth re-verified green by RA2 at the new pin), CI, and
      BAP-internal `test/` + corpus/tooling scripts (e.g. the `conformance/`
      checker). Cross-language `sdks/` (Rust/Python/TypeScript verifier SDKs,
      BAP ADR-0014) are allowed by the same logic — separate build targets that
      do not ship in the Elixir package BARA consumes. BAP repo housekeeping
      (README/SECURITY/`.github/`/`scripts/`) is allowed; a BAP `mix.exs` change
      that alters the package's DEPENDENCY GRAPH is NOT housekeeping — treat it
      as contract surface (no bump; wait for BA). A touched surface that cannot
      be classified = **no bump**; wait for BA.
3. **Re-alignment.** When BA bumps to a newer ref, BARA re-aligns to BA's pin at
   its next dependency pass.
4. **Enforcement is reviewer discipline, by necessity.** BA's pin lives in a
   sibling repo the wall test cannot reach (a cross-repo mechanical check would
   couple BARA's CI to a private sibling). The bumper MUST run the diff check by
   hand and quote the empty-`lib/` result + the surface classification in the
   bump commit message. A BARA-ahead bump commit without that evidence violates
   this policy and is revertible on sight.
5. **The pin is read from `mix.exs`, never from prose** (the AGENTS.md rule; a
   restated sha rots on the next bump).

## Consequences

- The policy's home is this ADR; the RA3 test's rationale comment
  (`dependency_direction_test.exs`, the NARROW EXCEPTION block) is its
  enforcement pointer and now cites it.
- A `lib/`-touching BAP advance — any contract change — can never ride the
   exception: BARA waits for BA (or the user explicitly supersedes this ADR).
- Corpus growth inside an accepted span is not silent: RA2's round-trip against
  the larger published corpus at the new pin is the acceptance evidence, quoted
  in the bump commit.
- The wall test itself is unchanged: it still asserts the pin is declared +
  locked in `mix.exs`/`mix.lock`; the BA-alignment condition stays a
  hand-verified commit-message obligation (decision 4).
