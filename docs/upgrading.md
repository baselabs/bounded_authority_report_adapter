# Upgrading

Per-version notes, newest first. For the protocol package's own release notes, see its
CHANGELOG; this page covers THIS library's releases.

## 0.6.2

Repository tooling/CI release — no library code, API, or runtime-dependency change; nothing
for a consumer to do. The CI matrix gains a `windows-latest` lane on the pinned versions
(Elixir 1.20.2 / OTP 29.0.3) in both jobs, so clone → build → test is proven on macOS,
Linux, AND Windows (the owner's cross-platform standard, ADR-0019's lane list amended).
Carrying that lane made the developer surface portable rather than POSIX-only: the
dependency-currency gate is now an `.exs` (same behavior), the `mix ci` alias uses an
env-guard instead of `env(1)` re-execs, the release gates spawn `mix` through a Windows
shim and avoid `mktemp`/`Path.wildcard`/cwd-directed tar extraction (each a real Windows
defect the lane caught), and `.gitattributes` keeps every checkout byte-identical. One
named test exclusion: `DriftProbeTest` skips on Windows — its stub harness intercepts
git/curl via POSIX shebang exec, which Git Bash bypasses (the drift probe itself runs
there); the exclusion is declared in the workflow's gate-job comment.

## 0.6.1

Repository tooling/hygiene release — no library code, API, or runtime-dependency change.
The repository now enforces its own toolchain: builds refuse Erlang/OTP majors outside the
supported set {27–29} at config load, before compilation (ADR-0019). OTP 25 and 26 are
explicitly outside the set — `bounded_authority_protocol` 0.4.0's codecs decode through
OTP 27's `:json` module, so the stack cannot compile its test battery there (probe-proven
on the official `elixir:1.18.4-otp-25` and `elixir:1.19.6-otp-26` images). The assert
lives in the repository's `config/config.exs`, which is NOT part of the published
package — consumers are unaffected. The CI matrix keeps its three lanes (1.18/27,
1.19/28, 1.20/29 — one per supported major), now locked to the enforced set. A
dependency-currency gate (latest-first policy, ADR-0020) runs in CI and `mix ci` for
both mix projects; dev-only dependency bumps: `dialyxir` 1.4.8, `ex_doc` 0.40.4
(example app: `req` 0.7.4). Nothing for a consumer to do.

## 0.6.0

The protocol dependency now selects `bounded_authority_protocol == 0.4.0` exactly
(from `== 0.3.0`). BAP 0.4.0 is additive — the v2 contract-major lands beside the
byte-frozen v1 profile — so this is a package-resolution break for consumers retaining
BAP 0.3.x, with zero adapter behavior change. The four signing APIs, return shapes,
key-handle contract, telemetry, and produced V1 wire forms are unchanged.

Run `mix deps.get` and confirm your lock contains one BAP 0.4.0 entry. Do not
override BARA back to BAP 0.3.x or retain parallel BAP lines.

## 0.5.0

The protocol dependency now selects `bounded_authority_protocol == 0.3.0`
exactly. BAP 0.3.0 adds the local-loopback application-proof profile without
changing any standard `dpop+jwt` byte, bound, or verdict — the four existing
signing APIs, return shapes, key-handle contract, telemetry, and produced V1
wire forms are unchanged, and the standard conformance oracle re-ran green at
the new pin. The version moves to a pre-1.0 minor because the exact pin is a
package-resolution break for consumers retaining BAP 0.2.x (see
ADR-0018 for the pin-policy record).

New capability: `sign_local_loopback_report/3` signs the byte-distinct
`ba+loopback-proof` profile for canonical `http://127.0.0.1` / `http://[::1]`
targets with a mandatory nonce. It is additive — nothing existing calls it —
and its errors are the same closed `sign_error()` set. Local-loopback HTTP is
plain HTTP (no TLS, not equivalent to HTTPS); the verifying host owns nonce
reservation, replay control, and listener-derived target state.

Run `mix deps.get` and confirm your lock contains one BAP 0.3.0 entry. Do not
override BARA back to BAP 0.2.x or retain parallel BAP lines.

## 0.4.0

The protocol dependency now selects `bounded_authority_protocol == 0.2.0`
exactly, matching the authority suite's recertified protocol identity. This is a
pre-1.0 minor release because consumers retaining BAP 0.1.x cannot solve the new
exact dependency line. BARA's four signing APIs, return shapes, key-handle
contract, telemetry, and produced V1 wire forms are unchanged.

Run `mix deps.get` and confirm your lock contains one BAP 0.2.0 entry. Do not
override BARA back to BAP 0.1.x or retain parallel BAP lines.

## 0.3.0

Pre-1.0 feature release carrying everything the proposed
[stability contract](#the-10-stability-contract) enumerates: the value-free
telemetry surface, the gate battery (coverage floor, dialyzer, doc warnings,
dependency audits), the package boundary check, the three-cell CI matrix, the
full guide set, the Igniter installer, the doctor preflight, and the
supply-chain workflow. The contract itself is NOT yet operative — 1.0 is
deferred until the release sees real consumer use (owner direction, 2026-08-26);
until then the pre-1.0 SemVer §4 policy applies.

## 0.2.1

- Documentation-only release (links into the repository's `examples/` fixed for the
  published docs).

## 0.2.0

- The protocol dependency moved from a git pin to the public Hex package
  (`~> 0.1.1` at the time). Lockfiles that referenced the private git remote should
  `mix deps.get` fresh.

## The (proposed) 1.0 stability contract

PROPOSED, not yet operative — 1.0 is deferred until this release line sees real
consumer use and the surface settles (owner direction, 2026-08-26). When 1.0 is
cut, the following becomes the PUBLIC SURFACE — breaking changes to it then
require a major version (SemVer §4's pre-1.0 carve-out ends):

- The four signing functions and their return shapes:
  `sign_report/3` → `{:ok, %{grant: binary, proof: binary}}`,
  `sign_anchor/3` → `{:ok, %{anchor: binary}}`,
  `sign_grant/3` → `{:ok, %{grant: binary}}`,
  `sign_key_transition/3` → `{:ok, %{key_transition: binary}}`,
  and their `@spec` input maps (`report()`, `anchor_input()`, `grant_input()`,
  `transition_input()` + the opts maps).
- The four closed error sets — `sign_error/0`, `anchor_sign_error/0`, `grant_sign_error/0`,
  `transition_sign_error/0` — including the fixed `{:producer_error, :invalid}` tuple
  shape.
- The key-handle behaviour: `sign/2`, `public_key/1`, `thumbprint/1`, `key_identity/1`,
  `signing_identity/1` and their `{:ok, _} | {:error, _}` contracts.
- The telemetry surface: `BoundedAuthorityReportAdapter.Telemetry`'s public functions
  (`Telemetry.sign_span/2`, `Telemetry.emit_start/1`, `Telemetry.emit_stop/3`, `Telemetry.objects/0`, `Telemetry.classes/0` — the `BoundedAuthorityReportAdapter.Telemetry` module), the two event
  names, and the value-free metadata contract (adding a metadata KEY is breaking by
  definition — the closed shape IS the contract).
- The dependency posture: the library depends only on the public protocol package (plus
  `:telemetry`) — a runtime dependency on anything else is breaking.

### Reserved break-rights (changes that may land in a MINOR)

The following may change without a major, each announced in the CHANGELOG:

- Security fixes, including ones that narrow behavior (a construct previously accepted
  that should never have been).
- Behavior-correcting fixes where the shipped behavior contradicts the documented
  contract.
- New compiler warnings or dialyzer findings becoming errors (raise your floor, not
  your lockstep).

### Frozen regardless

The wire formats this library produces are the protocol package's, frozen per its
contract-major discipline: a proof, grant, anchor, or transition compact signed by
version N verifies under the protocol's rules for that version's wire profile. This
library never invents or extends a wire format.
