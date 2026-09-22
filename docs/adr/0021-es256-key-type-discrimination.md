# 21. ES256 key-type discrimination and the V3 signing surface

Date: 2026-09-22

## Status

Accepted (B2 — the ES256 workout upgrade). Governs the key-handle key-type
discriminator, the contract-major-3 signing surface, and the producer-side
low-S duty this library carries under BAP 0.5.1
([BAP ADR 0035](https://github.com/baselabs/bounded_authority_protocol/blob/main/docs/adr/0035-es256-contract-major-activation.md)).

One independent adversarial design pass preceded implementation (2026-09-22,
claude peer, attended per the host's cross-vendor rule; receipt
`.kimosabe/reviews/2026-09-22-b2-adr0021-design-claude.md`): 18 findings —
2 BLOCKING, 11 SHOULD-FIX, 5 NOTE — adjudicated 17 accepted (repairs folded
into this text) and 1 accepted-with-modification (the proposed dropping of
the v2 corpus leg is overridden by the owner-directed B2 scope, which names
all three corpora; see Consequences). Two findings corrected factual errors
in the draft: BAP 0.5.1's v3 assembler performs NO signature range check
(any 64-byte blob assembles), and OTP `:crypto.sign/5` ECDSA output is DER,
not raw `r || s`.

## Context

BAP 0.5.0 activated contract-major 3 — the `BAP3-ES256-SHA256` suite: ECDSA
P-256 with SHA-256 (`ES256`, RFC 7518 §3.4), RFC 7518 §3.4 raw `r || s`
64-byte signatures with REQUIRED low-S canonicality, EC JWK holder keys
`{crv: "P-256", kty: "EC", x, y}`, the 65-byte uncompressed-SEC1 raw public
key, `alg: "ES256"`, payload `v: 3`, and `BAP3-*` domain separators
(`spec/bap-v3.md` §1–§5, read first-hand). BARA's exact pin moved to 0.5.1 in
this slice's first commit; the pin bump alone changes nothing about what this
library can sign.

Until now BARA's signing surface has been Ed25519-shaped end to end: the three
key resolvers (`resolve_public_key/1`, `resolve_key_identity/1`,
`resolve_signing_identity/1`) guard on exactly 32 bytes, the shared
`verify_signature/3` guard hardcodes `:crypto.verify(:eddsa, ...)`, the
transition builder pre-checks `next_public_key` at 32 bytes, and the
`sign_via_handle/2` tail accepts a 64-byte signature. A holder presenting a
P-256 key — the only key type a v3 credential can carry — is rejected before
signing. Nothing in the key-handle contract says WHY it is Ed25519-shaped; it
was the only suite that existed.

The open design questions are where the major is selected, how the key type
is discriminated, who owns the producer-side low-S duty, and how far the
producer gates mixed-major inputs. The constraints that dominate: the private
key still never enters this library (charter §6 invariant 1); profile
selection here has a house precedent — ADR-0018's local-loopback profile pin —
that profile selection is the FUNCTION NAME, never an option and never
inferred; and the closed-error contract (a caller-side raise out of any entry
point is a defect, not a diagnostics problem).

## Decision

1. **Major selection is the module name.** The contract-major-3 surface is a
   new namespace module, `BoundedAuthorityReportAdapter.V3`, exposing the four
   standard instantiations with the same signatures and closed-atom error sets
   as their major-1 counterparts: `sign_report/3`, `sign_grant/3`,
   `sign_anchor/3`, `sign_key_transition/3`. There is NO v3 local-loopback
   entry point: the local-loopback application-proof profile is bound to
   contract-major 1 (`spec/bap-v3.md` §2) and BAP's v3 façade exposes no
   loopback functions. The flat `BoundedAuthorityReportAdapter` module remains
   the major-1 surface — its valid-input behavior for major-1 objects is
   byte-identical, with ONE deliberate tightening (Decision 8's mixed-major
   fail-fast gate, CHANGELOG'd). This mirrors BAP's own `V1`/`V2`/`V3` façade
   topology and follows ADR-0018: the name the caller types selects the
   profile; no option key, no inference from key shape, URI, environment, or
   a failed producer call. A `.V1` alias is deliberately NOT shipped: the flat
   module IS the major-1 surface and says so in its moduledoc; a pure alias
   adds public API with no consumer. Contract-major 2 has no signing surface
   here — a recorded gap, not an accident (see Consequences).

2. **The key-type discriminator is the public key's wire shape AND point
   validity, enforced at the resolver boundary of each major's entry
   points.** The v1 resolvers continue to accept exactly 32-byte Ed25519 keys
   (byte-identical behavior). The v3 resolvers accept exactly the 65-byte
   uncompressed SEC1 point (`0x04 || x || y`) that is a VALID P-256 point —
   validated through `BoundedAuthorityProtocol.V3.EcJwk.encode_public/2`,
   which enforces the width, the `0x04` prefix, coordinate range (`< p`), and
   on-curve membership by pure arithmetic in one certified call; every
   failure maps to `{:error, :invalid_key_handle}`. Width alone is not
   discrimination: a secp256k1 point from a mis-wired custody slot is also
   65 bytes with an `0x04` prefix, and on the GRANT path BARA's verify guard
   is the key's first consumer (the v3 grant bytes carry only `kid` and
   `holder_thumbprint`; BAP's grant producer never touches the issuer public
   key), so an off-curve key would raise out of `:crypto.verify` as an
   ErlangError — the closed-error contract broken (adversarial finding 1,
   probe-verified). The same point validation applies to a v3 transition's
   caller-supplied `next_public_key` (the successor of a v3 chain key is
   itself a v3 chain key). The two accepted shapes are disjoint, so the
   discriminator is total: a key that is not exactly one of the two is
   `:invalid_key_handle` everywhere, and a key of the right type presented to
   the wrong major's entry point fails closed as `:invalid_key_handle` in
   both directions. This mirrors the protocol's own posture — a conforming
   verifier detects the profile from the artifact's bytes alone
   (`spec/bap-v3.md` §1) — pushed one step earlier, to the producer's key
   material: the bytes of the key name the suite that can sign with it.

   Relying on `V3.EcJwk` (a public, `@doc`'d module outside the versioned
   façade) is a recorded dependency-surface decision: the coupling is
   compile-time and therefore fail-loud (if BAP moves the module, this
   library stops compiling rather than silently accepting bad keys), and the
   alternative — re-deriving the on-curve arithmetic locally — would copy
   certified normative mechanics BAP owns (the ADR-0018 precedent this ADR
   itself applies in Decision 5's mirror decision).

3. **The handle callbacks are unchanged in shape, and their contract
   documentation becomes suite-parameterized.** `sign/2` returns a 64-byte
   binary — an Ed25519 signature under the v1 entry points, the RFC 7518 §3.4
   raw `r || s` form under the v3 entry points. The v3 `sign/2` contract is
   CLOSED on the raw form: a DER return (OTP `:crypto.sign/5` ECDSA output —
   71 bytes, `0x30`-led — and the native spelling of many HSM/KM stacks) is
   `{:error, :signing_failed}`, never silently converted here; "DER is never
   a v3 wire spelling" (`spec/bap-v3.md` §3.2), and a handle that can only
   produce DER must convert before returning (the install scaffold's comments
   and a `docs/recipes.md` P-256 recipe carry the conversion sketch). Note
   the width guard is NOT a DER discriminator — a DER signature can
   coincidentally be 64 bytes — which is one more reason the scalar range
   check (Decision 4) runs before anything else. `public_key/1`,
   `key_identity/1`, and `signing_identity/1` return the raw public key whose
   accepted width is selected by the entry point's major (32 or 65 bytes).
   `thumbprint/1` returns the RFC 7638 raw digest over the SUITE'S preimage:
   the OKP form `{crv, kty, x}` for major-1 keys, the EC form
   `{"crv":"P-256","kty":"EC","x":X,"y":Y}` for major-3 keys
   (`spec/bap-v3.md` §3.1) — the callback docs state both, and the doctor
   (Consequences) derives the expected thumbprint from the resolved public
   key and treats a mismatch as fatal, because the issuer's `cnf.jkt` is
   minted from that digest and a wrong preimage fails every envelope at
   verification with no producer-side catch. Existing major-1 handles compile
   and behave identically; a v3 handle is the same behaviour with P-256
   custody behind it. No tagged key-type returns, no new callbacks.

4. **Producer-side low-S normalization is BARA's duty, in the shared v3
   signing tail, with the order pinned: decode → range-check the RAW return →
   normalize → assert → verify → assemble.** Concretely: decode `r` and `s`
   as unsigned big-endian; REJECT unless `0 < r < n` AND `0 < s < n` (`n` the
   P-256 group order) — this runs BEFORE any arithmetic on `s`, because the
   conditional subtraction on an out-of-range `s` produces a negative scalar
   whose re-encoding is primitive-dependent (`:binary.encode_unsigned/1`
   raises on negatives; a bit-syntax re-encode silently wraps) — then apply
   the one conditional subtraction (`s ← n − s` when `s > n/2`, `n/2` the
   integer floor `div(n, 2)`: `n` is odd, `s = n/2⌋` stays untouched,
   `s = ⌊n/2⌋ + 1` maps to exactly `⌊n/2⌋`), assert the normalized `s ≤
   ⌊n/2⌋`, verify, assemble. Rationale: the profile binds PRODUCERS —
   "producers MUST normalize" (`spec/bap-v3.md` §3.2, `REQ3-SIGNING-low-s`) —
   and this library is the producing side. ECDSA verification accepts BOTH
   spellings `(r, s)` and `(r, n − s)`, so the wrong-key verify guard alone
   cannot catch a high-S emission; and there is NO backstop downstream — BAP
   0.5.1's v3 assembler accepts any 64-byte signature blob (verified
   first-hand: the assembler checks width only; `Es256.valid_raw_signature?/1`
   has verify-side callers exclusively), so a high-S or out-of-range emission
   through this library would become a compact that every conforming verifier
   rejects. The range/low-S duty is wholly this library's. Normalizing
   centrally means a handle that returns a high-S spelling — an HSM that
   applies no low-S convention, say — still yields conforming bytes.
   Consequence for custody audit stacks, documented: the compact's signature
   segment may differ from the bytes the HSM signed and logged (the `s`
   half); audit reconciliation keys on `(r, message)`, not the 64 bytes.

5. **The wrong-key verify guard is per suite, decorrelated from BAP's
   verifier, and exception-contained.** The v3 guard range-checks the
   normalized raw signature (`0 < r < n`, `0 < s ≤ ⌊n/2⌋`; zero or oversized
   scalars fail), re-encodes minimal-octet DER (the `0x00` sign guard when a
   scalar's high bit is set — without it roughly half of all valid signatures
   fail their own guard — and short-form lengths only, unreachable-long by
   construction), and verifies via `:crypto.verify(:ecdsa, :sha256, message,
   der, [public_key_65, :prime256v1])`, with the whole call wrapped
   rescue/catch → `:signing_failed` (a backend that raises returns the closed
   error value, `REQ3-SIGNING-backend-reject`; BAP's own `V3.Es256`
   rescues for the same reason, and an off-curve key raises here even past
   Decision 2's point validation if the backend is stricter than the
   arithmetic). This implementation is deliberately INDEPENDENT of BAP's
   `V3.Es256` (which stays verify-side and `@moduledoc false`): the
   producer's wrong-key guard not sharing bytes with the verifier's check is
   a decorrelation property, and equivalence is proven by a
   differential-agreement test over randomized signatures — valid pairs and
   single-bit mutations — where this guard's verdict must match
   `V3.Es256.verify/3`'s on every sample. The v1 guard (`:eddsa`, `:none`) is
   unchanged. The rotation-race defense carries over unchanged: the
   signature must verify against the key resolved in the same operation's
   snapshot, else `:signing_failed`.

6. **Struct sourcing follows BAP's v3 façade exactly.** v3 proofs and grants
   build BAP's own `%BoundedAuthorityProtocol.V3.Proof{}` /
   `%V3.Grant{}` (v3-specific structs; the grant's `operations` are
   `%V3.Operation{}`, whose selector algebra is v2's five kinds carried into
   v3); v3 anchors and transitions reuse the shared
   `%V1.BoundaryAnchor{}` / `%V1.KeyTransition{}` producer structs BAP's v3
   runtime consumes, with 65-byte keys (Decision 2's validation).

7. **Telemetry emits the same closed object atoms, and its documentation
   says what the axis is.** The v3 entry points emit `:report`, `:anchor`,
   `:grant`, and `:key_transition` spans — the object axis names the object
   KIND, not the entry point (nine entry points, five kinds including
   local-loopback). No new telemetry surface, no new fields; a `major: 1 | 3`
   metadata key was considered and declined: it would be the first semantic
   field beyond the closed object/class pair on a surface whose invariant is
   "two closed atoms and NOTHING else", and the major is caller-side
   knowledge recoverable from the call site; extending the metadata shape is
   a named-misuse-path change that deserves its own deliberate decision, not
   a rider on this slice. `telemetry.ex`'s wording and `docs/telemetry.md`
   move with this ADR (the doc is diffed against `@objects` by
   `telemetry_test.exs`).

8. **Mixed-major report inputs fail fast at the producer.** `spec/bap-v3.md`
   §1 (`REQ3-EVO-proof-major-equals-grant`, `REQ3-EVO-mixed-major-invalid`)
   makes mixed-major credentials invalid by construction, and BAP's v3 proof
   producer only HASHES `grant_compact` (`ath`) without parsing its header —
   so `V3.sign_report/3` with a v1 grant (the likely caller migration
   mistake) would return `{:ok, envelope}` for a credential no verifier will
   ever accept: a quiet interop failure of exactly the class this library
   exists to make loud. Both report validators (v1 and v3 — symmetrically)
   therefore route `grant_compact` through the respective major's
   `untrusted_key_locator/2` — a bounded, signature-free protected-header
   walk whose closed `alg` check pins the major (v3: `ES256`; v1: `EdDSA`) —
   returning `{:error, :invalid_report}` on mismatch before any key is
   resolved. On the v1 path this is a deliberate, CHANGELOG'd tightening:
   previously a v3 grant under `sign_report/3` produced an envelope that
   failed downstream at `check_envelope/2`; now it fails at the producer with
   the clean input error, per this repo's own fail-fast principle.

9. **Errors: the same closed-atom sets per operation, and no entry point
   raises.** Every path — including hostile handles (DER returns, out-of-range
   scalars, off-curve keys, exits/throws mid-callback) — collapses to the
   operation's closed error atoms.

## Rejected alternatives

- **An options-keyed major** (`sign_report(report, handle, major: 3)`):
  violates the profile-selection precedent (ADR-0018) twice over — an option
  has a default, and a defaulted option is an inference the caller never
  made. The wire profile of the output bytes is exactly the class of thing
  selection-by-name exists for.
- **Tagged key-type returns from the callbacks**
  (`public_key/1 -> {:ok, {:p256, key}}`): a breaking change to every
  existing handle that buys no discrimination — the two raw wire shapes are
  already disjoint, and the v3 raw form IS the 65-byte SEC1 binary
  (`spec/bap-v3.md` §3.1). The handle contract stays key-material-shaped,
  not key-type-tagged. (A tag would not have caught the off-curve key either
  — Decision 2's point validation is what closes that.)
- **Shape-driven façade selection inside one set of functions** (the key's
  width picks the BAP façade internally): the silent-major hazard —
  `sign_report/3` would emit `v: 3` bytes for one caller and `v: 1` bytes
  for another with no visible difference at the call site. A contract major
  is a profile, and profile selection is explicit (ADR-0018). (The doctor
  DOES infer the suite from key shape — defensibly: a diagnostic emits a
  report, not wire bytes, so the silent-major hazard does not exist there.)
- **Leaving low-S normalization to the handles**: every implementer
  re-derives the duty, and one that forgets ships non-conforming compacts
  that pass this library's guard and fail every conforming verifier — a
  quiet failure priced at interop. The producer is this library (Decision 4).
- **Rejecting a high-S return as `:signing_failed` instead of normalizing**:
  stricter-looking, but wrong on the spec — normalization is the producer's
  MUST (`REQ3-SIGNING-low-s`), and `(r, n − s)` is an equally valid
  verification spelling, so rejection would fail conforming custodians for
  no security gain (malleability is closed by emitting ONE spelling, which
  normalization does). The doctor's low-S advisory is the compensating
  feedback: a handle that always returns high-S still learns it is
  non-canonical, without being failed.
- **Consuming BAP's `V3.Es256` verify internals directly** instead of an
  independent guard: rejected to keep the producer's guard decorrelated from
  the verifier's implementation; equivalence is carried by the
  differential-agreement test instead (Decision 5).

## Failure modes and proofs

Every leg is RED-first against the un-implemented surface, through the real
dependency (BAP 0.5.1):

- **Cross-type rejection — the full ten-cell matrix.** Each of the four
  operations × both directions: an Ed25519 handle under each `V3.*` entry
  point and an EC handle under each v1 entry point return
  `{:error, :invalid_key_handle}` before `sign/2` is reached (the three
  resolvers and the transition's `next_public_key` guard each exercised). A
  33-byte compressed point and a 64-byte blob are invalid under BOTH majors.
  The grant legs include `{:issuer, kid, wrong_width_key}` snapshots for
  both majors, proving the C1 role gate still gates after the width literal
  widens (the C1 clause and the width guard share a clause head).
- **Point validation.** A 65-byte off-curve point (and an on-curve wrong-
  curve point) is `:invalid_key_handle` on every v3 path INCLUDING
  `V3.sign_grant/3` (whose bytes never reach BAP's own arithmetic) and as a
  v3 transition's `next_public_key` (`:invalid_transition`).
- **Scalar ordering and boundaries.** Handle returns with `s = n − 1`, `s =
  n`, `s = n + 1`, `r = 0`, and `r = n` each collapse to `:signing_failed`
  with no raise and no compact — the range check precedes normalization.
- **High-S normalization.** A handle whose `sign/2` deterministically returns
  a high-S spelling still produces a compact whose `s ≤ ⌊n/2⌋` (byte-level
  assertion on the emitted signature segment) that verifies green through
  `V3.check_envelope/2`.
- **Low-S pass-through.** A low-S return re-emits byte-identically
  (normalization is one conditional subtraction, not a re-sign).
- **DER rejection.** A handle returning OTP's native DER ECDSA output
  (71 bytes) is `:signing_failed`, never converted, never a compact.
- **Wrong-key rotation race — both suites.** A handle that snapshots key A
  and signs with key B returns `:signing_failed` under the v3 tail. The
  right-width wrong-suite leg: a handle whose `public_key/1` returns a valid
  65-byte point but whose `sign/2` returns an Ed25519 signature yields
  `:signing_failed`, never a compact (the width guard cannot separate the
  suites; only the verify can).
- **Differential agreement.** Over randomized valid and single-bit-mutated
  signatures, this library's v3 verify guard and BAP's
  `V3.Es256.verify/3` agree on every sample.
- **Round-trips.** All four v3 objects sign through this library and verify
  green through BAP's v3 façade (`check_envelope/2`, `verify_grant/3`,
  `verify_historical_anchor/3`, `verify_key_transition/4`) with 65-byte
  trust inputs.
- **Cross-major byte-distinctness.** A v3 envelope reds under
  `V1.check_envelope/2` and a v1 envelope reds under `V3.check_envelope/2`
  (BAP-enforced; pinned here as an ecosystem property of this library's
  output).
- **Mixed-major fail-fast.** `V3.sign_report/3` with a v1 grant and
  `sign_report/3` with a v3 grant each return `{:error, :invalid_report}`
  before any key resolution.
- **v1 byte identity across the tail refactor.** A byte-identity fixture for
  all four v1 objects (fixed handle key, message, `:proof_id`,
  `:issued_at` — Ed25519 is deterministic, so the compact is fully
  determined) is captured against the CURRENT pre-refactor code and must
  still pass after the shared tail becomes suite-parameterized: green
  verdicts cannot hide a byte-level regression.

## Consequences

- The flat module is now explicitly the major-1 surface, and its moduledoc
  says so; the v3 surface is additive — a minor version under the 0.x
  convention this repo follows (0.7.0).
- **Contract-major 2 has no signing surface — a recorded gap.** BAP's v2
  activated the range selector kinds under the same Ed25519 suite; no
  consumer has asked BARA to sign v2 bytes, and B2 does not add it. The five-
  kind algebra IS reachable through v3 (v3 incorporates v2's selector set,
  `spec/bap-v3.md` §4), so the range kinds are not blocked on a v2 surface.
  A future `V2` module, if ever demanded, follows this ADR's pattern.
- `mix bounded_authority_report_adapter.doctor` learns the same
  discriminator, with a `--major 1|3` flag: by default it reports which of
  the two accepted shapes it found and which majors that unlocks (fatal only
  on a key valid for neither); with `--major` it applies that major's strict
  width gate as a fatal. Its `--live` probe verifies with the matching
  algorithm (ECDSA probe rescue-contained), and a high-S observation is an
  ADVISORY that names BARA's normalization (a high-S handle is conforming
  through this library — failing it would be a false alarm; the advisory is
  how the custodian still learns). The doctor derives the expected
  thumbprint from the resolved public key (OKP preimage for 32-byte keys, EC
  preimage for 65-byte keys) and treats a mismatch with `thumbprint/1` as
  fatal.
- The install task's scaffold comments and the consumer docs state both key
  shapes, both majors, the closed raw-`r||s` `sign/2` contract, and the
  DER→raw conversion sketch for custodians whose stack emits DER.
- **Documentation and gate surface this ADR moves (enumerated so the
  reconciliation is this slice's, not a red gate's discovery):** the
  `@callback` docs (suite-parameterized, `thumbprint/1` preimages);
  `docs/telemetry.md` + `telemetry.ex` wording (nine entry points, five
  object kinds); `docs/charter.md` (the Ed25519-worded signing invariant and
  party table); `docs/strategy.md`; `docs/errors.md` (the 32-byte-worded
  `:invalid_transition` line); `docs/getting-started.md`;
  `docs/recipes.md` (the Ed-only HSM sign recipe gains a P-256 sibling);
  `docs/consumer-integration.md`; `docs/upgrading.md` (the 0.7.0 migration
  note incl. the v1 mixed-major tightening); `usage-rules.md`; the CHANGELOG
  0.7.0 entry; the README index ↔ ex_doc extras gate.
- **The conformance harness grows the three-corpus leg, superseding
  ADR-0013 decision 1's one-vector scope by explicit owner direction** (the
  B2 instruction of 2026-09-22 names all three corpora and their index
  pins). The extension is recorded the way ADR-0018 recorded supersession —
  explicit, scoped, owner-facing — as a dated amendment on ADR-0013 itself.
  Shape (amended after the B2 code review): all three corpora's index SHA-256
  pins asserted independently (v1 `4cb5072a…`, v2 `6de6289b…`, v3
  `a5c8075e…`), full integrity through the package loader, every case
  executed through the package's certified runner with the executed census
  proven from the runner's RESULTS, and a `.raw`-sidecar tamper leg proving
  hash enforcement. ALL THREE legs are dep tamper-evidence — BAP's certified
  corpus through BAP's own functions; the BARA-side production oracle is a
  SEPARATE test surface, not this leg: `v3_sign_test.exs`'s round-trips
  (this library signs; the v3 façade verifies) and its
  differential-agreement leg are where BARA's own producing path is proven.
  The runner's byte-exact signing-input cases certify the same producer
  functions BARA calls, at the package level. An exhaustive-coverage guard
  reds on corpus growth (the index pin) until deliberately extended.
- A future contract-major 4 with a new key type adds a new namespace module
  and a new accepted wire shape at its resolvers; nothing in this design
  requires revisiting the v1 or v3 surfaces.
