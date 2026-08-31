# ADR 0018: The local-loopback profile pin (BAP 0.2.0 → 0.3.0)

- Status: Accepted
- Date: 2026-08-31
- Extends: [ADR-0010](0010-pin-bump-policy.md) (records a deliberate,
  owner-authorized exception to its alignment default for this one bump)

## Context

BAP 0.3.0 (2026-08-31) adds the byte-distinct local-loopback HTTP application
proof — `bap-application-proof/local-loopback-http/1`, protected `typ:
"ba+loopback-proof"` (BAP ADR-0027). BARA's 0.5.0 release adds
`sign_local_loopback_report/3` against that surface; it cannot be built
against 0.2.0.

ADR-0010's default is **alignment**: BARA's BAP pin tracks BA's pin, and a
BARA-ahead bump may ride the exception ONLY when the span's `lib/` diff is
EMPTY. The `v0.2.0..v0.3.0` release-tag span is `lib/`-NON-EMPTY (verified in
the protocol repo):

```
lib/bounded_authority_protocol/application_profile/local_loopback_http/v1.ex
lib/bounded_authority_protocol/application_profile/local_loopback_http/v1/uri.ex
lib/bounded_authority_protocol/uri_path.ex
lib/bounded_authority_protocol/v1/compact_jws.ex
lib/bounded_authority_protocol/v1/runtime.ex
lib/bounded_authority_protocol/v1/signing_input.ex
lib/bounded_authority_protocol/v1/uri.ex
```

BA (the authority runtime) still selects BAP 0.2.0 exactly. Under ADR-0010's
default, BARA would wait for BA.

The owner explicitly directed this release (2026-08-31 task instruction:
release BARA 0.5.0 against BAP 0.3.0, adding the explicit holder-side signer;
no BA/BAP changes authorized). ADR-0010's consequences clause names exactly
this escape: *"BARA waits for BA (or the user explicitly supersedes this
ADR)."* This ADR is that supersession — scoped to this bump, not a general
retirement of the alignment policy.

## Decision

1. BARA 0.5.0 selects `bounded_authority_protocol == 0.3.0` exactly. Root and
   example locks, the dependency-wall attributes, and the documentation
   identities move together in one commit (the same mechanical discipline as
   the 0.4.0 bump).
2. The substitution for the authority validation BARA is waiting for under
   alignment: BARA executes BAP's complete published acceptance evidence
   through the dependency itself — the unchanged standard corpus oracle
   (RA2, green at the new pin) PLUS the complete local-loopback profile corpus
   (8 proof cases × three declared verdicts, 36 URI admission cases, the
   certified index's sha256 self-declaration, byte-exact certified-proof
   reproduction through the producer/assembler pair BARA drives), PLUS the
   real IPv4/IPv6 listener smoke in the example app. The consumed surface is
   the profile facade + the runtime functions above; nothing else in the span
   is consumed.
3. The alignment debt is recorded, not hidden: BA re-aligns (or explicitly
   ratifies its own 0.3.0 pin) at its next dependency pass, and BARA follows
   per ADR-0010 decision 3. Until then the ecosystem pins differ by design.
4. ADR-0010 otherwise stands unchanged. This is a single-bump supersession
   recorded BEFORE the bump lands, not a precedent: the next `lib/`-non-empty
   span without owner direction still waits for BA.

## Rejected alternatives

- **Wait for BA.** Rejected by the owner's explicit release direction; the
  local-loopback profile is a BARA-facing capability whose consumers are
  development listeners, not the authority runtime.
- **`~> 0.3.0`.** Rejected for the same reason as every prior bump: the exact
  pin is the identity contract; a caret silently accepts an unreviewed later
  patch.
- **Dual BAP lines or vendoring.** Rejected in ADR-0017 and still — they
  conceal rather than resolve identity.
- **Building the profile signer locally in BARA (no bump).** Rejected: it
  would copy normative mechanics (URI admission, profile bytes) that BAP owns
  and certifies — exactly the duplication the dependency wall exists to
  prevent.

## Failure modes and proofs

- **Resolver drift** — the wall test pins requirement + locked version +
   example parity; a bare `mix deps.update` reds the gate.
- **Standard-bytes drift at the new pin** — RA2's round-trip over the
  published standard vector, unconditional (ADR-0010 D4 as amended), green at
  0.3.0 in the bump commit.
- **Profile-semantics drift** — the profile corpus executor reds on any
  verdict or corpus-file divergence (index sha256 enforced at compile time).
- **Profile confusion** — kind-gated assemblers and typ-gated parsers make
  cross-profile bytes structurally impossible; both directions are pinned by
  tests and by the corpus's certified cross-verdicts.
