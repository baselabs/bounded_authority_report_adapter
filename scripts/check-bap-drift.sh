#!/usr/bin/env bash
# check-bap-drift.sh — one-command ecosystem drift check for the protocol dependency.
#
# What BARA compiles against is a deliberate, reviewed choice (ADR-0023: the pin follows
# published BAP releases; the wall test's version clauses keep it exact). This probe
# answers, READ-ONLY, the three questions every bump or audit session needs:
#
#   1. what BARA locks + requires          (this repo's mix.lock / mix.exs)
#   2. what hex.pm publishes               (public API; skipped offline)
#   3. how far the protocol's main has     (git ls-remote on the remote URL — no fetch,
#      moved, and what lib/ says             no sibling .git writes, no tag clobber)
#
# It reads no consumer's repository: no consumer's pin gates a BARA bump (ADR-0023).
#
# Verdicts render only from verified inputs; every degraded input prints its own skip
# line. NOT a gate: exits 0 unless the script itself is broken; it never writes to any
# repo (lib/ spans run in the local sibling only when both commits are already present
# locally).

set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
APP="bounded_authority_protocol"
BAP_REMOTE="https://github.com/baselabs/bounded_authority_protocol.git"
BAP_SIBLING="$REPO/../bounded_authority_protocol"

say() { printf '%s\n' "$*"; }
print_files() {
  while IFS= read -r file; do
    [ -n "$file" ] && printf '    %s\n' "$file"
  done <<<"$1"
}

# --- 1. BARA's own declaration (the source of truth — never a restated version) ------
locked="$(sed -nE "s/.*\"$APP\": [{]:hex, :$APP, \"([^\"]+)\".*/\1/p" "$REPO/mix.lock" | head -1)"
requirement="$(sed -nE "s/.*[{:]$APP, \"([^\"]+)\".*/\1/p" "$REPO/mix.exs" | head -1)"

if [ -z "$locked" ] || [ -z "$requirement" ]; then
  say "FAIL: could not parse the lock/resolution from $REPO — run from the repo or fix the format"
  exit 1
fi

say "BARA:    locks $APP $locked (requirement $requirement)"

# --- 2. hex.pm (public API; degrade offline) ------------------------------------------
hex_json="$(curl -fsSm 10 https://hex.pm/api/packages/$APP 2>/dev/null || true)"

if [ -n "$hex_json" ]; then
  hex_metadata="$(printf '%s' "$hex_json" | python3 -c '
import json, sys
d = json.load(sys.stdin)
latest = d["latest_stable_version"]
vs = [r["version"] for r in d["releases"]]
if not isinstance(latest, str) or not latest or latest not in vs:
    raise ValueError("incoherent Hex package metadata")
try:
    vs = sorted(vs, key=lambda v: tuple(int(p) for p in v.split(".")))
except ValueError:
    vs = sorted(vs)
print(latest, " ".join(vs))
' 2>/dev/null || true)"

  if [ -n "$hex_metadata" ]; then
    read -r hex_latest hex_releases <<<"$hex_metadata"
    say "hex.pm:  latest stable $hex_latest (published: $hex_releases)"
  else
    hex_latest=""
    say "hex.pm:  WITHHELD (malformed API response) — release verdicts withheld"
  fi
else
  hex_latest=""
  say "hex.pm:  SKIP (offline or API unreachable) — release verdicts withheld"
fi

# --- 3/4. the protocol remote, read-only (ls-remote: no fetch, no tag clobber) -------
remote_refs="$(git ls-remote "$BAP_REMOTE" 2>/dev/null || true)"

if [ -z "$remote_refs" ]; then
  say "BAP:     SKIP (remote unreachable) — main/tag verdicts withheld"
fi

bap_main="$(printf '%s\n' "$remote_refs" | awk '$2 == "refs/heads/main" {print $1}')"
locked_commit="$(
  printf '%s\n' "$remote_refs" | awk -v t="refs/tags/v$locked^{}" '$2 == t {print $1}'
)"
# Lightweight-tag fallback (cross-vendor note): the peeled ^{} ref exists only
# for annotated tags; for a lightweight tag the tag ref itself IS the commit.
[ -z "$locked_commit" ] &&
  locked_commit="$(printf '%s\n' "$remote_refs" | awk -v t="refs/tags/v$locked" '$2 == t {print $1}')"

if [ -n "$bap_main" ]; then
  say "BAP:     main ${bap_main:0:12}"
  if [ -n "$locked_commit" ]; then
    say "         v$locked tag commit ${locked_commit:0:12}"
  else
    say "         v$locked tag commit unknown on the remote (peeled ref absent — is $locked a real release tag?)"
  fi
fi

if [ ! -d "$BAP_SIBLING" ]; then
  say "BAP:     SKIP (sibling $BAP_SIBLING absent) — lib/-span verdicts limited to locally verifiable pairs"
fi

# --- verdicts (only from verified inputs) ---------------------------------------------
say ""
say "--- verdicts ------------------------------------------------------------"

have_span() {  # $1 $2 = two 40-char commit shas; true when the local sibling can diff them
  [ -d "$BAP_SIBLING" ] || return 1
  git -C "$BAP_SIBLING" cat-file -e "$1^{commit}" 2>/dev/null &&
    git -C "$BAP_SIBLING" cat-file -e "$2^{commit}" 2>/dev/null
}

lib_span() {  # $1 $2 = shas; prints the lib/ file list between them (may be empty)
  git -C "$BAP_SIBLING" diff --name-only "$1" "$2" -- lib/
}

# Release verdict: is a newer hex release published, and what would crossing to it mean?
if [ -n "$hex_latest" ] && [ "$hex_latest" != "?" ] && [ "$hex_latest" != "$locked" ]; then
  say "NEW HEX RELEASE: $locked -> $hex_latest is published."
  newest_commit="$(
    printf '%s\n' "$remote_refs" | awk -v t="refs/tags/v$hex_latest^{}" '$2 == t {print $1}'
  )"
  # Lightweight-tag fallback (same as the locked-version lookup above): the
  # peeled ^{} ref exists only for annotated tags; v0.6.1 ships lightweight,
  # and without this the release verdict read UNVERIFIED for a span both
  # commits of which were locally diffable.
  [ -z "$newest_commit" ] &&
    newest_commit="$(printf '%s\n' "$remote_refs" | awk -v t="refs/tags/v$hex_latest" '$2 == t {print $1}')"

  if [ -n "$newest_commit" ] && [ -n "$locked_commit" ] && have_span "$locked_commit" "$newest_commit"; then
    lib_files="$(lib_span "$locked_commit" "$newest_commit")"

    if [ -z "$lib_files" ]; then
      say "  Release span lib/ is EMPTY; a bump is still a deliberate, enumerated," \
          "same-commit move (wall attributes + both locks; ADR-0023)."
    else
      say "  Release span lib/ is NON-EMPTY:"
      print_files "$lib_files"
      say "  A bump classifies these library changes in the bump commit and exercises" \
          "the consumed surfaces in BARA's suite (ADR-0023 Decision 3)."
    fi
  else
    say "  Span UNVERIFIED (remote tags or local objects unavailable) — verify first-hand" \
        "in the protocol repo before any bump decision."
  fi
elif [ -n "$hex_latest" ]; then
  say "RELEASES: locked $locked is the latest stable — no bump decision pending."
fi

# Main drift: what protocol main carries past our locked version — the
# eligibility question for the NEXT bump (cross-vendor note: the header
# promised this and the script never computed it).
if [ -n "$bap_main" ] && [ -n "$locked_commit" ]; then
  if have_span "$locked_commit" "$bap_main"; then
    main_lib="$(lib_span "$locked_commit" "$bap_main")"

    if [ -z "$main_lib" ]; then
      say "MAIN DRIFT: main sits past our lock with lib/ UNTOUCHED."
    else
      say "MAIN DRIFT: main sits past our lock with lib/ NON-EMPTY:"
      print_files "$main_lib"
      say "  A bump to a release from this span classifies these changes (ADR-0023 Decision 3)."
    fi
  else
    say "MAIN DRIFT: WITHHELD (span not locally verifiable) — locked ${locked_commit:0:12} vs main ${bap_main:0:12}."
  fi
fi

say "-------------------------------------------------------------------------"
say "Probe only — not a gate. Verdicts above came only from inputs actually verified."
