#!/usr/bin/env bash
# check-bap-drift.sh — one-command ecosystem drift check for the protocol dependency.
#
# What BARA compiles against is a deliberate, reviewed choice (ADR-0010's discipline,
# carried into the Hex era by the wall test's version clauses). This probe answers,
# READ-ONLY, the four questions every bump/re-align/audit session needs:
#
#   1. what BARA locks + requires          (this repo's mix.lock / mix.exs)
#   2. what hex.pm publishes               (public API; skipped offline)
#   3. where the authority runtime's pin   (sibling ../bounded_authority, AS CHECKED OUT)
#      sits relative to ours
#   4. how far the protocol's main has     (git ls-remote on the remote URL — no fetch,
#      moved, and what lib/ says             no sibling .git writes, no tag clobber)
#
# Verdicts render only from verified inputs; every degraded input prints its own skip
# line. NOT a gate: exits 0 unless the script itself is broken; it never writes to any
# repo (lib/ spans run in the local sibling only when both commits are already present
# locally).

set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
APP="bounded_authority_protocol"
BAP_REMOTE="https://github.com/baselabs/bounded_authority_protocol.git"
BA_SIBLING="$REPO/../bounded_authority"
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

# --- the authority runtime's pin (sibling files, AS CHECKED OUT — not fetched) -------
ba_version=""
ba_pin=""

if [ -f "$BA_SIBLING/mix.exs" ]; then
  ba_version="$(python3 -c '
import re, sys
text = open(sys.argv[1], encoding="utf-8").read()
match = re.search(
    r"\{\s*:bounded_authority_protocol\s*,\s*\"==\s*([^\"]+)\"\s*\}",
    text,
)
print(match.group(1) if match else "")
' "$BA_SIBLING/mix.exs" 2>/dev/null || true)"

  if [ -n "$ba_version" ]; then
    ba_locked="$(python3 -c '
import re, sys
text = open(sys.argv[1], encoding="utf-8").read()
match = re.search(
    r"\"bounded_authority_protocol\"\s*(?::|=>)\s*\{:hex,\s*:bounded_authority_protocol,\s*\"([^\"]+)\"",
    text,
)
print(match.group(1) if match else "")
' "$BA_SIBLING/mix.lock" 2>/dev/null || true)"

    if [ "$ba_locked" = "$ba_version" ]; then
      say "BA:      pins bounded_authority_protocol $ba_version from Hex (sibling as checked out)"

      ba_pin="$(
        printf '%s\n' "$remote_refs" | awk -v t="refs/tags/v$ba_version^{}" '$2 == t {print $1}'
      )"
      [ -z "$ba_pin" ] &&
        ba_pin="$(printf '%s\n' "$remote_refs" | awk -v t="refs/tags/v$ba_version" '$2 == t {print $1}')"
    else
      say "BA:      WITHHELD — mix.exs requires exact $ba_version but mix.lock selects ${ba_locked:-nothing}"
      ba_version=""
    fi
  else
    ba_pin="$(python3 -c '
import re, sys
text = open(sys.argv[1], encoding="utf-8").read()
match = re.search(
    r"\{\s*:bounded_authority_protocol\s*,[^}]*?\bref:\s*\"([0-9a-f]{40})\"",
    text,
    re.S,
)
print(match.group(1) if match else "")
' "$BA_SIBLING/mix.exs" 2>/dev/null || true)"

    if [ -n "$ba_pin" ]; then
      say "BA:      pins ${ba_pin:0:12} (sibling as checked out — fetch BA before relying on this in an audit)"
    else
      say "BA:      sibling present but no exact Hex or git ref parsed — read $BA_SIBLING/mix.exs first-hand"
    fi
  fi
else
  say "BA:      SKIP (sibling $BA_SIBLING absent) — alignment verdict withheld"
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

  if [ -n "$newest_commit" ] && [ -n "$locked_commit" ] && have_span "$locked_commit" "$newest_commit"; then
    lib_files="$(lib_span "$locked_commit" "$newest_commit")"

    if [ -z "$lib_files" ]; then
      say "  Release span lib/ is EMPTY — a bump MAY ride ADR-0010's exception (D2.1);" \
          "still a deliberate, enumerated, same-commit bump (wall attributes + both locks)."
    else
      say "  Release span lib/ is NON-EMPTY:"
      print_files "$lib_files"
      say "  It CANNOT ride ADR-0010's exception — no bump unless the authority runtime" \
          "validates the span first, or the policy is deliberately amended."
    fi
  else
    say "  Span UNVERIFIED (remote tags or local objects unavailable) — verify first-hand" \
        "in the protocol repo before any bump decision."
  fi
elif [ -n "$hex_latest" ]; then
  say "RELEASES: locked $locked is the latest stable — no bump decision pending."
fi

# Alignment verdict: the authority runtime's pin vs ours. Every branch speaks —
# a silently-absent verdict reads as "no misalignment flagged" (cross-vendor
# finding: the no-else form violated the script's own every-skip-printed
# contract).
if [ -n "$ba_version" ] && [ "$ba_version" = "$locked" ]; then
  say "ALIGNMENT: pins match ($locked) — ADR-0010 default posture holds."
elif [ -n "$ba_version" ] && [ -z "$ba_pin" ]; then
  say "ALIGNMENT: WITHHELD — BA's v$ba_version tag commit is unknown on the remote."
elif [ -z "$ba_pin" ]; then
  : # the sibling-absent SKIP already printed above
elif [ -z "$locked_commit" ]; then
  say "ALIGNMENT: WITHHELD — the locked version's tag commit is unknown on the remote."
elif have_span "$ba_pin" "$locked_commit"; then
  ba_lib="$(lib_span "$ba_pin" "$locked_commit")"

  if [ "$ba_pin" = "$locked_commit" ]; then
    say "ALIGNMENT: pins match ($locked) — ADR-0010 default posture holds."
  elif git -C "$BAP_SIBLING" merge-base --is-ancestor "$ba_pin" "$locked_commit" 2>/dev/null; then
    # AHEAD legitimacy turns on the span's lib/ being empty (ADR-0010 D2.1) —
    # classify it, never render both states identically (cross-vendor finding).
    if [ -z "$ba_lib" ]; then
      say "ALIGNMENT: BARA is AHEAD of the authority pin (it pins ${ba_pin:0:12}); the span's lib/ is EMPTY — legal per ADR-0010 D2.1."
    else
      say "ALIGNMENT: BARA is AHEAD of the authority pin (it pins ${ba_pin:0:12}) and the span's lib/ is NON-EMPTY:"
      print_files "$ba_lib"
      say "  A POLICY-VIOLATING ahead state (ADR-0010 D2.1) — re-align or amend the policy, deliberately."
    fi
  elif git -C "$BAP_SIBLING" merge-base --is-ancestor "$locked_commit" "$ba_pin" 2>/dev/null; then
    say "ALIGNMENT: AUTHORITY is AHEAD (its pin descends ours) — ADR-0010 D3: re-align" \
        "at the next dependency pass (deliberate, same-commit, wall attributes + locks)."
  else
    say "ALIGNMENT: pins DIVERGED (neither descends the other) — read both repos first-hand."
  fi
else
  say "ALIGNMENT: WITHHELD — both pins known but the span is not locally verifiable" \
      "(BAP sibling absent or objects missing); read the protocol repo first-hand before deciding."
fi

# Main drift: what protocol main carries past our locked version — the
# eligibility question for the NEXT bump (cross-vendor note: the header
# promised this and the script never computed it).
if [ -n "$bap_main" ] && [ -n "$locked_commit" ]; then
  if have_span "$locked_commit" "$bap_main"; then
    main_lib="$(lib_span "$locked_commit" "$bap_main")"

    if [ -z "$main_lib" ]; then
      say "MAIN DRIFT: main sits past our lock with lib/ UNTOUCHED — a future release from it may ride the exception (once tagged)."
    else
      say "MAIN DRIFT: main sits past our lock with lib/ NON-EMPTY:"
      print_files "$main_lib"
      say "  Future releases from this span CANNOT ride ADR-0010's exception until the authority validates."
    fi
  else
    say "MAIN DRIFT: WITHHELD (span not locally verifiable) — locked ${locked_commit:0:12} vs main ${bap_main:0:12}."
  fi
fi

say "-------------------------------------------------------------------------"
say "Probe only — not a gate. Verdicts above came only from inputs actually verified."
