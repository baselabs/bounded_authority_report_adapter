#!/usr/bin/env bash
set -euo pipefail

# check-bap-drift.sh: one-command ecosystem drift check for the protocol dependency.
#
# What BARA compiles against is a deliberate, reviewed choice (the lock follows
# published BAP releases; the requirement is a range with a security floor and the wall
# test's clauses pin the range shape and the locked version). This probe
# answers, READ-ONLY, the three questions every bump or audit session needs:
#
#   1. what BARA locks + requires          (the library and example locks / mix.exs)
#   2. what hex.pm publishes               (public API; skipped offline)
#   3. how far the protocol's main has     (git ls-remote on the remote URL: no fetch,
#      moved, and what lib/ says             no sibling .git writes, no tag clobber)
#
# It reads no consumer's repository: no consumer's pin gates a BARA bump.
#
# Verdicts render only from verified inputs; every degraded input prints its own skip
# line. NOT a gate: exits 0 unless the script itself is broken; it never writes to any
# repo (lib/ spans run in the local sibling only when both commits are already present
# locally).

script_dir="$(dirname "$0")"
REPO="$(cd "$script_dir/.." && pwd)"
APP="bounded_authority_protocol"
BAP_REMOTE="https://github.com/baselabs/bounded_authority_protocol.git"
BAP_SIBLING="$REPO/../bounded_authority_protocol"

say() { printf '%s\n' "$*"; }
print_files() {
  while IFS= read -r file; do
    if [ -n "$file" ]; then
      printf '    %s\n' "$file"
    fi
  done <<<"$1"
}

# --- 1. BARA's own declaration (the source of truth: never a restated version) ------
lock_entry() {
  sed -nE "/\"$APP\": [{]:hex, :$APP, /p" "$1"
}

library_entry="$(lock_entry "$REPO/mix.lock")"
example_entry="$(lock_entry "$REPO/examples/edge_agent/mix.lock")"
locked="$(sed -nE "s/.*:hex, :$APP, \"([^\"]+)\".*/\1/p" <<<"$library_entry")"
requirement="$(sed -nE "s/.*[{:]$APP, \"([^\"]+)\".*/\1/p" "$REPO/mix.exs" | head -1)"

if [ -z "$locked" ] || [ -z "$requirement" ]; then
  say "FAIL: could not parse the lock/resolution from $REPO: run from the repo or fix the format"
  exit 1
fi

say "BARA:    locks $APP $locked (requirement $requirement)"
if [ "$library_entry" = "$example_entry" ]; then
  say "Example: matches the library's Hex lock entry"
else
  say "Example: Hex lock entry differs or is missing"
fi

# --- 2. hex.pm (public API; degrade offline) ------------------------------------------
hex_status=0
hex_json="$(curl -fsSm 10 "https://hex.pm/api/packages/$APP" 2>/dev/null)" || hex_status=$?
case "$hex_status" in
  0) ;;
  # Network, HTTP and TLS failures are expected for this offline-capable probe.
  5|6|7|18|22|28|35|52|55|56|60) hex_json="" ;;
  *) exit "$hex_status" ;;
esac

if [ -n "$hex_json" ]; then
  metadata_status=0
  hex_metadata="$(printf '%s' "$hex_json" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
    latest = d["latest_stable_version"]
    vs = [r["version"] for r in d["releases"]]
    if (not isinstance(latest, str) or not latest or latest not in vs
            or not all(isinstance(v, str) for v in vs)):
        raise ValueError("incoherent Hex package metadata")
    try:
        vs = sorted(vs, key=lambda v: tuple(int(p) for p in v.split(".")))
    except ValueError:
        vs = sorted(vs)
except (ValueError, KeyError, TypeError):
    sys.exit(2)  # Malformed metadata withholds verdicts; tool failures still fail.
print(latest, " ".join(vs))
' 2>/dev/null)" || metadata_status=$?

  case "$metadata_status" in
    0)
      read -r hex_latest hex_releases <<<"$hex_metadata"
      say "hex.pm:  latest stable $hex_latest (published: $hex_releases)"
      ;;
    2)
      hex_latest=""
      say "hex.pm:  WITHHELD (malformed API response): release verdicts withheld"
      ;;
    *) exit "$metadata_status" ;;
  esac
else
  hex_latest=""
  say "hex.pm:  SKIP (offline or API unreachable): release verdicts withheld"
fi

# --- 3/4. the protocol remote, read-only (ls-remote: no fetch, no tag clobber) -------
remote_status=0
remote_refs="$(git ls-remote "$BAP_REMOTE" 2>/dev/null)" || remote_status=$?
case "$remote_status" in
  0) ;;
  128) remote_refs="" ;; # Git could not reach the remote; verdicts remain withheld.
  *) exit "$remote_status" ;;
esac

if [ -z "$remote_refs" ]; then
  say "BAP:     SKIP (remote unreachable): main/tag verdicts withheld"
fi

bap_main="$(printf '%s\n' "$remote_refs" | awk '$2 == "refs/heads/main" {print $1}')"
release_commit() {
  # Prefer the current package-prefixed tag and accept legacy version tags.
  # Annotated tags carry a peeled commit. Lightweight tags point at it directly.
  printf '%s\n' "$remote_refs" |
    awk -v current="refs/tags/baselabs_${APP}-v$1" -v legacy="refs/tags/v$1" '
      $2 == current "^{}" {current_commit = $1}
      $2 == current {current_tag = $1}
      $2 == legacy "^{}" {legacy_commit = $1}
      $2 == legacy {legacy_tag = $1}
      END {
        if (current_commit != "") print current_commit
        else if (current_tag != "") print current_tag
        else if (legacy_commit != "") print legacy_commit
        else if (legacy_tag != "") print legacy_tag
      }
    '
}
locked_commit="$(release_commit "$locked")"

if [ -n "$bap_main" ]; then
  say "BAP:     main ${bap_main:0:12}"
  if [ -n "$locked_commit" ]; then
    say "         release $locked tag commit ${locked_commit:0:12}"
  else
    say "         release $locked tag commit unknown on the remote"
  fi
fi

if [ ! -d "$BAP_SIBLING" ]; then
  say "BAP:     SKIP (sibling $BAP_SIBLING absent): lib/-span verdicts limited to locally verifiable pairs"
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
  newest_commit="$(release_commit "$hex_latest")"

  if [ -n "$newest_commit" ] && [ -n "$locked_commit" ] && have_span "$locked_commit" "$newest_commit"; then
    lib_files="$(lib_span "$locked_commit" "$newest_commit")"

    if [ -z "$lib_files" ]; then
      say "  Release span lib/ is EMPTY; a bump is still a deliberate, enumerated," \
          "same-commit move (wall attributes + both locks)."
    else
      say "  Release span lib/ is NON-EMPTY:"
      print_files "$lib_files"
      say "  A bump classifies these library changes in the bump commit and exercises" \
          "the consumed surfaces in BARA's suite."
    fi
  else
    say "  Span UNVERIFIED (remote tags or local objects unavailable): verify first-hand" \
        "in the protocol repo before any bump decision."
  fi
elif [ -n "$hex_latest" ]; then
  say "RELEASES: locked $locked is the latest stable: no bump decision pending."
fi

# Main drift: what protocol main carries past our locked version: the
# eligibility question for the NEXT bump (cross-vendor note: the header
# promised this and the script never computed it).
if [ -n "$bap_main" ] && [ -n "$locked_commit" ]; then
  if [ "$locked_commit" = "$bap_main" ]; then
    say "MAIN DRIFT: main and the locked release point to the same commit."
  elif have_span "$locked_commit" "$bap_main"; then
    main_lib="$(lib_span "$locked_commit" "$bap_main")"

    if [ -z "$main_lib" ]; then
      say "MAIN DRIFT: main sits past our lock with lib/ UNTOUCHED."
    else
      say "MAIN DRIFT: main sits past our lock with lib/ NON-EMPTY:"
      print_files "$main_lib"
      say "  A bump to a release from this span classifies these changes."
    fi
  else
    say "MAIN DRIFT: WITHHELD (span not locally verifiable): locked ${locked_commit:0:12} vs main ${bap_main:0:12}."
  fi
fi

say "-------------------------------------------------------------------------"
say "Probe only: not a gate. Verdicts above came only from inputs actually verified."
