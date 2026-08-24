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
  read -r hex_latest hex_releases <<<"$(printf '%s' "$hex_json" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print(d.get("latest_stable_version", "?"), " ".join(sorted(r["version"] for r in d["releases"])))
' 2>/dev/null || echo "? ?")"
  say "hex.pm:  latest stable $hex_latest (published: $hex_releases)"
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

if [ -n "$bap_main" ]; then
  say "BAP:     main ${bap_main:0:12}"
  [ -n "$locked_commit" ] && say "         v$locked tag commit ${locked_commit:0:12}" ||
    say "         v$locked tag commit unknown on the remote (peeled ref absent — is $locked a real release tag?)"
fi

# --- the authority runtime's pin (sibling file, AS CHECKED OUT — not fetched) --------
if [ -f "$BA_SIBLING/mix.exs" ]; then
  ba_pin="$(sed -nE 's/.*ref: "([0-9a-f]{40})".*/\1/p' "$BA_SIBLING/mix.exs" | head -1)"
  if [ -n "$ba_pin" ]; then
    say "BA:      pins ${ba_pin:0:12} (sibling as checked out — fetch BA before relying on this in an audit)"
  else
    say "BA:      sibling present but no git ref parsed — read $BA_SIBLING/mix.exs first-hand"
    ba_pin=""
  fi
else
  say "BA:      SKIP (sibling $BA_SIBLING absent) — alignment verdict withheld"
  ba_pin=""
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
      printf '    %s\n' $lib_files
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

# Alignment verdict: the authority runtime's pin vs ours.
if [ -n "$ba_pin" ] && [ -n "$locked_commit" ] && have_span "$ba_pin" "$locked_commit"; then
  if [ "$ba_pin" = "$locked_commit" ]; then
    say "ALIGNMENT: pins match ($locked) — ADR-0010 default posture holds."
  elif git -C "$BAP_SIBLING" merge-base --is-ancestor "$ba_pin" "$locked_commit" 2>/dev/null; then
    say "ALIGNMENT: BARA is AHEAD of the authority pin (it pins ${ba_pin:0:12})."
  elif git -C "$BAP_SIBLING" merge-base --is-ancestor "$locked_commit" "$ba_pin" 2>/dev/null; then
    say "ALIGNMENT: AUTHORITY is AHEAD (its pin descends ours) — ADR-0010 D3: re-align" \
        "at the next dependency pass (deliberate, same-commit, wall attributes + locks)."
  else
    say "ALIGNMENT: pins DIVERGED (neither descends the other) — read both repos first-hand."
  fi
fi

say "-------------------------------------------------------------------------"
say "Probe only — not a gate. Verdicts above came only from inputs actually verified."
