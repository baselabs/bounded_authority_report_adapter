#!/usr/bin/env bash
# Dependency currency check — the latest-first policy gate (ADR-0020).
#
# Caller-cwd contract: this script NEVER cds — it audits whatever mix project
# owns the caller's working directory. CI invokes it once per project job from
# that job's working directory; `mix ci` invokes it from the library root and
# from examples/edge_agent.
#
# Classification is on the RENDERED table, never on the exit code (mix
# hex.outdated exits nonzero BOTH on drift and on lookup failure):
#   - "Update possible"        -> resolvable drift  -> exit 1, packages named
#   - "Update not possible"    -> resolver-rejected -> reported with each
#                                  package's requirement chain (mix hex.outdated
#                                  <pkg>); a parent's requirement is a pin, so
#                                  it does not fail the gate
#   - no table rendered        -> currency state UNVERIFIED -> exit 1
# Rows are padded with trailing whitespace, so status matches are anchored on
# [[:space:]]*$ — a hard-$ pattern would fail open on the padded rows.
#
# Both the direct-dependency table and `--all` (transitives) are classified:
# a resolvable transitive drift is drift.
set -uo pipefail

classify_table() {
  local label="$1"
  shift
  local out
  out="$(mix hex.outdated "$@" 2>&1)" || true

  if ! printf '%s\n' "$out" |
       grep -qE '^Dependency[[:space:]]+(Only[[:space:]]+)?Current[[:space:]]+Latest'; then
    echo "check-deps-currency [$label]: no dependency table rendered — currency state unverified:" >&2
    printf '%s\n' "$out" >&2
    return 9
  fi

  local drift rejected status=0
  drift="$(printf '%s\n' "$out" | grep -E 'Update possible[[:space:]]*$' || true)"
  rejected="$(printf '%s\n' "$out" | grep -E 'Update not possible[[:space:]]*$' || true)"

  if [ -n "$drift" ]; then
    echo "check-deps-currency [$label]: RESOLVABLE DRIFT (latest-first policy, ADR-0020):" >&2
    printf '%s\n' "$drift" >&2
    status=1
  fi

  if [ -n "$rejected" ]; then
    echo "check-deps-currency [$label]: resolver-rejected updates (requirement chains):" >&2
    printf '%s\n' "$rejected" >&2
    printf '%s\n' "$rejected" | awk '{print $1}' | while read -r pkg; do
      [ -n "$pkg" ] || continue
      mix hex.outdated "$pkg" 2>&1 |
        grep -vE 'authentication session|hex\.user auth' >&2 || true
    done
  fi

  return "$status"
}

overall=0
classify_table direct || overall=$?
classify_table all --all || overall=$?
# 9 (no table rendered) is as much a failure as drift: never pass unverified.
[ "$overall" -ne 0 ] && overall=1

if [ "$overall" -eq 0 ]; then
  echo "check-deps-currency: no resolvable drift (direct or transitive); pins are upstream of this gate"
fi
exit "$overall"
