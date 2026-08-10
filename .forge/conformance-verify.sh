#!/usr/bin/env bash
#
# .forge/conformance-verify.sh — layer-iii conformance re-execution runner.
#
# Forge-skill conformance doctrine (layer iii): CI re-executes the matrix's named
# red-capable cells against their injected defects to confirm the named tests are
# REAL (a test-id the agent NAMED is a claim; only re-execution on a machine the
# agent does not control proves it). `dispatch.py --verify-conformance` shells to
# this script with the matrix path as $1.
#
# HONESTY BOUNDARY (stated plainly): in an agent's own session this is ADVISORY —
# the agent could tamper the runner it invokes. Honesty-INDEPENDENT only when CI
# runs this on the PUSHED commit (the H9 boundary). No CI exists in this repo
# today; a workflow calling `dispatch.py --verify-conformance` is the ops
# follow-on that makes this proof.
#
# What this runner does (three stages):
#   1. PARSE the matrix — extract the named test phrases (the evidence column).
#      Reject an empty or malformed matrix (a cross-vendor finding: a prior
#      version only checked the file EXISTED, so an empty matrix passed).
#   2. RE-EXECUTE the conformance suite — every named red-capable cell's
#      red-assertion must hold under its injected defect. Confirm every named
#      phrase matches an EXECUTED test name (non-comment, non-:skip), so a
#      vacated cell (dropped or skipped test) surfaces.
#   3. NEGATIVE CONTROL — replicate the signature-flip logic and assert (a) the
#      output DIFFERS from the input (the flip is real, not identity) and (b) an
#      identity re-encode (decode + re-encode without flipping) stays GREEN,
#      proving re-encoding alone is not the cause of the tamper test's red.
#
# Usage: .forge/conformance-verify.sh <matrix-path>
# Exit: 0 if the matrix is well-formed, every named cell's red-assertion holds,
#       and the negative control stays green; nonzero otherwise.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

MATRIX="${1:-.forge/conformance/b2-ra-conformance-roundtrip}"
TEST_FILE="test/bounded_authority_report_adapter/conformance_roundtrip_test.exs"

if [ ! -f "$MATRIX" ]; then
  echo "conformance-verify: FAIL — matrix not found at $MATRIX" >&2
  exit 1
fi

if [ ! -f "$TEST_FILE" ]; then
  echo "conformance-verify: FAIL — conformance test file not found at $TEST_FILE" >&2
  exit 1
fi

# Private work dir for all temp artifacts. mktemp -d yields an unpredictable path
# (CWE-377: avoids predictable-/tmp-path clobber/symlink-planting). One EXIT trap.
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

# --- stage 1: parse + validate the matrix; reject empty/malformed/non-matrix files ---
# Each data row is TAB-separated with EXACTLY 3 fields: class<TAB>surface<TAB>evidence.
# Validate: (a) every data row has exactly 3 non-empty TAB-separated fields; (b) the
# file carries at least one valid row. Reject any file that isn't a real conformance
# matrix (a cross-vendor finding: a prior version accepted /etc/shells — any text file
# with non-empty lines — as 8 "cells"). The evidence column (field 3) names the test.
ROW_COUNT=0
MALFORMED=0
# Each entry: "class<TAB>evidence" — the class is carried alongside the evidence
# so stage 2 can cross-check the class's verdict direction against the matched
# test's verdict direction (a cross-vendor finding: the prior validator checked
# class, surface, and evidence INDEPENDENTLY, so an invalid_nonce row pointing to
# the valid top-level test passed).
ROWS=()

# Valid classes (BAP's 16-class corpus taxonomy) and surfaces this slice
# exercises. A fabricated class/surface (e.g. made_up_class) is rejected.
VALID_CLASSES=" valid boundary_near exact_bound maximum_plus_one invalid_duplicate invalid_encoding invalid_algorithm invalid_key invalid_claim invalid_time invalid_nonce invalid_uri invalid_request invalid_selector invalid_limit tamper_meaningful_byte "
VALID_SURFACES=" check_envelope verify_grant "

valid_field() {
  # $1 = the space-padded whitelist, $2 = the value
  [[ "$1" == *" $2 "* ]]
}

while IFS= read -r line; do
  # Skip comments and blank lines.
  [[ "$line" =~ ^[[:space:]]*# ]] && continue
  [[ -z "${line//[[:space:]]/}" ]] && continue
  ROW_COUNT=$((ROW_COUNT + 1))
  # Split on TAB; a valid row has exactly 3 non-empty fields.
  IFS=$'\t' read -r f1 f2 f3 rest <<< "$line"
  if [[ -z "$f1" || -z "$f2" || -z "$f3" || -n "$rest" ]]; then
    MALFORMED=1
    echo "conformance-verify: FAIL — matrix row is not exactly 3 TAB-separated non-empty fields: '$line'" >&2
  elif ! valid_field "$VALID_CLASSES" "$f1"; then
    MALFORMED=1
    echo "conformance-verify: FAIL — matrix row has an unknown class '$f1' (not in BAP's corpus taxonomy): '$line'" >&2
  elif ! valid_field "$VALID_SURFACES" "$f2"; then
    MALFORMED=1
    echo "conformance-verify: FAIL — matrix row has an unknown surface '$f2' (expected check_envelope or verify_grant): '$line'" >&2
  else
    ROWS+=("$f1"$'\t'"$f3")
  fi
done < "$MATRIX"

if [ "$MALFORMED" -ne 0 ]; then
  exit 1
fi

if [ "$ROW_COUNT" -eq 0 ]; then
  echo "conformance-verify: FAIL — matrix $MATRIX carries no data rows (empty/malformed); a conformance matrix must name its red-capable cells" >&2
  exit 1
fi

if [ "${#ROWS[@]}" -eq 0 ]; then
  echo "conformance-verify: FAIL — matrix $MATRIX has no valid rows after validation" >&2
  exit 1
fi

echo "conformance-verify: matrix parsed — ${#ROWS[@]} named cell(s) across $ROW_COUNT row(s)"

# --- stage 2: re-execute the suite + confirm every named phrase is a real TEST NAME ---
echo "conformance-verify: running the conformance suite (every named cell's red-assertion must hold)"
if ! mix test "$TEST_FILE" >"$WORK_DIR/suite.log" 2>&1; then
  echo "conformance-verify: FAIL — conformance suite did not pass; at least one named red-capable cell's assertion did not hold under its injected defect:" >&2
  tail -20 "$WORK_DIR/suite.log" >&2
  exit 1
fi

# Extract the set of test names (the strings inside `test "..."` on non-comment
# lines) so each evidence phrase is tied to a real test. A cross-vendor finding:
# a plain grep matched commented-out `# test "..."` lines.
mapfile -t TEST_NAMES < <(
  grep -oE '^[[:space:]]*test "[^"]*"' "$TEST_FILE" | sed 's/^[[:space:]]*test "//;s/"$//'
)

# Confirm no test in the file is skipped — in ANY form ExUnit honors: the atom
# `:skip`, the keyword `skip: true`, or `skip: "<reason>"`. A skipped test
# vacates its cell (the suite exits 0 but the assertion never ran). Also reject
# a test_helper that excludes the :conformance tag (every test carries it) —
# that would run zero tests while exit 0.
if grep -qE '^[[:space:]]*(@tag|@moduletag)[[:space:]]+(:skip|skip:)' "$TEST_FILE"; then
  echo "conformance-verify: FAIL — $TEST_FILE contains a skip tag; a skipped test vacates its matrix cell" >&2
  exit 1
fi

if [ -f test/test_helper.exs ] && grep -qE 'ExUnit\.configure.*exclude.*:conformance' test/test_helper.exs; then
  echo "conformance-verify: FAIL — test/test_helper.exs excludes :conformance; zero tests would run" >&2
  exit 1
fi

# Executed-test COUNT assertion: the suite log's passed-count must equal the
# number of `test "..."` definitions (a cross-vendor finding: the prior comment
# promised this check but it was absent). A divergence means a test was skipped/
# filtered while the suite still exited 0. The parse matches ExUnit's summary
# across versions: "N passed" (1.18+) and "N tests, N failures" (older) — both
# carry the count as the first integer on the summary line. If the parse yields
# 0 (unrecognized format), fail rather than silently passing.
SUITE_PASSED=$(grep -oE '[0-9]+ (passed|tests?)' "$WORK_DIR/suite.log" | grep -oE '^[0-9]+' | head -1 || echo 0)
TEST_DEF_COUNT="${#TEST_NAMES[@]}"

if [ "$SUITE_PASSED" -eq 0 ]; then
  echo "conformance-verify: FAIL — could not parse the executed-test count from the suite log (unrecognized ExUnit summary format); refusing to certify without a count" >&2
  tail -5 "$WORK_DIR/suite.log" >&2
  exit 1
fi

if [ "$SUITE_PASSED" != "$TEST_DEF_COUNT" ]; then
  echo "conformance-verify: FAIL — suite ran $SUITE_PASSED test(s) but the file defines $TEST_DEF_COUNT; a test was skipped/filtered while the suite exited 0 (a vacated cell)" >&2
  exit 1
fi

for row in "${ROWS[@]}"; do
  IFS=$'\t' read -r class phrase <<< "$row"
  matched_name=""
  for name in "${TEST_NAMES[@]}"; do
    if [[ "$name" == *"$phrase"* ]]; then
      matched_name="$name"
      break
    fi
  done
  if [ -z "$matched_name" ]; then
    echo "conformance-verify: FAIL — matrix names a cell ('$phrase') that matches no test name in $TEST_FILE" >&2
    exit 1
  fi
  # Cross-check the class's verdict direction against the matched test's verdict
  # direction (a cross-vendor finding: the prior validator checked class and
  # evidence independently, so an invalid class pointing to a valid/green test
  # passed). The signals are SYMMETRIC: a 'valid' class rejects any red signal;
  # an 'invalid_*'/'tamper_*'/'maximum_plus_one' class rejects any green signal.
  # Red signals: "goes red", "(invalid)", ": red". Green signals: "verify green",
  # "verifies green", "(valid)".
  lname=$(echo "$matched_name" | tr '[:upper:]' '[:lower:]')

  is_red_name() {
    [[ "$1" == *"goes red"* || "$1" == *"(invalid)"* || "$1" == *": red"* ]]
  }

  is_green_name() {
    [[ "$1" == *"verify green"* || "$1" == *"verifies green"* || "$1" == *"(valid)"* ]]
  }

  case "$class" in
    valid|boundary_near|exact_bound)
      if is_red_name "$lname"; then
        echo "conformance-verify: FAIL — class '$class' (expects green) maps to a red-asserting test '$matched_name'" >&2
        exit 1
      fi
      ;;
    invalid_*|tamper_*|maximum_plus_one)
      if is_green_name "$lname"; then
        echo "conformance-verify: FAIL — class '$class' (expects red) maps to a green-asserting test '$matched_name'" >&2
        exit 1
      fi
      ;;
  esac
done
echo "conformance-verify: every named cell's test is present, its red-assertion held, and its class matches the test's verdict direction"

# --- stage 3: negative control — confirm the tamper is REAL and re-encoding alone doesn't red ---
# Two independent controls (a cross-vendor finding: a prior version defined
# separate no-op helpers in a new module, which didn't exercise the actual
# tamper logic):
#   (a) REAL-FLIP control: replicate flip_signature_byte's logic and assert the
#       output DIFFERS from the input — proving the flip changes a byte (if it
#       were identity, the tamper test would be vacuous: it would assert red on
#       the un-tampered envelope, which is green, so the test would fail — but
#       this control catches a helper that silently no-ops).
#   (b) IDENTITY-RE-ENCODE control: decode + re-encode the signature segment
#       WITHOUT flipping (identity, since BAP uses padding: false) and confirm
#       check_envelope stays GREEN — proving re-encoding alone is not the cause
#       of the tamper test's red.
cat > "$WORK_DIR/negative_control_test.exs" <<'ELIXIR'
defmodule Ra2ConformanceVerifyNegativeControlTest do
  use ExUnit.Case, async: true
  alias BoundedAuthorityProtocol.V1
  alias BoundedAuthorityProtocol.V1.{Credentials, ExpectedRequest, TrustedIssuer}
  alias BoundedAuthorityReportAdapter.Keys.RawKey
  alias BoundedAuthorityReportAdapter.TestKeys

  @now 1_750_000_000
  @cast {:object, [{"record", {:object, [{"region", {:string, "us-east"}}]}}]}

  # Replicate flip_signature_byte's logic exactly (the real helper is private to
  # the test module; this copy mirrors it so the control exercises the same
  # mechanism). Flips the last byte of the decoded signature segment.
  defp replicate_flip_signature(compact) do
    [protected, payload, signature_b64] = String.split(compact, ".")
    signature = Base.url_decode64!(signature_b64, padding: false)
    bytes = :binary.bin_to_list(signature)
    {pre, [last]} = Enum.split(bytes, -1)
    flipped = IO.iodata_to_binary(pre ++ [Bitwise.bxor(last, 0x01)])
    protected <> "." <> payload <> "." <> Base.url_encode64(flipped, padding: false)
  end

  # Identity re-encode: decode + re-encode the signature segment WITHOUT flipping.
  defp identity_reencode_signature(compact) do
    [protected, payload, signature_b64] = String.split(compact, ".")
    signature = Base.url_decode64!(signature_b64, padding: false)
    protected <> "." <> payload <> "." <> Base.url_encode64(signature, padding: false)
  end

  test "the signature flip produces a DIFFERENT compact (the tamper is real, not identity)" do
    {holder_pub, _} = TestKeys.holder_keypair()
    thumb = TestKeys.holder_thumbprint_raw(holder_pub)

    {grant, _issuer_pub} =
      TestKeys.issuer_signed_grant_compact(thumb,
        issued_at: @now - 100,
        not_before: @now - 100,
        expires_at: @now + 3600
      )

    report = %{
      grant_compact: grant,
      operation: "report_external_materialization",
      method: "POST",
      target_uri: "https://api.example.test/invoke",
      invocation_id: "123e4567-e89b-42d3-a456-426614174000",
      cast_arguments: @cast,
      nonce: nil
    }

    {:ok, %{proof: proof}} =
      BoundedAuthorityReportAdapter.sign_report(
        report,
        {RawKey, TestKeys.holder_keypair()},
        %{issued_at: @now - 50, proof_id: "ra2-cv-real-flip"}
      )

    flipped = replicate_flip_signature(proof)
    # The flip MUST change the compact — if it didn't, the tamper test asserts
    # red on the un-tampered (green) envelope, which is vacuous.
    refute flipped == proof, "the signature flip is identity (no byte changed) — the tamper test is vacuous"
  end

  test "an identity re-encode (no flip) stays GREEN (re-encoding alone is not the cause of the red)" do
    {holder_pub, _} = TestKeys.holder_keypair()
    thumb = TestKeys.holder_thumbprint_raw(holder_pub)

    {grant, issuer_pub} =
      TestKeys.issuer_signed_grant_compact(thumb,
        issued_at: @now - 100,
        not_before: @now - 100,
        expires_at: @now + 3600
      )

    report = %{
      grant_compact: grant,
      operation: "report_external_materialization",
      method: "POST",
      target_uri: "https://api.example.test/invoke",
      invocation_id: "123e4567-e89b-42d3-a456-426614174000",
      cast_arguments: @cast,
      nonce: nil
    }

    {:ok, %{proof: proof}} =
      BoundedAuthorityReportAdapter.sign_report(
        report,
        {RawKey, TestKeys.holder_keypair()},
        %{issued_at: @now - 50, proof_id: "ra2-cv-identity"}
      )

    er = %ExpectedRequest{
      trusted_issuer: %TrustedIssuer{key_id: "issuer-2026-07", public_key: issuer_pub},
      issuer: "https://issuer.example.test",
      audience: "https://verifier.example.test",
      method: "POST",
      target_uri: "https://api.example.test/invoke",
      invocation_id: "123e4567-e89b-42d3-a456-426614174000",
      operation: "report_external_materialization",
      cast_arguments: @cast,
      evaluation_time: @now,
      clock_skew: 60,
      proof_max_age: 300,
      nonce: :not_required,
      bounds: V1.Bounds.maximum()
    }

    # The identity re-encode MUST stay green — if it reds, the tamper test's red
    # comes from re-encoding, not from the flip.
    assert {:ok, _} =
             V1.check_envelope(
               %Credentials{grant: grant, proof: identity_reencode_signature(proof)},
               er
             )
  end
end
ELIXIR

echo "conformance-verify: running negative control (real-flip differs + identity-reencode green)"
if ! mix test "$WORK_DIR/negative_control_test.exs" >"$WORK_DIR/negative.log" 2>&1; then
  echo "conformance-verify: FAIL — negative control failed; either the flip is identity (vacuous tamper) or re-encoding alone reds (the tamper red is not from the flip)" >&2
  tail -20 "$WORK_DIR/negative.log" >&2
  exit 1
fi

echo "conformance-verify: OK — matrix well-formed (${#ROWS[@]} cells), every named cell's red-assertion holds, the flip is real, and re-encoding alone stays green"
exit 0
