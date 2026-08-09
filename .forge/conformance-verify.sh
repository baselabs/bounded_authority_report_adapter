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
#      phrase appears in the test file (a dropped test = a vacated cell).
#   3. NEGATIVE CONTROL — redefine the tamper helpers as NO-OPs (return the
#      original compact) in a throwaway test, and confirm check_envelope stays
#      GREEN. This proves the tamper tests' reds depend on the flip producing a
#      DIFFERENT byte, not on some unrelated artifact (a cross-vendor finding: a
#      prior version built a separate untouched proof, which didn't neuter the
#      actual tamper helper).
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

# --- stage 1: parse the matrix; reject empty/malformed ---
# Each data row is TAB-separated: class<TAB>surface<TAB>evidence. The evidence
# column (field 3) is the named test phrase. Extract every NON-EMPTY evidence
# phrase and confirm the matrix carries at least one red-capable row. A row with
# an empty field-3 is malformed (no named test) and is rejected, not silently
# passed (an empty grep -qF "" matches any file, so empty phrases must be
# filtered before the presence check).
mapfile -t EVIDENCE_PHRASES < <(
  awk -F'\t' '/^#/ || /^$/ {next} $3 == "" {bad=1; next} {print $3} END {exit bad}' "$MATRIX"
)
awk_status=$?

if [ "$awk_status" -ne 0 ]; then
  echo "conformance-verify: FAIL — matrix $MATRIX has a data row with an empty evidence (field 3); every row must name its red-capable test" >&2
  exit 1
fi

if [ "${#EVIDENCE_PHRASES[@]}" -eq 0 ]; then
  echo "conformance-verify: FAIL — matrix $MATRIX carries no data rows (empty/malformed); a conformance matrix must name its red-capable cells" >&2
  exit 1
fi

echo "conformance-verify: matrix parsed — ${#EVIDENCE_PHRASES[@]} named cell(s)"

# --- stage 2: re-execute the suite + confirm every named phrase is present ---
echo "conformance-verify: running the conformance suite (every named cell's red-assertion must hold)"
if ! mix test "$TEST_FILE" >"$WORK_DIR/suite.log" 2>&1; then
  echo "conformance-verify: FAIL — conformance suite did not pass; at least one named red-capable cell's assertion did not hold under its injected defect:" >&2
  tail -20 "$WORK_DIR/suite.log" >&2
  exit 1
fi

for phrase in "${EVIDENCE_PHRASES[@]}"; do
  # The evidence phrase names a test (its "test name" or a unique substring).
  # A missing phrase means the matrix names a cell the harness no longer exercises.
  if ! grep -qF "$phrase" "$TEST_FILE"; then
    echo "conformance-verify: FAIL — matrix names a cell ('$phrase') absent from $TEST_FILE" >&2
    exit 1
  fi
done
echo "conformance-verify: every named cell's test is present and its red-assertion held"

# --- stage 3: negative control — neuter the tamper helpers, confirm GREEN ---
# Redefine flip_signature_byte/flip_payload_byte as NO-OPs (return the original
# compact unchanged) and confirm check_envelope stays GREEN on the un-flipped
# proof. This proves the tamper tests' reds depend on the flip producing a
# DIFFERENT byte — if they reds came from re-encoding or some unrelated guard,
# the no-op flip (which still re-encodes the original bytes) would also red.
cat > "$WORK_DIR/negative_control_test.exs" <<'ELIXIR'
defmodule Ra2ConformanceVerifyNegativeControlTest do
  use ExUnit.Case, async: true
  alias BoundedAuthorityProtocol.V1
  alias BoundedAuthorityProtocol.V1.{Credentials, ExpectedRequest, TrustedIssuer}
  alias BoundedAuthorityReportAdapter.Keys.RawKey
  alias BoundedAuthorityReportAdapter.TestKeys

  @now 1_750_000_000
  @cast {:object, [{"record", {:object, [{"region", {:string, "us-east"}}]}}]}

  # Negative control: build the adapter's green envelope, then apply the tamper
  # helpers BUT with the flip neutered (the helpers re-encode the segment WITHOUT
  # changing any byte). check_envelope MUST stay GREEN on both — proving the
  # tamper tests' reds come from the byte flip, not from re-encoding.
  defp noop_flip_signature_byte(compact) do
    [protected, payload, signature_b64] = String.split(compact, ".")
    # Re-encode the signature segment WITHOUT flipping — identity (BAP uses
    # padding: false everywhere). The reassembled compact equals the original.
    signature = Base.url_decode64!(signature_b64, padding: false)
    protected <> "." <> payload <> "." <> Base.url_encode64(signature, padding: false)
  end

  defp noop_flip_payload_byte(compact) do
    [protected, payload_b64, signature_b64] = String.split(compact, ".")
    payload = Base.url_decode64!(payload_b64, padding: false)
    protected <> "." <> Base.url_encode64(payload, padding: false) <> "." <> signature_b64
  end

  test "no-op signature flip stays green (the flip is the cause of the red)" do
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
        %{issued_at: @now - 50, proof_id: "ra2-cv-neg-sig"}
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

    # The no-op-flipped proof (re-encoded, byte-identical) MUST stay green.
    assert {:ok, _} =
             V1.check_envelope(
               %Credentials{grant: grant, proof: noop_flip_signature_byte(proof)},
               er
             )
  end

  test "no-op payload flip stays green (the flip is the cause of the red)" do
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
        %{issued_at: @now - 50, proof_id: "ra2-cv-neg-pay"}
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

    assert {:ok, _} =
             V1.check_envelope(
               %Credentials{grant: grant, proof: noop_flip_payload_byte(proof)},
               er
             )
  end
end
ELIXIR

echo "conformance-verify: running negative control (no-op flip must stay GREEN)"
if ! mix test "$WORK_DIR/negative_control_test.exs" >"$WORK_DIR/negative.log" 2>&1; then
  echo "conformance-verify: FAIL — negative control red; the tamper tests' reds are not attributable to the flip (vacuous)" >&2
  tail -20 "$WORK_DIR/negative.log" >&2
  exit 1
fi

echo "conformance-verify: OK — matrix well-formed (${#EVIDENCE_PHRASES[@]} cells), every named cell's red-assertion holds, tamper reds depend on the flip"
exit 0
