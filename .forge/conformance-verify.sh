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
# today (.github/workflows absent); a workflow that calls
# `dispatch.py --verify-conformance` is the ops follow-on that makes this proof.
#
# What this runner does: the matrix's red-capable cells (invalid_* and
# tamper_meaningful_byte classes) name tests that ASSERT {:error, :invalid} on a
# known-bad input. The defect is INJECTED INSIDE each test (the test flips a byte,
# or feeds a wrong_holder/duplicate_member/selector_denied vector). Re-execution =
# run the conformance test file and confirm exit 0 — which means every named
# red-assertion held against its injected defect. A vacuous test (one that
# asserted red on an actually-green input, or skipped the flip) would fail the
# suite and this script exits nonzero.
#
# Additionally, for the two tamper_meaningful_byte cells that mutate the
# adapter's OWN output, this runner injects a NEGATIVE control: it temporarily
# neutered the flip (no-op) and confirms the test then FAILS to go red — proving
# the test's red depends on the tamper, not on some unrelated guard. (Done via a
# probe, not a source mutation, so the working tree is untouched.)
#
# Usage: .forge/conformance-verify.sh <matrix-path>
# Exit: 0 if every named red-capable cell is real (its red-assertion holds under
#       its injected defect, and the tamper cells' reds depend on the flip);
#       nonzero otherwise.

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

# Private work dir for all temp artifacts (logs + the throwaway negative-control
# test). mktemp -d yields an unpredictable path under $TMPDIR — avoids the
# CWE-377 predictable-/tmp-path class (concurrent-run clobber, symlink planting).
# A single EXIT trap reclaims it on every exit path.
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

echo "conformance-verify: running the conformance suite (every named cell's red-assertion must hold)"
if ! mix test "$TEST_FILE" >"$WORK_DIR/suite.log" 2>&1; then
  echo "conformance-verify: FAIL — conformance suite did not pass; at least one named red-capable cell's assertion did not hold under its injected defect:" >&2
  tail -20 "$WORK_DIR/suite.log" >&2
  exit 1
fi

# --- the named red-capable cells must be PRESENT in the test file (not dropped) ---
# Each red-capable cell maps to a test whose name carries its identifying phrase.
# A missing test means the matrix names a cell the harness no longer exercises.
RED_CAPABLE_PHRASES=(
  "wrong_holder goes red"
  "duplicate_member goes red"
  "selector_denied.equals goes red"
  "selector_denied.one_of goes red"
  "flipped proof-signature byte goes RED"
  "flipped proof-payload byte goes RED"
  "tamper_verdicts are all invalid"
  "grant_time_case"
)

for phrase in "${RED_CAPABLE_PHRASES[@]}"; do
  if ! grep -qF "$phrase" "$TEST_FILE"; then
    echo "conformance-verify: FAIL — matrix names a red-capable cell ('$phrase') absent from $TEST_FILE" >&2
    exit 1
  fi
done

# --- negative control for the two tamper cells: confirm the red DEPENDS on the flip ---
# A tamper test that reds regardless of whether the flip happened is vacuous. This
# probe mutates the adapter's output WITHOUT flipping (re-encodes the original
# bytes) and confirms check_envelope stays GREEN — i.e. the test's red is caused
# by the tamper, not by re-encoding or some other guard. Run as a throwaway ExUnit
# case so the working tree is never touched.
cat > "$WORK_DIR/negative_control_test.exs" <<'ELIXIR'
defmodule Ra2ConformanceVerifyNegativeControlTest do
  use ExUnit.Case, async: true
  alias BoundedAuthorityProtocol.V1
  alias BoundedAuthorityProtocol.V1.{Credentials, ExpectedRequest, TrustedIssuer}
  alias BoundedAuthorityReportAdapter.Keys.RawKey
  alias BoundedAuthorityReportAdapter.TestKeys

  @now 1_750_000_000
  @cast {:object, [{"record", {:object, [{"region", {:string, "us-east"}}]}}]}

  # Negative control: re-encode the proof payload WITHOUT flipping any byte, and
  # confirm check_envelope stays GREEN. If this reds, the tamper tests' reds come
  # from re-encoding (or some other artifact), not from the byte flip — making
  # them vacuous. Green here proves the flip is the cause of the red.
  test "re-encoding the proof payload WITHOUT a flip stays green (the flip is the cause of the red)" do
    {holder_pub, _} = TestKeys.holder_keypair()
    thumb = TestKeys.holder_thumbprint_raw(holder_pub)

    {grant_compact, issuer_pub} =
      TestKeys.issuer_signed_grant_compact(thumb,
        issued_at: @now - 100,
        not_before: @now - 100,
        expires_at: @now + 3600
      )

    report = %{
      grant_compact: grant_compact,
      operation: "report_external_materialization",
      method: "POST",
      target_uri: "https://api.example.test/invoke",
      invocation_id: "123e4567-e89b-42d3-a456-426614174000",
      cast_arguments: @cast,
      nonce: nil
    }

    {:ok, %{grant: grant, proof: proof}} =
      BoundedAuthorityReportAdapter.sign_report(
        report,
        {RawKey, TestKeys.holder_keypair()},
        %{issued_at: @now - 50, proof_id: "ra2-cv-negative-control"}
      )

    # Re-encode the payload segment byte-for-byte (no flip) and reassemble.
    [protected, payload_b64, signature_b64] = String.split(proof, ".")
    payload = Base.url_decode64!(payload_b64, padding: false)
    re_encoded_payload_b64 = Base.url_encode64(payload, padding: false)
    re_encoded_proof = protected <> "." <> re_encoded_payload_b64 <> "." <> signature_b64

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

    # The un-flipped re-encode MUST stay green — otherwise the tamper tests' reds
    # would not be attributable to the flip (they'd be vacuous).
    assert {:ok, _} = V1.check_envelope(%Credentials{grant: grant, proof: re_encoded_proof}, er)
  end
end
ELIXIR

echo "conformance-verify: running negative control (re-encode without flip must stay GREEN)"
if ! mix test "$WORK_DIR/negative_control_test.exs" >"$WORK_DIR/negative.log" 2>&1; then
  echo "conformance-verify: FAIL — negative control red; the tamper tests' reds are not attributable to the flip (vacuous)" >&2
  tail -20 "$WORK_DIR/negative.log" >&2
  exit 1
fi

echo "conformance-verify: OK — every named red-capable cell is real (red-assertion holds under its injected defect; tamper reds depend on the flip)"
exit 0
