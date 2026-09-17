import Config

# Self-enforcing toolchain (ADR-0019): the repository refuses to build on an
# Erlang/OTP major outside the supported set — every major on which the
# dependency stack actually compiles for the supported Elixir line
# (1.18/1.19/1.20). Probed 2026-09-16 four ways: asdf list-all, the official
# elixir docker tags, bob (repo.hex.pm) builds, AND compile probes. OTP 25
# and 26 are EXCLUDED despite having images:
# bounded_authority_protocol 0.4.0's codecs decode through :json
# (deps/.../v1/json.ex:73), which enters stdlib in OTP 27 — proven by probe
# (`code:ensure_loaded(json)` -> {error,nofile} on 25 and 26; the battery's
# test/support corpus parsing raises UndefinedFunctionError :json on both).
# This file is NOT shipped: `files:` in mix.exs excludes config/ (the
# exact-set census in scripts/check_package.exs proves it), so the assert
# governs THIS repository's builds only, never a consumer's.
#
# LOCKSTEP: mix.exs's elixir range, this set, .tool-versions, and the CI
# matrix lanes move together in ONE commit (a supported major without a CI
# lane is a defect; a lane outside the set is a defect).
supported_otp = ["27", "28", "29"]
running_otp = to_string(:erlang.system_info(:otp_release))

unless running_otp in supported_otp do
  raise "bounded_authority_report_adapter supports Erlang/OTP 27/28/29; running #{running_otp} (Elixir #{System.version()}, code root #{:code.root_dir()})."
end
