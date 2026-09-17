# `mix ci` env guard — the FIRST alias step (the RA7 trap's replacement for
# the old env(1) re-exec, which was POSIX-only). A bare `mix ci` boots :dev,
# and a :dev compile skips test/support — so refuse anything but :test, with
# the per-shell invocation (cross-platform: sh/bash, PowerShell, cmd.exe —
# feedback_cross_platform_capability_is_required).

unless Mix.env() == :test do
  raise """
  mix ci must run under MIX_ENV=test (a :dev boot compiles without test/support \
  and misses its warnings — the RA7 trap). Invoke per shell:

    sh/bash:     MIX_ENV=test mix ci
    PowerShell:  $env:MIX_ENV = "test"; mix ci
    cmd.exe:     set MIX_ENV=test&& mix ci
  """
end

IO.puts("ci env guard: MIX_ENV=#{Mix.env()} ok")
