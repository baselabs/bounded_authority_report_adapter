defmodule BoundedAuthorityReportAdapter.ProtocolDependency do
  @moduledoc false

  @app :bounded_authority_protocol
  @candidate_remote "https://github.com/baselabs/bounded_authority_protocol.git"
  @candidate_ref "2e339cec88d2831c7e5e3e848fa5ff8199764f8c"

  def identity! do
    dep =
      Enum.find(Mix.Dep.cached(), &(&1.app == @app)) || Mix.raise("Protocol dependency missing")

    lock = Map.fetch!(Mix.Dep.Lock.read(), @app)

    unless dep.scm.checked_out?(dep.opts) and
             dep.scm.lock_status(Keyword.put(dep.opts, :lock, lock)) == :ok do
      Mix.raise("Protocol checkout does not match the active dependency lock")
    end

    identity!(dep.scm, dep.requirement, lock)
  end

  defp identity!(
         Mix.SCM.Git,
         nil,
         {:git, @candidate_remote, @candidate_ref, [ref: @candidate_ref]}
       ),
       do: "git:#{@candidate_ref}"

  defp identity!(Hex.SCM, "~> 1.5", {:hex, @app, version, _inner, _managers, _, "hexpm", outer})
       when is_binary(outer) do
    unless Version.match?(version, "~> 1.5") and Regex.match?(~r/\A[0-9a-f]{64}\z/, outer) do
      Mix.raise("Protocol Hex lock is outside the supported range or lacks an outer checksum")
    end

    "hex:#{version}:#{outer}"
  end

  defp identity!(_scm, _requirement, _lock),
    do:
      Mix.raise(
        "Protocol dependency must resolve the bearing Hex release or the pinned candidate"
      )
end
