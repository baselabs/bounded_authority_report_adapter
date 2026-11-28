defmodule BoundedAuthorityReportAdapter.ProtocolDependency do
  @moduledoc false

  @app :bounded_authority_protocol

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

  defp identity!(Hex.SCM, requirement, {:hex, @app, version, _, _, _, "hexpm", outer})
       when is_binary(requirement) and is_binary(outer) do
    unless Version.match?(version, requirement) and Regex.match?(~r/\A[0-9a-f]{64}\z/, outer) do
      Mix.raise("Protocol Hex lock is outside the supported range or lacks an outer checksum")
    end

    "hex:#{version}:#{outer}"
  end

  defp identity!(_scm, _requirement, _lock),
    do: Mix.raise("Protocol dependency must resolve a release from hexpm")
end
