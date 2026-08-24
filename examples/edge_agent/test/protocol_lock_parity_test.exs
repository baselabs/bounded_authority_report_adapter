defmodule EdgeAgent.ProtocolLockParityTest do
  @moduledoc """
  The example app's `mix.lock` must resolve `bounded_authority_protocol` at
  the SAME Hex version as the library's lock.

  The two locks regenerate independently (the example resolves the protocol
  transitively through the path dep on the adapter). If the example drifts
  while the library holds — a bare `mix deps.update` run from the wrong
  directory — the two CI jobs test DIFFERENT protocol versions: a quiet
  split-brain in which the gate job's green certifies a span the example job
  never ran. The library's wall pins its own lock version; this test pins the
  PARITY of the two.
  """

  use ExUnit.Case, async: true

  @protocol_app "bounded_authority_protocol"

  # examples/edge_agent/test → edge_agent → examples → repo root.
  @library_lock Path.expand("../../../mix.lock", __DIR__)

  test "the example lock resolves the protocol package at the library's locked version" do
    assert {:ok, library_version} = locked_version(File.read!(@library_lock))
    assert {:ok, example_version} = locked_version(File.read!("mix.lock"))

    assert example_version == library_version,
           "the two locks resolve :#{@protocol_app} at different versions " <>
             "(example #{example_version} != library #{library_version}) — a silent " <>
             "`mix deps.update` in one project split the CI jobs onto different " <>
             "protocol spans; re-lock BOTH in the same deliberate-bump commit"
  end

  # The lock line shape: "bounded_authority_protocol": {:hex, :bounded_authority_protocol, "0.1.1", …
  # (terminated at the closing quote + comma so a version that merely PREFIX-matches
  # cannot satisfy it — the same terminator discipline as the library wall's clause).
  defp locked_version(lock) do
    case Regex.run(~r/"#{@protocol_app}": \{:hex, :#{@protocol_app}, "([^"]+)",/, lock) do
      [_, version] -> {:ok, version}
      nil -> :error
    end
  end
end
