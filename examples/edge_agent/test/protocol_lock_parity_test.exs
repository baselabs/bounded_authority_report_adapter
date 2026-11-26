defmodule EdgeAgent.ProtocolLockParityTest do
  use ExUnit.Case, async: false

  alias Mix.Dep.Lock

  @root Path.expand("../../..", __DIR__)
  @protocol :bounded_authority_protocol

  test "the example and library actively lock the same protocol package" do
    example = Map.fetch!(Lock.read(), @protocol)

    library =
      Mix.Project.in_project(:bounded_authority_report_adapter, @root, fn _ ->
        Map.fetch!(Lock.read(), @protocol)
      end)

    assert example == library
  end
end
