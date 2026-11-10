defmodule EdgeAgent.ReceiverStartTest do
  @moduledoc """
  The README's two-terminal run: terminal one runs
  `mix run --no-halt -e EdgeAgent.Receiver.start`, which evaluates the expression in a
  process that exits as soon as it returns. The receiver must keep serving after that
  process is gone, or terminal two's `EdgeAgent.run()` gets `:econnrefused`.

  `async: false` — the receiver's supervisor and nonce ledger are registered by name.
  """

  use ExUnit.Case, async: false

  test "EdgeAgent.Receiver.start/1 keeps serving after the process that called it exits" do
    port = free_port()

    # The caller exits normally once start/1 returns, as `mix run -e` does.
    caller = spawn(fn -> :ok = EdgeAgent.Receiver.start(port: port) end)
    ref = Process.monitor(caller)
    assert_receive {:DOWN, ^ref, :process, ^caller, :normal}, 5_000

    supervisor = Process.whereis(EdgeAgent.Receiver.Supervisor)
    assert is_pid(supervisor) and Process.alive?(supervisor)
    on_exit(fn -> Supervisor.stop(supervisor) end)

    assert {:ok, 200, "accepted"} =
             EdgeAgent.run(receiver_url: "http://127.0.0.1:#{port}/report")
  end

  defp free_port do
    {:ok, socket} = :gen_tcp.listen(0, ip: {127, 0, 0, 1}, reuseaddr: true)
    {:ok, port} = :inet.port(socket)
    :gen_tcp.close(socket)
    port
  end
end
