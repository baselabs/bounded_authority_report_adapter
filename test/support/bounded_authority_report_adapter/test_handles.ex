defmodule BoundedAuthorityReportAdapter.TestHandles do
  @moduledoc """
  Test-only key-handle modules for the RA1 sign_report suite.

  These live in `test/support/` (compiled in `:test` via `mix.exs`
  `elixirc_paths`) so they are always loaded when the tests run — defining
  them at the bottom of the `_test.exs` file left them unloaded at test time
  in some `mix test` orderings (function_exported? returned false even though
  the module compiled), which made the WrongKeyHandle test flake.
  """
end

defmodule CountingKeyHandle do
  @moduledoc "Counts sign/2 calls — the C1 tripwire (asserts exactly one signing call)."
  @behaviour BoundedAuthorityReportAdapter

  @key {__MODULE__, :sign_count}

  @impl true
  def sign(message, {_public_key, private_key}) do
    Process.put(@key, (Process.get(@key) || 0) + 1)
    {:ok, :crypto.sign(:eddsa, :ed25519, message, [private_key, :ed25519])}
  end

  @impl true
  def public_key({public_key, _private_key}), do: {:ok, public_key}

  @impl true
  def thumbprint({public_key, _private_key}) do
    {:ok, raw} = BoundedAuthorityProtocol.V1.Jwk.public_key_thumbprint_raw(public_key, %{})
    {:ok, raw}
  end

  def sign_call_count, do: Process.get(@key) || 0
end

defmodule CapturingKeyHandle do
  @moduledoc "Captures the message handed to sign/2 — the no-canonical-bytes-fork tripwire."
  @behaviour BoundedAuthorityReportAdapter

  @key {__MODULE__, :message}

  @impl true
  def sign(message, {_public_key, private_key}) do
    Process.put(@key, message)
    {:ok, :crypto.sign(:eddsa, :ed25519, message, [private_key, :ed25519])}
  end

  @impl true
  def public_key({public_key, _private_key}), do: {:ok, public_key}

  @impl true
  def thumbprint({public_key, _private_key}) do
    {:ok, raw} = BoundedAuthorityProtocol.V1.Jwk.public_key_thumbprint_raw(public_key, %{})
    {:ok, raw}
  end

  def captured_message, do: Process.get(@key)
end

defmodule FailingKeyHandle do
  @moduledoc "A key-handle whose sign/2 always fails — exercises the :signing_failed path."
  @behaviour BoundedAuthorityReportAdapter

  @impl true
  def sign(_message, _handle), do: {:error, :always_fails}

  @impl true
  def public_key({public_key, _private_key}), do: {:ok, public_key}

  @impl true
  def thumbprint({public_key, _private_key}) do
    {:ok, raw} = BoundedAuthorityProtocol.V1.Jwk.public_key_thumbprint_raw(public_key, %{})
    {:ok, raw}
  end
end

defmodule BadContractHandle do
  @moduledoc """
  A key-handle whose sign/2 violates the {:ok,_}|{:error,_} contract (returns :ok).
  Cross-vendor closeout finding: sign_via_handle/2 was non-total; a non-tuple
  return raised CaseClauseError. The catch-all now maps it to :signing_failed.
  """
  @behaviour BoundedAuthorityReportAdapter

  @impl true
  def sign(_message, _handle), do: :ok

  @impl true
  def public_key({public_key, _private_key}), do: {:ok, public_key}

  @impl true
  def thumbprint({public_key, _private_key}) do
    {:ok, raw} = BoundedAuthorityProtocol.V1.Jwk.public_key_thumbprint_raw(public_key, %{})
    {:ok, raw}
  end
end

defmodule ShortKeyHandle do
  @moduledoc """
  A key-handle whose public_key/1 returns a short (non-32-byte) key.
  Cross-vendor closeout finding: a short key passed the is_binary guard then
  failed downstream as {:producer_error, :invalid}. The guard now requires 32
  bytes, so this fails fast as :invalid_key_handle.
  """
  @behaviour BoundedAuthorityReportAdapter

  @impl true
  def sign(_message, _handle), do: {:error, :unused}

  @impl true
  def public_key(_handle), do: {:ok, <<0::16>>}

  @impl true
  def thumbprint(_handle), do: {:ok, <<0::256>>}
end

defmodule ExitingKeyHandle do
  @moduledoc """
  A key-handle whose public_key/1 calls exit/1 (simulating a GenServer.call
  timeout in a production HSM/key-server callback). Cross-vendor round 2
  blocking finding: rescue did not catch exits, so this crashed the caller.
  The catch clauses now contain it -> :invalid_key_handle.
  """
  @behaviour BoundedAuthorityReportAdapter

  @impl true
  def sign(_message, _handle), do: exit(:simulated_hsm_timeout)

  @impl true
  def public_key(_handle), do: exit(:simulated_hsm_timeout)

  @impl true
  def thumbprint(_handle), do: {:ok, <<0::256>>}
end

defmodule WrongKeyHandle do
  @moduledoc """
  A key-handle whose public_key/1 returns key A but whose sign/2 signs with a
  DIFFERENT key B (a rotation/misconfiguration race). Cross-vendor round 2
  should-fix finding: the adapter validated only 64-byte length, not that the
  signature verifies against the resolved public key. The adapter now verifies
  the signature against the public key -> :signing_failed.
  """
  @behaviour BoundedAuthorityReportAdapter

  @impl true
  def public_key({public_key, _private_key}), do: {:ok, public_key}

  @impl true
  def sign(message, _handle) do
    {_other_pub, other_priv} = :crypto.generate_key(:eddsa, :ed25519, <<99::256>>)
    {:ok, :crypto.sign(:eddsa, :ed25519, message, [other_priv, :ed25519])}
  end

  @impl true
  def thumbprint({public_key, _private_key}) do
    {:ok, raw} = BoundedAuthorityProtocol.V1.Jwk.public_key_thumbprint_raw(public_key, %{})
    {:ok, raw}
  end
end
