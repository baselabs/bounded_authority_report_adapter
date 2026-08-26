defmodule BoundedAuthorityReportAdapter.TestHandles do
  @moduledoc """
  Test-only key-handle modules for the sign_report (RA1) + sign_anchor (RA4) suites.

  These live in `test/support/` (compiled in `:test` via `mix.exs`
  `elixirc_paths`) so they are always loaded when the tests run — defining
  them at the bottom of the `_test.exs` file left them unloaded at test time
  in some `mix test` orderings (function_exported? returned false even though
  the module compiled), which made the WrongKeyHandle test flake.

  The RA1 handles (CountingKeyHandle, CapturingKeyHandle, etc.) implement only
  the proof-required callbacks. The RA4 anchor handles additionally implement
  `key_identity/1` (the optional callback `sign_anchor/3` resolves into the signed
  anchor header).
  """
end

defmodule CountingKeyHandle do
  alias BoundedAuthorityProtocol.V1.Jwk
  @moduledoc "Counts sign/2 calls — the C1 tripwire (asserts exactly one signing call)."
  @behaviour BoundedAuthorityReportAdapter

  @key {__MODULE__, :sign_count}

  @impl true
  def sign(message, {_public_key, private_key}) do
    Process.put(@key, (Process.get(@key) || 0) + 1)
    {:ok, :crypto.sign(:eddsa, :none, message, [private_key, :ed25519])}
  end

  @impl true
  def public_key({public_key, _private_key}), do: {:ok, public_key}

  @impl true
  def thumbprint({public_key, _private_key}) do
    {:ok, raw} = Jwk.public_key_thumbprint_raw(public_key, %{})
    {:ok, raw}
  end

  def sign_call_count, do: Process.get(@key) || 0
end

defmodule CapturingKeyHandle do
  alias BoundedAuthorityProtocol.V1.Jwk
  @moduledoc "Captures the message handed to sign/2 — the no-canonical-bytes-fork tripwire."
  @behaviour BoundedAuthorityReportAdapter

  @key {__MODULE__, :message}

  @impl true
  def sign(message, {_public_key, private_key}) do
    Process.put(@key, message)
    {:ok, :crypto.sign(:eddsa, :none, message, [private_key, :ed25519])}
  end

  @impl true
  def public_key({public_key, _private_key}), do: {:ok, public_key}

  @impl true
  def thumbprint({public_key, _private_key}) do
    {:ok, raw} = Jwk.public_key_thumbprint_raw(public_key, %{})
    {:ok, raw}
  end

  def captured_message, do: Process.get(@key)
end

defmodule FailingKeyHandle do
  alias BoundedAuthorityProtocol.V1.Jwk
  @moduledoc "A key-handle whose sign/2 always fails — exercises the :signing_failed path."
  @behaviour BoundedAuthorityReportAdapter

  @impl true
  def sign(_message, _handle), do: {:error, :always_fails}

  @impl true
  def public_key({public_key, _private_key}), do: {:ok, public_key}

  @impl true
  def thumbprint({public_key, _private_key}) do
    {:ok, raw} = Jwk.public_key_thumbprint_raw(public_key, %{})
    {:ok, raw}
  end
end

defmodule BadContractHandle do
  alias BoundedAuthorityProtocol.V1.Jwk

  @moduledoc """
  A key-handle whose sign/2 violates the {:ok,_}|{:error,_} contract (returns :ok).
  Cross-vendor closeout finding: sign_via_handle/2 was non-total; a non-tuple
  return raised CaseClauseError. The catch-all now maps it to :signing_failed.
  """
  @behaviour BoundedAuthorityReportAdapter

  # The contract violation IS this fixture's purpose — suppress the dialyzer
  # callback mismatch for this one module, narrowly, so the dialyzer gate
  # stays zero-warning without weakening the fixture.
  @dialyzer {:nowarn_function, sign: 2}

  @impl true
  def sign(_message, _handle), do: :ok

  @impl true
  def public_key({public_key, _private_key}), do: {:ok, public_key}

  @impl true
  def thumbprint({public_key, _private_key}) do
    {:ok, raw} = Jwk.public_key_thumbprint_raw(public_key, %{})
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
  alias BoundedAuthorityProtocol.V1.Jwk

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
    {:ok, :crypto.sign(:eddsa, :none, message, [other_priv, :ed25519])}
  end

  @impl true
  def thumbprint({public_key, _private_key}) do
    {:ok, raw} = Jwk.public_key_thumbprint_raw(public_key, %{})
    {:ok, raw}
  end
end

# ---------------------------------------------------------------------------
# RA4 anchor handles — implement key_identity/1 (the optional callback sign_anchor/3
# places in the signed header). key_id is pinned to the same constant RawKey
# uses so the anchor round-trip can build the matching HistoricalPublicKey.
# ---------------------------------------------------------------------------

defmodule AnchorCapturingKeyHandle do
  alias BoundedAuthorityProtocol.V1.Jwk

  @moduledoc """
  Captures the message handed to sign/2 — the no-canonical-bytes-fork tripwire
  for sign_anchor/3. Implements key_identity/1 so sign_anchor reaches sign/2.
  """
  @key {__MODULE__, :message}

  def sign(message, {_public_key, private_key}) do
    Process.put(@key, message)
    {:ok, :crypto.sign(:eddsa, :none, message, [private_key, :ed25519])}
  end

  def public_key({public_key, _private_key}), do: {:ok, public_key}

  def thumbprint({public_key, _private_key}) do
    {:ok, raw} = Jwk.public_key_thumbprint_raw(public_key, %{})
    {:ok, raw}
  end

  def key_identity({public_key, _private_key}), do: {:ok, {"test-anchor-key-001", public_key}}

  def captured_message, do: Process.get(@key)
end

defmodule AnchorWrongKeyHandle do
  alias BoundedAuthorityProtocol.V1.Jwk

  @moduledoc """
  key_identity/1 + public_key/1 return key A's material, but sign/2 signs with a
  DIFFERENT key B (a rotation/misconfiguration race). The verify_signature
  guard in the shared signing tail must reject this -> :signing_failed.
  """
  def public_key({public_key, _private_key}), do: {:ok, public_key}

  def sign(message, _handle) do
    {_other_pub, other_priv} = :crypto.generate_key(:eddsa, :ed25519, <<77::256>>)
    {:ok, :crypto.sign(:eddsa, :none, message, [other_priv, :ed25519])}
  end

  def thumbprint({public_key, _private_key}) do
    {:ok, raw} = Jwk.public_key_thumbprint_raw(public_key, %{})
    {:ok, raw}
  end

  def key_identity({public_key, _private_key}), do: {:ok, {"test-anchor-key-001", public_key}}
end

defmodule AnchorExitingKeyHandle do
  @moduledoc """
  key_identity/1 calls exit/1 (a simulated HSM/key-server timeout). safe_callback's
  catch clause must contain it -> :invalid_key_handle, not a crash.
  """
  def public_key({_public_key, _private_key}), do: exit(:simulated_hsm_timeout)
  def sign(_message, _handle), do: exit(:simulated_hsm_timeout)
  def thumbprint(_handle), do: {:ok, <<0::256>>}
  def key_identity(_handle), do: exit(:simulated_hsm_timeout)
end

defmodule AnchorFailingKeyHandle do
  alias BoundedAuthorityProtocol.V1.Jwk

  @moduledoc """
  key_identity/1 + public_key/1 succeed; sign/2 returns {:error, _} -> :signing_failed.
  """
  def public_key({public_key, _private_key}), do: {:ok, public_key}

  def sign(_message, _handle), do: {:error, :always_fails}

  def thumbprint({public_key, _private_key}) do
    {:ok, raw} = Jwk.public_key_thumbprint_raw(public_key, %{})
    {:ok, raw}
  end

  def key_identity({public_key, _private_key}), do: {:ok, {"test-anchor-key-001", public_key}}
end

defmodule RacingKeyIdentityHandle do
  @moduledoc """
  Defense-in-depth tripwire for the atomic `key_identity/1` snapshot.
  `key_identity/1` returns a consistent `{key_id, pub_a}` snapshot, then flips
  internal state so `sign/2` signs with key-b (a simulated post-snapshot
  rotation). The atomic snapshot means `key_id`+`public_key` cannot drift apart;
  the `verify_signature` guard catches the `sign/2`-vs-snapshot mismatch ->
  `:signing_failed`. This is the rotation race a cross-vendor (Codex) probe
  exploited under the separate-callback design, now caught at sign time.

  The handle term is an `Agent` pid whose state is
  `%{key_id:, pub_a:, priv_a:, priv_b:, rotated:}`.
  """
  def key_identity(pid) do
    Agent.get_and_update(pid, fn s -> {{:ok, {s.key_id, s.pub_a}}, %{s | rotated: true}} end)
  end

  def sign(message, pid) do
    priv = Agent.get(pid, fn s -> if s.rotated, do: s.priv_b, else: s.priv_a end)
    {:ok, :crypto.sign(:eddsa, :none, message, [priv, :ed25519])}
  end

  def public_key(_pid), do: {:ok, <<0::256>>}
  def thumbprint(_pid), do: {:ok, <<0::256>>}
end

# ---------------------------------------------------------------------------
# RA8 transition handles — like the anchor handles, they implement key_identity/1
# (the optional callback sign_key_transition/3 resolves as the atomic {key_id,
# public_key} snapshot). Role-agnostic: NO signing_identity/1 (the transition is a
# historical-key operation, not a role-gated one — see ADR-0009). RawKey (the holder/
# anchor reference) already implements key_identity/1 -> {"test-anchor-key-001", pub},
# so it is the happy-path transition handle; the modules below exercise the failure /
# tripwire paths (wrong-key, capturing, exit, atomic-snapshot drift).
# ---------------------------------------------------------------------------

defmodule TransitionCapturingKeyHandle do
  alias BoundedAuthorityProtocol.V1.Jwk

  @moduledoc """
  Captures the message handed to sign/2 — the no-canonical-bytes-fork tripwire for
  sign_key_transition/3. Implements key_identity/1 so sign_key_transition reaches sign/2.
  """
  @key {__MODULE__, :message}

  def sign(message, {_public_key, private_key}) do
    Process.put(@key, message)
    {:ok, :crypto.sign(:eddsa, :none, message, [private_key, :ed25519])}
  end

  def public_key({public_key, _private_key}), do: {:ok, public_key}

  def thumbprint({public_key, _private_key}) do
    {:ok, raw} = Jwk.public_key_thumbprint_raw(public_key, %{})
    {:ok, raw}
  end

  def key_identity({public_key, _private_key}), do: {:ok, {"test-anchor-key-001", public_key}}

  def captured_message, do: Process.get(@key)
end

defmodule TransitionWrongKeyHandle do
  @moduledoc """
  key_identity/1 returns the handle's pub A; sign/2 signs with a DIFFERENT key B (a
  rotation/misconfiguration race). The verify_signature guard in the shared tail must
  reject this -> :signing_failed (the mirror of AnchorWrongKeyHandle).
  """

  def public_key({public_key, _private_key}), do: {:ok, public_key}

  def sign(message, _handle) do
    {_other_pub, other_priv} = :crypto.generate_key(:eddsa, :ed25519, <<88::256>>)
    {:ok, :crypto.sign(:eddsa, :none, message, [other_priv, :ed25519])}
  end

  def key_identity({public_key, _private_key}), do: {:ok, {"test-anchor-key-001", public_key}}
end

defmodule TransitionExitingKeyHandle do
  @moduledoc """
  key_identity/1 calls exit/1 (a simulated HSM/key-server timeout). safe_callback's
  catch clause must contain it -> :invalid_key_handle, not a crash (mirror of
  AnchorExitingKeyHandle).
  """
  def public_key({_public_key, _private_key}), do: exit(:simulated_hsm_timeout)
  def sign(_message, _handle), do: exit(:simulated_hsm_timeout)
  def key_identity(_handle), do: exit(:simulated_hsm_timeout)
end

defmodule TransitionRacingKeyIdentityHandle do
  @moduledoc """
  Defense-in-depth tripwire for the atomic `key_identity/1` snapshot (the transition
  analogue of RacingKeyIdentityHandle). `key_identity/1` returns a consistent
  `{key_id, pub_a}` snapshot, then flips internal state so `sign/2` signs with priv_b
  (a simulated post-snapshot rotation). The atomic snapshot means key_id+public_key
  cannot drift apart; the `verify_signature` guard catches the sign/2-vs-snapshot
  mismatch -> `:signing_failed`.

  The handle term is an `Agent` pid whose state is
  `%{key_id:, pub_a:, priv_a:, priv_b:, rotated:}`.
  """
  def key_identity(pid) do
    Agent.get_and_update(pid, fn s -> {{:ok, {s.key_id, s.pub_a}}, %{s | rotated: true}} end)
  end

  def sign(message, pid) do
    priv = Agent.get(pid, fn s -> if s.rotated, do: s.priv_b, else: s.priv_a end)
    {:ok, :crypto.sign(:eddsa, :none, message, [priv, :ed25519])}
  end

  def public_key(_pid), do: {:ok, <<0::256>>}
  def thumbprint(_pid), do: {:ok, <<0::256>>}
end

# ---------------------------------------------------------------------------
# RA7 grant handles — implement signing_identity/1 (the optional callback sign_grant/3
# resolves as the atomic {role, key_id, public_key} snapshot + the C1 role gate).
# GrantIssuerHandle is the issuer-role reference; the others exercise the failure /
# tripwire paths (holder-role rejection, roleless rejection, atomic-snapshot drift,
# wrong-key, capturing, exit/throw, sign/2 failure). The issuer kid is pinned to
# "issuer-2026-07" so the round-trip can build the matching TrustedIssuer.
# ---------------------------------------------------------------------------

defmodule GrantIssuerHandle do
  alias BoundedAuthorityProtocol.V1.Jwk

  @moduledoc "The issuer-role handle for sign_grant tests: signing_identity/1 -> {:issuer, 'issuer-2026-07', pub}."
  @behaviour BoundedAuthorityReportAdapter

  @issuer_kid "issuer-2026-07"

  @impl true
  def signing_identity({public_key, _private_key}), do: {:ok, {:issuer, @issuer_kid, public_key}}

  @impl true
  def sign(message, {_public_key, private_key}) do
    {:ok, :crypto.sign(:eddsa, :none, message, [private_key, :ed25519])}
  end

  @impl true
  def public_key({public_key, _private_key}), do: {:ok, public_key}

  @impl true
  def thumbprint({public_key, _private_key}) do
    {:ok, raw} = Jwk.public_key_thumbprint_raw(public_key, %{})
    {:ok, raw}
  end

  def issuer_kid, do: @issuer_kid
end

defmodule GrantHolderCountingHandle do
  alias BoundedAuthorityProtocol.V1.Jwk

  @moduledoc """
  The C1 tripwire for sign_grant: signing_identity/1 -> {:holder, ...}, and sign/2
  counts calls. sign_grant MUST reject a :holder handle BEFORE sign/2, so
  sign_call_count/0 stays 0. (The mirror of sign_report's CountingKeyHandle, which
  asserts sign/2 is called exactly once — pointed the other way.)
  """
  @behaviour BoundedAuthorityReportAdapter
  @key {__MODULE__, :sign_count}

  @impl true
  def signing_identity({public_key, _private_key}),
    do: {:ok, {:holder, "holder-test", public_key}}

  @impl true
  def sign(message, {_public_key, private_key}) do
    Process.put(@key, (Process.get(@key) || 0) + 1)
    {:ok, :crypto.sign(:eddsa, :none, message, [private_key, :ed25519])}
  end

  @impl true
  def public_key({public_key, _private_key}), do: {:ok, public_key}

  @impl true
  def thumbprint({public_key, _private_key}) do
    {:ok, raw} = Jwk.public_key_thumbprint_raw(public_key, %{})
    {:ok, raw}
  end

  def sign_call_count, do: Process.get(@key) || 0
end

defmodule GrantRolelessHandle do
  alias BoundedAuthorityProtocol.V1.Jwk

  @moduledoc """
  The roleless tripwire: implements sign/2 + public_key/1 + thumbprint/1 +
  key_identity/1 but OMITS signing_identity/1. sign_grant must reject it as
  :invalid_key_handle (the UndefinedFunctionError from apply/3 is caught by
  safe_callback). key_identity/1 is included to prove the rejection is
  role-specific (signing_identity absent), not key-identity-specific.
  """
  @behaviour BoundedAuthorityReportAdapter

  @impl true
  def sign(message, {_public_key, private_key}) do
    {:ok, :crypto.sign(:eddsa, :none, message, [private_key, :ed25519])}
  end

  @impl true
  def public_key({public_key, _private_key}), do: {:ok, public_key}

  @impl true
  def thumbprint({public_key, _private_key}) do
    {:ok, raw} = Jwk.public_key_thumbprint_raw(public_key, %{})
    {:ok, raw}
  end

  @impl true
  def key_identity({public_key, _private_key}), do: {:ok, {"roleless-test", public_key}}

  # Deliberately NO signing_identity/1.
end

defmodule GrantCapturingKeyHandle do
  alias BoundedAuthorityProtocol.V1.Jwk
  @moduledoc "Captures the sign/2 message — the no-canonical-bytes-fork tripwire for sign_grant."
  @behaviour BoundedAuthorityReportAdapter
  @key {__MODULE__, :message}

  @impl true
  def signing_identity({public_key, _private_key}),
    do: {:ok, {:issuer, "issuer-2026-07", public_key}}

  @impl true
  def sign(message, {_public_key, private_key}) do
    Process.put(@key, message)
    {:ok, :crypto.sign(:eddsa, :none, message, [private_key, :ed25519])}
  end

  @impl true
  def public_key({public_key, _private_key}), do: {:ok, public_key}

  @impl true
  def thumbprint({public_key, _private_key}) do
    {:ok, raw} = Jwk.public_key_thumbprint_raw(public_key, %{})
    {:ok, raw}
  end

  def captured_message, do: Process.get(@key)
end

defmodule GrantWrongKeyHandle do
  alias BoundedAuthorityProtocol.V1.Jwk

  @moduledoc """
  signing_identity/1 returns the handle's pub A; sign/2 signs with a DIFFERENT key B.
  The verify_signature guard in the shared tail catches the sign/2-vs-snapshot mismatch
  -> :signing_failed.
  """
  @behaviour BoundedAuthorityReportAdapter

  @impl true
  def signing_identity({public_key, _private_key}),
    do: {:ok, {:issuer, "issuer-2026-07", public_key}}

  @impl true
  def sign(message, _handle) do
    {_other_pub, other_priv} = :crypto.generate_key(:eddsa, :ed25519, <<99::256>>)
    {:ok, :crypto.sign(:eddsa, :none, message, [other_priv, :ed25519])}
  end

  @impl true
  def public_key({public_key, _private_key}), do: {:ok, public_key}

  @impl true
  def thumbprint({public_key, _private_key}) do
    {:ok, raw} = Jwk.public_key_thumbprint_raw(public_key, %{})
    {:ok, raw}
  end
end

defmodule GrantRacingIdentityHandle do
  @moduledoc """
  The atomic-snapshot drift tripwire for sign_grant (the design-adversarial TOCTOU fix).
  signing_identity/1 returns a consistent {:issuer, kid_a, pub_a} snapshot, then flips
  internal state so sign/2 signs with priv_b (a simulated post-snapshot rotation). The
  atomic snapshot means role+kid+pub cannot drift apart; the verify_signature guard
  catches the sign/2-vs-snapshot mismatch -> :signing_failed, never a silent false-success.
  The handle term is an Agent pid whose state is %{kid:, pub_a:, priv_a:, priv_b:, rotated:}.
  """
  def signing_identity(pid) do
    Agent.get_and_update(pid, fn s -> {{:ok, {:issuer, s.kid, s.pub_a}}, %{s | rotated: true}} end)
  end

  def sign(message, pid) do
    priv = Agent.get(pid, fn s -> if s.rotated, do: s.priv_b, else: s.priv_a end)
    {:ok, :crypto.sign(:eddsa, :none, message, [priv, :ed25519])}
  end

  def public_key(_pid), do: {:ok, <<0::256>>}
  def thumbprint(_pid), do: {:ok, <<0::256>>}
end

defmodule GrantExitingHandle do
  @moduledoc """
  signing_identity/1 calls exit/1 (simulated HSM/key-server timeout). safe_callback's
  catch clause must contain it -> :invalid_key_handle, not a crash.
  """
  @behaviour BoundedAuthorityReportAdapter

  @impl true
  def signing_identity(_handle), do: exit(:simulated_hsm_timeout)

  @impl true
  def sign(_message, _handle), do: exit(:simulated_hsm_timeout)

  @impl true
  def public_key(_handle), do: {:ok, <<0::256>>}

  @impl true
  def thumbprint(_handle), do: {:ok, <<0::256>>}
end

defmodule GrantFailingKeyHandle do
  alias BoundedAuthorityProtocol.V1.Jwk

  @moduledoc "signing_identity/1 + public_key/1 succeed; sign/2 -> {:error, _} -> :signing_failed."
  @behaviour BoundedAuthorityReportAdapter

  @impl true
  def signing_identity({public_key, _private_key}),
    do: {:ok, {:issuer, "issuer-2026-07", public_key}}

  @impl true
  def sign(_message, _handle), do: {:error, :always_fails}

  @impl true
  def public_key({public_key, _private_key}), do: {:ok, public_key}

  @impl true
  def thumbprint({public_key, _private_key}) do
    {:ok, raw} = Jwk.public_key_thumbprint_raw(public_key, %{})
    {:ok, raw}
  end
end
