defmodule BoundedAuthorityReportAdapter.V3TestHandles do
  @moduledoc """
  Test-only EC key-handle modules for the v3 signing suite (ADR-0021's
  failure-modes matrix). Compiled in `:test` only, like every handle under
  `test/support/` (ADR-0014).

  The modules below are TOP-LEVEL (not nested under this wrapper) — the
  house pattern `test_handles.ex` documents: handles defined inside a
  wrapper or at the bottom of a `_test.exs` file can stay unloaded in some
  `mix test` orderings, which makes the suites flaky.

  Each hostile handle isolates ONE producer-side failure class the v3 tail
  must close: high-S returns, DER-native returns, out-of-range scalars,
  off-curve and wrong-curve key material, right-width wrong-suite signatures,
  and the rotation race. `GrantIssuerECKeyHandle` is the issuer-role
  reference for `V3.sign_grant/3`; `CapturingECKeyHandle` captures the exact
  `sign/2` message and return for the differential-agreement and
  pass-through legs.
  """

  alias BoundedAuthorityReportAdapter.TestKeys

  @doc "The P-256 group order (the low-S boundary), for handle fixtures."
  def ec_n, do: TestKeys.ec_n()
end

defmodule HighSECKeyHandle do
  @moduledoc """
  Signs VALIDLY, then deterministically re-spells the signature HIGH-S
  (`s ← n − s` when the return is low) — a real `(r, n − s)` counterpart
  that satisfies the verification equation but violates `REQ3-SIGNING-low-s`.
  The adapter's normalization (ADR-0021 Decision 4) must recover the low-S
  spelling and emit a conforming compact.
  """
  @behaviour BoundedAuthorityReportAdapter

  alias BoundedAuthorityReportAdapter.TestKeys

  @ec_n TestKeys.ec_n()
  @ec_half_n div(@ec_n, 2)

  @impl true
  def sign(message, {_public_key, private_key}) when is_binary(message) do
    raw = TestKeys.ec_sign_raw_low_s(message, private_key)
    <<r::binary-32, s::binary-32>> = raw
    si = :binary.decode_unsigned(s)
    s_bytes = if si > @ec_half_n, do: si, else: @ec_n - si
    {:ok, r <> pad32(s_bytes)}
  end

  def sign(_message, _handle), do: {:error, :invalid_handle}

  @impl true
  def public_key({public_key, _private_key}), do: {:ok, public_key}

  @impl true
  def thumbprint({public_key, _private_key}), do: {:ok, TestKeys.ec_thumbprint_raw(public_key)}

  defp pad32(int) do
    bytes = :binary.encode_unsigned(int)
    String.duplicate(<<0>>, 32 - byte_size(bytes)) <> bytes
  end
end

defmodule DerReturnECKeyHandle do
  @moduledoc """
  Returns OTP's native `:crypto.sign/5` ECDSA output — DER
  (`0x30`-led SEQUENCE). DER is never a v3 wire spelling: the tail must
  close it as `:signing_failed`, never convert, never emit a compact
  (ADR-0021 Decision 3).
  """
  @behaviour BoundedAuthorityReportAdapter

  alias BoundedAuthorityReportAdapter.TestKeys

  @impl true
  def sign(message, {_public_key, private_key}) when is_binary(message) do
    {:ok, :crypto.sign(:ecdsa, :sha256, message, [private_key, :prime256v1])}
  end

  def sign(_message, _handle), do: {:error, :invalid_handle}

  @impl true
  def public_key({public_key, _private_key}), do: {:ok, public_key}

  @impl true
  def thumbprint({public_key, _private_key}), do: {:ok, TestKeys.ec_thumbprint_raw(public_key)}
end

defmodule CraftedSignatureHandle do
  @moduledoc """
  Returns a caller-crafted 64-byte blob as the signature (the handle term
  is `{public_key, blob}`). The scalar-range legs drive this with zero `r`,
  `r = n`, `s = n`, `s = n + 1`, and `s = n − 1` spellings — each must
  collapse to `:signing_failed` with no raise and no compact (ADR-0021
  Decision 4's order: the RAW range check precedes normalization).
  """
  @behaviour BoundedAuthorityReportAdapter

  alias BoundedAuthorityReportAdapter.TestKeys

  @impl true
  def sign(_message, {_public_key, blob}), do: {:ok, blob}

  @impl true
  def public_key({public_key, _blob}), do: {:ok, public_key}

  @impl true
  def thumbprint({public_key, _blob}), do: {:ok, TestKeys.ec_thumbprint_raw(public_key)}
end

defmodule OffCurveKeyHandle do
  @moduledoc """
  `public_key/1` returns a 65-byte `0x04`-led binary whose coordinates are
  NOT a P-256 point (all-`0xFF` — outside the field). The v3 resolvers must
  reject it as `:invalid_key_handle` through the point validation
  (ADR-0021 Decision 2) — INCLUDING on `V3.sign_grant/3`, whose bytes never
  reach BAP's own key arithmetic.
  """
  @behaviour BoundedAuthorityReportAdapter

  @off_curve <<4>> <> String.duplicate(<<0xFF>>, 64)

  @impl true
  def sign(_message, _handle), do: {:error, :unused}

  @impl true
  def public_key(_handle), do: {:ok, @off_curve}

  @impl true
  def thumbprint(_handle), do: {:ok, <<0::256>>}
end

defmodule WrongCurveKeyHandle do
  @moduledoc """
  `public_key/1` returns a VALID secp256k1 point — exactly the mis-wired
  custody slot of the design review's finding 1: right width, right prefix,
  real point, wrong curve. Only the on-curve arithmetic catches it.
  """
  @behaviour BoundedAuthorityReportAdapter

  {secp_pub, _} = :crypto.generate_key(:ecdh, :secp256k1, <<3::256>>)
  @secp_pub secp_pub

  @impl true
  def sign(_message, _handle), do: {:error, :unused}

  @impl true
  def public_key(_handle), do: {:ok, @secp_pub}

  @impl true
  def thumbprint(_handle), do: {:ok, <<0::256>>}
end

defmodule WrongSuiteHandle do
  @moduledoc """
  `public_key/1` returns a valid 65-byte P-256 point, but `sign/2` produces
  an Ed25519 signature (an Ed private key rides the term). Both suites'
  signatures are exactly 64 bytes, so only the verify guard can separate
  them: `:signing_failed`, never a compact (ADR-0021, the
  right-width-wrong-suite leg).
  """
  @behaviour BoundedAuthorityReportAdapter

  alias BoundedAuthorityReportAdapter.TestKeys

  @impl true
  def sign(message, {_public_key, ed_private_key}) do
    {:ok, :crypto.sign(:eddsa, :none, message, [ed_private_key, :ed25519])}
  end

  @impl true
  def public_key({public_key, _ed_private_key}), do: {:ok, public_key}

  @impl true
  def thumbprint({public_key, _ed_private_key}),
    do: {:ok, TestKeys.ec_thumbprint_raw(public_key)}
end

defmodule WrongKeyECHandle do
  @moduledoc """
  `public_key/1` returns key A's P-256 material; `sign/2` signs with a
  DIFFERENT P-256 key B (the rotation/misconfiguration race). The v3
  wrong-key guard must reject: `:signing_failed`.
  """
  @behaviour BoundedAuthorityReportAdapter

  alias BoundedAuthorityReportAdapter.TestKeys

  @impl true
  def sign(message, _handle) do
    {_other_pub, other_priv} = TestKeys.ec_keypair(<<99::256>>)
    {:ok, TestKeys.ec_sign_raw_low_s(message, other_priv)}
  end

  @impl true
  def public_key({public_key, _private_key}), do: {:ok, public_key}

  @impl true
  def thumbprint({public_key, _private_key}), do: {:ok, TestKeys.ec_thumbprint_raw(public_key)}
end

defmodule GrantIssuerECKeyHandle do
  @moduledoc """
  The issuer-role handle for `V3.sign_grant/3`:
  `signing_identity/1 -> {:issuer, "issuer-2026-09", pub}` over P-256
  material (the EC mirror of `GrantIssuerHandle`).
  """
  @behaviour BoundedAuthorityReportAdapter

  alias BoundedAuthorityReportAdapter.TestKeys

  @issuer_kid "issuer-2026-09"

  @impl true
  def signing_identity({public_key, _private_key}),
    do: {:ok, {:issuer, @issuer_kid, public_key}}

  @impl true
  def sign(message, {_public_key, private_key}),
    do: {:ok, TestKeys.ec_sign_raw_low_s(message, private_key)}

  @impl true
  def public_key({public_key, _private_key}), do: {:ok, public_key}

  @impl true
  def thumbprint({public_key, _private_key}), do: {:ok, TestKeys.ec_thumbprint_raw(public_key)}

  def issuer_kid, do: @issuer_kid
end

defmodule GrantHolderECKeyHandle do
  @moduledoc """
  The C1 tripwire for `V3.sign_grant/3`: a valid P-256 handle whose
  `signing_identity/1` declares `:holder`. The role gate must reject it
  BEFORE `sign/2` (count stays 0).
  """
  @behaviour BoundedAuthorityReportAdapter

  alias BoundedAuthorityReportAdapter.TestKeys

  @key {__MODULE__, :sign_count}

  @impl true
  def signing_identity({public_key, _private_key}),
    do: {:ok, {:holder, "holder-v3-test", public_key}}

  @impl true
  def sign(message, {_public_key, private_key}) do
    Process.put(@key, (Process.get(@key) || 0) + 1)
    {:ok, TestKeys.ec_sign_raw_low_s(message, private_key)}
  end

  @impl true
  def public_key({public_key, _private_key}), do: {:ok, public_key}

  @impl true
  def thumbprint({public_key, _private_key}), do: {:ok, TestKeys.ec_thumbprint_raw(public_key)}

  def sign_call_count, do: Process.get(@key) || 0
end

defmodule CapturingECKeyHandle do
  @moduledoc """
  Captures the message handed to `sign/2` AND the exact signature bytes it
  returned (the EC mirror of `CapturingKeyHandle`) — the
  differential-agreement leg needs the signing input BAP produced, and the
  low-S pass-through leg needs the handle's own return to compare against
  the compact's signature segment.
  """
  @behaviour BoundedAuthorityReportAdapter

  alias BoundedAuthorityReportAdapter.TestKeys

  @message_key {__MODULE__, :message}
  @signature_key {__MODULE__, :signature}

  @impl true
  def sign(message, {_public_key, private_key}) do
    signature = TestKeys.ec_sign_raw_low_s(message, private_key)
    Process.put(@message_key, message)
    Process.put(@signature_key, signature)
    {:ok, signature}
  end

  @impl true
  def public_key({public_key, _private_key}), do: {:ok, public_key}

  @impl true
  def thumbprint({public_key, _private_key}), do: {:ok, TestKeys.ec_thumbprint_raw(public_key)}

  def captured_message, do: Process.get(@message_key)
  def captured_signature, do: Process.get(@signature_key)
end

defmodule EdSnapshotIssuerHandle do
  @moduledoc """
  An `{:issuer, kid, 32-byte-key}` snapshot over Ed25519 material — the v3
  grant path must reject it (the width literal and the C1 role share a
  clause head; the design review's finding 5), and `sign/2` must never be
  reached.
  """
  @behaviour BoundedAuthorityReportAdapter

  @key {__MODULE__, :sign_count}

  def signing_identity({public_key, _private_key}),
    do: {:ok, {:issuer, "issuer-2026-09", public_key}}

  def sign(_message, _handle) do
    Process.put(@key, (Process.get(@key) || 0) + 1)
    {:error, :must_not_be_called}
  end

  def public_key({public_key, _private_key}), do: {:ok, public_key}
  def thumbprint(_handle), do: {:ok, <<0::256>>}
  def sign_call_count, do: Process.get(@key) || 0
end

defmodule ECSnapshotIssuerHandle do
  @moduledoc """
  An `{:issuer, kid, 65-byte-key}` snapshot over P-256 material — the v1
  grant path must reject it (the C1-under-widening mirror of
  `EdSnapshotIssuerHandle`).
  """
  @behaviour BoundedAuthorityReportAdapter

  def signing_identity({public_key, _private_key}),
    do: {:ok, {:issuer, "issuer-2026-07", public_key}}

  def sign(_message, _handle), do: {:error, :must_not_be_called}
  def public_key({public_key, _private_key}), do: {:ok, public_key}
  def thumbprint(_handle), do: {:ok, <<0::256>>}
end
