defmodule BoundedAuthorityReportAdapter.DoctorTaskTest do
  @moduledoc """
  The doctor preflight. Each FATAL check is RED-proven: a scratch module
  missing exactly that thing trips exactly that check (the ticket's
  acceptance). The --live probe is proven both ways: a coherent handle passes,
  a wrong-key handle trips the advisory.
  """

  use ExUnit.Case, async: false

  alias BoundedAuthorityProtocol.V1
  alias Mix.Tasks.BoundedAuthorityReportAdapter.Doctor

  def ed_thumb_ref(pub), do: elem(V1.Jwk.public_key_thumbprint_raw(pub, %{}), 1)

  # Scratch handles, one per defect class.
  defmodule FullHandle do
    def sign(message, _ref), do: {:ok, keypair_sign(message)}
    def public_key(_ref), do: {:ok, elem(keypair(), 0)}
    def thumbprint(_ref), do: {:ok, __MODULE__.ed_thumb_ref(elem(keypair(), 0))}
    def key_identity(_ref), do: {:ok, {"k", elem(keypair(), 0)}}
    def signing_identity(_ref), do: {:ok, {:holder, "k", elem(keypair(), 0)}}
    defp keypair, do: :crypto.generate_key(:eddsa, :ed25519, <<7::256>>)
    defp keypair_sign(m), do: :crypto.sign(:eddsa, :none, m, [elem(keypair(), 1), :ed25519])
  end

  defmodule NoSignHandle do
    def public_key(_ref), do: {:ok, elem(:crypto.generate_key(:eddsa, :ed25519, <<7::256>>), 0)}

    def thumbprint(_ref),
      do: {:ok, __MODULE__.ed_thumb_ref(elem(:crypto.generate_key(:eddsa, :ed25519, <<7::256>>), 0))}

    def key_identity(_ref),
      do: {:ok, {"k", :crypto.generate_key(:eddsa, :ed25519, <<7::256>>) |> elem(0)}}

    def signing_identity(_ref), do: {:ok, {:holder, "k", :key}}
  end

  defmodule NoPublicKeyHandle do
    def sign(_m, _r), do: {:ok, <<0::512>>}
    def thumbprint(_r), do: {:ok, <<0::256>>}
    def key_identity(_r), do: {:ok, {"k", :key}}
    def signing_identity(_r), do: {:ok, {:holder, "k", :key}}
  end

  defmodule NoThumbprintHandle do
    def sign(_m, _r), do: {:ok, <<0::512>>}
    def public_key(_r), do: {:ok, elem(:crypto.generate_key(:eddsa, :ed25519, <<7::256>>), 0)}
    def key_identity(_r), do: {:ok, {"k", :key}}
    def signing_identity(_r), do: {:ok, {:holder, "k", :key}}
  end

  defmodule ShortKeyHandle do
    def sign(_m, _r), do: {:ok, <<0::512>>}
    def public_key(_ref), do: {:ok, <<1, 2, 3>>}
    def thumbprint(_r), do: {:ok, <<0::256>>}
    def key_identity(_r), do: {:ok, {"k", :key}}
    def signing_identity(_r), do: {:ok, {:holder, "k", :key}}
  end

  defmodule MinimalHandle do
    def sign(_m, _r), do: {:ok, <<0::512>>}
    def public_key(_r), do: {:ok, elem(:crypto.generate_key(:eddsa, :ed25519, <<7::256>>), 0)}

    def thumbprint(_r),
      do: {:ok, __MODULE__.ed_thumb_ref(elem(:crypto.generate_key(:eddsa, :ed25519, <<7::256>>), 0))}
  end

  defmodule WrongKeyHandle do
    def sign(m, _r),
      do:
        {:ok,
         :crypto.sign(:eddsa, :none, m, [
           elem(:crypto.generate_key(:eddsa, :ed25519, <<9::256>>), 1),
           :ed25519
         ])}

    def public_key(_r), do: {:ok, elem(:crypto.generate_key(:eddsa, :ed25519, <<7::256>>), 0)}

    def thumbprint(_r),
      do: {:ok, __MODULE__.ed_thumb_ref(elem(:crypto.generate_key(:eddsa, :ed25519, <<7::256>>), 0))}

    def key_identity(_r), do: {:ok, {"k", :key}}
    def signing_identity(_r), do: {:ok, {:holder, "k", :key}}
  end

  # EC fixtures (ADR-0021): a clean P-256 handle, an off-curve key, a
  # thumbprint mismatch, a high-S producer, and a valid-point wrong-curve key.
  defmodule FullECHandle do
    alias BoundedAuthorityReportAdapter.TestKeys

    defp keypair, do: :crypto.generate_key(:ecdh, :prime256v1, <<7::256>>)

    def sign(message, _ref), do: {:ok, TestKeys.ec_sign_raw_low_s(message, elem(keypair(), 1))}

    def public_key(_ref), do: {:ok, elem(keypair(), 0)}

    def thumbprint(_ref), do: {:ok, TestKeys.ec_thumbprint_raw(elem(keypair(), 0))}

    def key_identity(_ref), do: {:ok, {"k", elem(keypair(), 0)}}
    def signing_identity(_ref), do: {:ok, {:holder, "k", elem(keypair(), 0)}}
  end

  defmodule OffCurveECHandle do
    def sign(_m, _r), do: {:ok, <<0::512>>}
    def public_key(_r), do: {:ok, <<4>> <> String.duplicate(<<0xFF>>, 64)}
    def thumbprint(_r), do: {:ok, <<0::256>>}
    def key_identity(_r), do: {:ok, {"k", :key}}
    def signing_identity(_r), do: {:ok, {:holder, "k", :key}}
  end

  defmodule ThumbprintMismatchECHandle do
    alias BoundedAuthorityReportAdapter.TestKeys

    def sign(message, _r),
      do: {:ok, TestKeys.ec_sign_raw_low_s(message, elem(keypair(), 1))}

    def public_key(_r), do: {:ok, elem(keypair(), 0)}

    # The WRONG preimage: a hash of the raw key bytes, not the RFC 7638 EC
    # member set — exactly the implementation mistake the fatal exists for.
    def thumbprint(_r), do: {:ok, :crypto.hash(:sha256, elem(keypair(), 0))}

    defp keypair, do: :crypto.generate_key(:ecdh, :prime256v1, <<7::256>>)
  end

  defmodule HighSECHandle do
    alias BoundedAuthorityReportAdapter.TestKeys

    @ec_n TestKeys.ec_n()
    @ec_half_n div(@ec_n, 2)

    def sign(message, _r) do
      raw = TestKeys.ec_sign_raw_low_s(message, elem(keypair(), 1))
      <<r::binary-32, s::binary-32>> = raw
      si = :binary.decode_unsigned(s)
      s_bytes = if si > @ec_half_n, do: si, else: @ec_n - si
      bytes = :binary.encode_unsigned(s_bytes)
      {:ok, r <> String.duplicate(<<0>>, 32 - byte_size(bytes)) <> bytes}
    end

    def public_key(_r), do: {:ok, elem(keypair(), 0)}
    def thumbprint(_r), do: {:ok, TestKeys.ec_thumbprint_raw(elem(keypair(), 0))}
    defp keypair, do: :crypto.generate_key(:ecdh, :prime256v1, <<7::256>>)
  end

  test "a fully-wired handle is clean" do
    assert %{fatals: [], advisories: []} = Doctor.check(FullHandle, :ref, true)
  end

  test "RED: an unloaded module trips exactly the not-loaded fatal" do
    assert %{fatals: [fatal]} = Doctor.check(NoSuchHandleModule, :ref, false)
    assert fatal =~ "not loaded / does not exist"
  end

  test "RED: missing sign/2 trips exactly that fatal" do
    assert %{fatals: [fatal]} = Doctor.check(NoSignHandle, :ref, false)
    assert fatal == "missing required callback sign/2"
  end

  test "RED: missing public_key/1 trips exactly that fatal" do
    assert %{fatals: [fatal]} = Doctor.check(NoPublicKeyHandle, :ref, false)
    assert fatal == "missing required callback public_key/1"
  end

  test "RED: missing thumbprint/1 trips exactly that fatal" do
    assert %{fatals: [fatal]} = Doctor.check(NoThumbprintHandle, :ref, false)
    assert fatal == "missing required callback thumbprint/1"
  end

  test "RED: a short public key trips the 32-byte fatal" do
    assert %{fatals: [fatal]} = Doctor.check(ShortKeyHandle, :ref, false)
    assert fatal =~ "32-byte"
  end

  test "minimal handle: no fatals, both advisories (which operation each blocks)" do
    assert %{fatals: [], advisories: advisories} = Doctor.check(MinimalHandle, :ref, false)

    assert Enum.any?(advisories, &(&1 =~ "key_identity/1 absent" and &1 =~ "sign_anchor/3"))
    assert Enum.any?(advisories, &(&1 =~ "signing_identity/1 absent" and &1 =~ "sign_grant/3"))
  end

  test "--live: a wrong-key handle trips the wrong-key advisory" do
    assert %{fatals: [], advisories: advisories} = Doctor.check(WrongKeyHandle, :ref, true)
    assert Enum.any?(advisories, &(&1 =~ "--live probe" and &1 =~ "wrong-key"))
  end

  test "--live is skipped with a note when fatals exist" do
    assert %{fatals: [_ | _], advisories: advisories} = Doctor.check(NoSignHandle, :ref, true)
    assert Enum.any?(advisories, &(&1 =~ "--live skipped"))
  end

  test "a fully-wired P-256 handle is clean (major-3 surface, --live green)" do
    assert %{fatals: [], advisories: []} = Doctor.check(FullECHandle, :ref, true)
  end

  test "RED: a 65-byte key that is not a P-256 point trips the shape fatal" do
    assert %{fatals: fatals} = Doctor.check(OffCurveECHandle, :ref, false)
    assert Enum.any?(fatals, &(&1 =~ "65-byte on-curve P-256 point"))
  end

  test "RED: a thumbprint over the wrong preimage trips the match fatal" do
    assert %{fatals: fatals} = Doctor.check(ThumbprintMismatchECHandle, :ref, false)
    assert Enum.any?(fatals, &(&1 =~ "RFC 7638 digest derived from public_key/1"))
  end

  test "--major 3: an Ed25519 key is fatal; --major 1: a P-256 key is fatal" do
    assert %{fatals: fatals} = Doctor.check(FullHandle, :ref, false, 3)
    assert Enum.any?(fatals, &(&1 =~ "wrong key type for --major 3"))

    assert %{fatals: fatals} = Doctor.check(FullECHandle, :ref, false, 1)
    assert Enum.any?(fatals, &(&1 =~ "wrong key type for --major 1"))
  end

  test "--major with a matching key stays clean and reports the unlocked surface" do
    assert %{fatals: [], advisories: advisories} =
             Doctor.check(FullECHandle, :ref, false, 3)

    assert Enum.any?(advisories, &(&1 =~ "major-3 surface"))
  end

  test "--live on a high-S P-256 handle: the normalization advisory, not a failure" do
    assert %{fatals: [], advisories: advisories} = Doctor.check(HighSECHandle, :ref, true)
    assert Enum.any?(advisories, &(&1 =~ "HIGH-S" and &1 =~ "normalizes"))
  end

  # --- the run/1 CLI wrapper (exit discipline + shell output) ---

  # Capture the shell for the run/1 tests, restoring whatever was set before
  # (never a hardcoded shell — a CI wrapper may run the suite under another one).
  defp with_process_shell(fun) do
    prior = Mix.shell()
    Mix.shell(Mix.Shell.Process)

    try do
      fun.()
    after
      Mix.shell(prior)
    end
  end

  @tag :capture_shell
  test "run/1 exits 1 and prints the fatal on a bad handle" do
    with_process_shell(fn ->
      assert catch_exit(Doctor.run(["--handle", "NoSuchHandleModule"])) == {:shutdown, 1}

      assert_received {:mix_shell, :error, ["[FATAL] " <> fatal]}
      assert fatal =~ "not loaded / does not exist"
    end)
  end

  @tag :capture_shell
  test "run/1 without --handle exits 1 with the usage fatal" do
    with_process_shell(fn ->
      assert catch_exit(Doctor.run([])) == {:shutdown, 1}
      assert_received {:mix_shell, :error, ["[FATAL] --handle <Module> is required"]}
    end)
  end

  @tag :capture_shell
  test "run/1 on a clean handle prints clean and does not exit" do
    with_process_shell(fn ->
      Doctor.run(["--handle", "BoundedAuthorityReportAdapter.DoctorTaskTest.FullHandle"])
      assert_received {:mix_shell, :info, ["doctor: clean"]}
    end)
  end
end
