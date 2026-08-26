defmodule BoundedAuthorityReportAdapter.DoctorTaskTest do
  @moduledoc """
  The doctor preflight. Each FATAL check is RED-proven: a scratch module
  missing exactly that thing trips exactly that check (the ticket's
  acceptance). The --live probe is proven both ways: a coherent handle passes,
  a wrong-key handle trips the advisory.
  """

  use ExUnit.Case, async: false

  alias Mix.Tasks.BoundedAuthorityReportAdapter.Doctor

  # Scratch handles, one per defect class.
  defmodule FullHandle do
    def sign(message, _ref), do: {:ok, keypair_sign(message)}
    def public_key(_ref), do: {:ok, elem(keypair(), 0)}
    def thumbprint(_ref), do: {:ok, :crypto.hash(:sha256, elem(keypair(), 0))}
    def key_identity(_ref), do: {:ok, {"k", elem(keypair(), 0)}}
    def signing_identity(_ref), do: {:ok, {:holder, "k", elem(keypair(), 0)}}
    defp keypair, do: :crypto.generate_key(:eddsa, :ed25519, <<7::256>>)
    defp keypair_sign(m), do: :crypto.sign(:eddsa, :none, m, [elem(keypair(), 1), :ed25519])
  end

  defmodule NoSignHandle do
    def public_key(_ref), do: {:ok, elem(:crypto.generate_key(:eddsa, :ed25519, <<7::256>>), 0)}
    def thumbprint(_ref), do: {:ok, <<0::256>>}

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
    def thumbprint(_r), do: {:ok, <<0::256>>}
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
    def thumbprint(_r), do: {:ok, <<0::256>>}
    def key_identity(_r), do: {:ok, {"k", :key}}
    def signing_identity(_r), do: {:ok, {:holder, "k", :key}}
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

  # --- the run/1 CLI wrapper (exit discipline + shell output) ---

  @tag :capture_shell
  test "run/1 exits 1 and prints the fatal on a bad handle" do
    Mix.shell(Mix.Shell.Process)

    assert catch_exit(Doctor.run(["--handle", "NoSuchHandleModule"])) == {:shutdown, 1}

    assert_received {:mix_shell, :error, ["[FATAL] " <> fatal]}
    assert fatal =~ "not loaded / does not exist"
  after
    Mix.shell(Mix.Shell.IO)
  end

  @tag :capture_shell
  test "run/1 without --handle exits 1 with the usage fatal" do
    Mix.shell(Mix.Shell.Process)

    assert catch_exit(Doctor.run([])) == {:shutdown, 1}
    assert_received {:mix_shell, :error, ["[FATAL] --handle <Module> is required"]}
  after
    Mix.shell(Mix.Shell.IO)
  end

  @tag :capture_shell
  test "run/1 on a clean handle prints clean and does not exit" do
    Mix.shell(Mix.Shell.Process)

    Doctor.run(["--handle", "BoundedAuthorityReportAdapter.DoctorTaskTest.FullHandle"])
    assert_received {:mix_shell, :info, ["doctor: clean"]}
  after
    Mix.shell(Mix.Shell.IO)
  end
end
