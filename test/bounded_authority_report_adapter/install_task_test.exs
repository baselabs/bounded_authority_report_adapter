defmodule BoundedAuthorityReportAdapter.InstallTaskTest do
  @moduledoc """
  The Igniter installer: scaffolds a starter key-handle that compiles clean and
  RAISES on every callback until wired (the no-accidental-signing posture), and
  imports the dep into the consumer's .formatter.exs.

  The no-igniter fallback (a clean Mix.raise with the remedy) is exercised by
  the smoke transcript in the ticket closeout — it compiles only when igniter
  is absent, which is never the case in this test env.
  """

  use ExUnit.Case, async: false

  alias Igniter.Test, as: IT

  defp run_install do
    IT.test_project()
    |> Igniter.compose_task("bounded_authority_report_adapter.install", [
      "--module",
      "MyApp.HolderKey"
    ])
  end

  test "scaffolds a starter handle that declares the behaviour and raises until wired" do
    IT.assert_creates(run_install(), "lib/my_app/holder_key.ex", fn content ->
      assert content =~ "@behaviour BoundedAuthorityReportAdapter"

      assert content =~ "raise \"wire MyApp.HolderKey.sign/2",
             "the scaffold must not sign anything until the consumer wires a key store"

      # All five callbacks present (the behaviour compiles warning-clean).
      for callback <- ~w(sign public_key thumbprint key_identity signing_identity) do
        assert content =~ "def #{callback}("
      end
    end)
  end

  test "imports the dep into the consumer's .formatter.exs" do
    # The formatter file already exists — this is a modification, so assert on
    # the planned diff rather than a creation.
    assert IT.diff(run_install()) =~ "import_deps: [:bounded_authority_report_adapter]"
  end

  test "the no-igniter fallback branch compiles and raises with the remedy" do
    source = File.read!("lib/mix/tasks/bounded_authority_report_adapter.install.ex")

    [_real, fallback] = String.split(source, "else\n", parts: 2)
    # Drop the trailing `end` that closes the outer `if` in the task file.
    {fallback, _closing_end} = String.split_at(fallback, String.length(fallback) - 4)
    fallback = String.trim_trailing(fallback)

    # Compile under a PROBE name: compiling the real name would redefine the
    # loaded task module for the rest of the VM (order-dependent poisoning of
    # the other tests in this module).
    probe = "Mix.Tasks.BoundedAuthorityReportAdapter.InstallFallbackProbe"

    fallback =
      String.replace(
        fallback,
        "defmodule Mix.Tasks.BoundedAuthorityReportAdapter.Install do",
        "defmodule #{probe} do"
      )

    {result, diagnostics} = Code.with_diagnostics(fn -> Code.compile_string(fallback) end)

    assert is_list(result),
           "the no-igniter fallback branch no longer compiles: #{inspect(diagnostics)}"

    for diagnostic <- diagnostics do
      refute diagnostic.severity == :error, inspect(diagnostic)
    end

    assert_raise Mix.Error, ~r/requires the optional :igniter dependency/, fn ->
      String.to_atom("Elixir." <> probe).run([])
    end
  end
end
