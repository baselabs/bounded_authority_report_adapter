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
end
