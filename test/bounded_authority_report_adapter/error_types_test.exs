defmodule BoundedAuthorityReportAdapter.ErrorTypesTest do
  @moduledoc """
  The error types are the contract callers dialyze against, so every error an entry point
  can return must be in its declared type. The two suite surfaces share their error sets:
  each `*_sign_error` type on `BoundedAuthorityReportAdapter.V3` must name exactly the
  errors of its namesake on `BoundedAuthorityReportAdapter`, and the errors that only the
  V3 surface can produce are pinned against the V3 types by calling the function.
  """

  use ExUnit.Case, async: true

  alias BoundedAuthorityReportAdapter.V3

  @shared_types [:sign_error, :anchor_sign_error, :grant_sign_error, :transition_sign_error]

  test "each V3 error type names exactly the errors of its major-1 namesake" do
    for type <- @shared_types do
      assert error_terms(V3, type) == error_terms(BoundedAuthorityReportAdapter, type),
             "V3.#{type}/0 and BoundedAuthorityReportAdapter.#{type}/0 differ"
    end
  end

  test "V3.sign_grant/3 refuses the role-attestation option with an error its type declares" do
    for opts <- [%{role_attestation: nil}, [role_attestation: nil]] do
      assert {:error, reason} = V3.sign_grant(%{}, {NoSuchHandle, :ref}, opts)
      assert reason == :invalid_role_attestation
      assert reason in error_terms(V3, :grant_sign_error)
    end
  end

  # The members of a union-of-errors type, as terms: atoms and the one fixed tuple.
  defp error_terms(module, type) do
    {:ok, types} = Code.Typespec.fetch_types(module)

    {:type, {^type, ast, []}} =
      Enum.find(types, &match?({:type, {^type, _ast, []}}, &1)) ||
        flunk("#{inspect(module)} has no #{type}/0 type")

    ast |> union_members() |> Enum.map(&to_term/1) |> Enum.sort()
  end

  defp union_members({:type, _line, :union, members}), do: members
  defp union_members(single), do: [single]

  defp to_term({:atom, _line, atom}), do: atom

  defp to_term({:type, _line, :tuple, elements}),
    do: elements |> Enum.map(&to_term/1) |> List.to_tuple()
end
