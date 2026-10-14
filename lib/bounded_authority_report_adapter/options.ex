defmodule BoundedAuthorityReportAdapter.Options do
  @moduledoc false
  # The one boundary normalization every sign_*/3 entry point applies to its options: a map
  # is used as given, and a keyword list becomes the equivalent map, so the two forms are the
  # same call. Anything else is malformed, fail closed: a list that is not a proper keyword
  # list with unique atom keys, and any other value (nil, an atom, a number, a tuple, a
  # binary). Each entry point returns its closed input error for :malformed. Omitting the
  # options argument is the %{} default of each sign_*/3, not a value that reaches here.

  @spec normalize(term()) :: {:ok, map()} | :malformed
  def normalize(opts) when is_map(opts), do: {:ok, opts}
  def normalize(opts) when is_list(opts), do: from_keyword(opts, %{})
  def normalize(_opts), do: :malformed

  defp from_keyword([], acc), do: {:ok, acc}

  defp from_keyword([{key, value} | rest], acc) when is_atom(key) and not is_map_key(acc, key),
    do: from_keyword(rest, Map.put(acc, key, value))

  defp from_keyword(_malformed, _acc), do: :malformed
end
