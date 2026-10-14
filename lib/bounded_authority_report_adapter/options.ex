defmodule BoundedAuthorityReportAdapter.Options do
  @moduledoc false
  # The one boundary normalization every sign_*/3 entry point applies to its options: a map
  # is used as given, and a keyword list becomes the equivalent map, so the two forms are the
  # same call. A list that is not a proper keyword list with unique atom keys is malformed.
  # Each entry point decides what any other value means (the five original major-1 entry
  # points and the V3 entry points use their defaults; sign_content_assertion/3 refuses it).

  @spec normalize(term()) :: {:ok, map()} | :malformed | :not_options
  def normalize(opts) when is_map(opts), do: {:ok, opts}
  def normalize(opts) when is_list(opts), do: from_keyword(opts, %{})
  def normalize(_opts), do: :not_options

  defp from_keyword([], acc), do: {:ok, acc}

  defp from_keyword([{key, value} | rest], acc) when is_atom(key) and not is_map_key(acc, key),
    do: from_keyword(rest, Map.put(acc, key, value))

  defp from_keyword(_malformed, _acc), do: :malformed
end
