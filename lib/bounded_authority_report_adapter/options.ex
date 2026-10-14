defmodule BoundedAuthorityReportAdapter.Options do
  @moduledoc false
  # The one boundary check every sign_*/3 entry point applies to its options, before any
  # key-handle callback runs. Options are a plain map or a keyword list; the two forms are
  # the same call. Each entry point passes its schema: the option keys it accepts and the
  # kind of value each takes. Anything else fails closed:
  #
  #   * a value that is neither a plain map nor a proper keyword list (nil, an atom, a
  #     number, a tuple, a binary, a struct, an improper list);
  #   * a repeated key, a key that is not an atom, or an atom key the entry point does not
  #     accept (a misspelled option must not silently fall back to its default);
  #   * a present value of the wrong kind (`proof_id: nil` is not "use the default").
  #
  # The result is {:ok, map} or {:error, key}, where key names the offending option, or is
  # :options when the problem is not one option's value. The entry point maps that to its
  # closed error. Omitting the options argument is each sign_*/3's %{} default and never
  # reaches here.

  @type kind :: :integer | :binary | :bounds | :any
  @type schema :: %{atom() => kind()}

  # The options each kind of entry point accepts, on both suite surfaces. V3.sign_grant/3
  # accepts :role_attestation here only to refuse it with its own closed error.
  @schemas %{
    report: %{bounds: :bounds, issued_at: :integer, proof_id: :binary},
    anchor: %{bounds: :bounds, anchored_at: :integer},
    grant: %{bounds: :bounds, role_attestation: :any},
    key_transition: %{bounds: :bounds},
    content_assertion: %{bounds: :bounds}
  }

  @doc false
  @spec schema(:report | :anchor | :grant | :key_transition | :content_assertion) :: schema()
  def schema(object), do: Map.fetch!(@schemas, object)

  @spec normalize(term(), schema()) :: {:ok, map()} | {:error, atom()}
  def normalize(opts, schema) when is_map(opts) and not is_struct(opts),
    do: check(Map.to_list(opts), schema, %{})

  def normalize(opts, schema) when is_list(opts) do
    case keyword_to_map(opts) do
      {:ok, map} -> check(Map.to_list(map), schema, %{})
      :error -> {:error, :options}
    end
  end

  def normalize(_opts, _schema), do: {:error, :options}

  @doc false
  # A proper keyword list with unique atom keys, as a map.
  @spec keyword_to_map(term()) :: {:ok, map()} | :error
  def keyword_to_map(list) when is_list(list), do: keyword_to_map(list, %{})
  def keyword_to_map(_other), do: :error

  defp keyword_to_map([], acc), do: {:ok, acc}

  defp keyword_to_map([{key, value} | rest], acc) when is_atom(key) and not is_map_key(acc, key),
    do: keyword_to_map(rest, Map.put(acc, key, value))

  defp keyword_to_map(_malformed, _acc), do: :error

  defp check([], _schema, acc), do: {:ok, acc}

  defp check([{key, value} | rest], schema, acc) when is_atom(key) and is_map_key(schema, key) do
    case value(Map.fetch!(schema, key), value) do
      {:ok, value} -> check(rest, schema, Map.put(acc, key, value))
      :error -> {:error, key}
    end
  end

  defp check(_unknown_or_non_atom_key, _schema, _acc), do: {:error, :options}

  defp value(:integer, value) when is_integer(value), do: {:ok, value}
  defp value(:binary, value) when is_binary(value), do: {:ok, value}
  defp value(:bounds, value) when is_map(value) and not is_struct(value), do: {:ok, value}
  defp value(:bounds, %BoundedAuthorityProtocol.V1.Bounds{} = value), do: {:ok, value}
  defp value(:any, value), do: {:ok, value}
  defp value(_kind, _value), do: :error
end
