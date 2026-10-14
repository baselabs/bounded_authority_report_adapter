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
  # Nested options follow the same rule all the way down: a :bounds or :role_attestation
  # value given as a keyword list is the equivalent map, and a malformed one is refused here,
  # before any callback (a role attestation's shape: a binary :compact, a
  # BoundedAuthorityProtocol.V1.HistoricalPublicKey :attestor and an optional integer :now;
  # other keys in it are ignored, because its subject always comes from the key handle).
  #
  # The result is {:ok, map} or {:error, key}, where key names the offending option, or is
  # :options when the problem is not one option's value. The entry point maps that to its
  # closed error. Omitting the options argument is each sign_*/3's %{} default and never
  # reaches here.

  @type kind :: :integer | :binary | :bounds | :role_attestation
  @type schema :: %{atom() => kind()}

  # The options each kind of entry point accepts, on both suite surfaces. V3.sign_grant/3
  # accepts :role_attestation here only to refuse it with its own closed error.
  @schemas %{
    report: %{bounds: :bounds, issued_at: :integer, proof_id: :binary},
    anchor: %{bounds: :bounds, anchored_at: :integer},
    grant: %{bounds: :bounds, role_attestation: :role_attestation},
    key_transition: %{bounds: :bounds},
    content_assertion: %{bounds: :bounds}
  }

  @doc false
  @spec schema(:report | :anchor | :grant | :key_transition | :content_assertion) :: schema()
  def schema(object), do: Map.fetch!(@schemas, object)

  @spec normalize(term(), schema()) :: {:ok, map()} | {:error, atom()}
  def normalize(opts, schema) when is_map(opts) and not is_struct(opts), do: check(opts, schema)

  def normalize(opts, schema) when is_list(opts) do
    case keyword_to_map(opts) do
      {:ok, map} -> check(map, schema)
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

  # Keys first, so an unknown key is reported as such whatever the values are; then each
  # value against its kind.
  defp check(opts, schema) do
    if Enum.all?(Map.keys(opts), &(is_atom(&1) and is_map_key(schema, &1))),
      do: check_values(Map.to_list(opts), schema, %{}),
      else: {:error, :options}
  end

  defp check_values([], _schema, acc), do: {:ok, acc}

  defp check_values([{key, value} | rest], schema, acc) do
    case value(Map.fetch!(schema, key), value) do
      {:ok, value} -> check_values(rest, schema, Map.put(acc, key, value))
      :error -> {:error, key}
    end
  end

  defp value(:integer, value) when is_integer(value), do: {:ok, value}
  defp value(:binary, value) when is_binary(value), do: {:ok, value}
  defp value(:bounds, value) when is_map(value) and not is_struct(value), do: {:ok, value}
  defp value(:bounds, %BoundedAuthorityProtocol.V1.Bounds{} = value), do: {:ok, value}
  defp value(:bounds, value) when is_list(value), do: keyword_value(value)

  defp value(:role_attestation, value) when is_list(value) do
    with {:ok, map} <- keyword_to_map(value), do: value(:role_attestation, map)
  end

  defp value(:role_attestation, %{compact: compact, attestor: attestor} = value)
       when is_binary(compact) and not is_struct(value) and
              is_struct(attestor, BoundedAuthorityProtocol.V1.HistoricalPublicKey) do
    if is_integer(Map.get(value, :now, 0)), do: {:ok, value}, else: :error
  end

  defp value(_kind, _value), do: :error

  defp keyword_value(list) do
    case keyword_to_map(list) do
      {:ok, map} -> {:ok, map}
      :error -> :error
    end
  end
end
