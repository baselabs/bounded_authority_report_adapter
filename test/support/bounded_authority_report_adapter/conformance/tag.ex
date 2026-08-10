defmodule BoundedAuthorityReportAdapter.Conformance.Tag do
  @moduledoc """
  TEST-ONLY translator: the vector's typed-JSON array form to BAP's tagged
  `Json.value()` tuple form (design §1.6 A).

  The vector stores typed values as JSON arrays `["typename", value]` (e.g.
  `["object", {...}]`, `["string", "us-east"]`). BAP's `RequestDigest.typed/1`
  requires the tagged tuple form (`{:object, members}`, `{:string, v}`, ...).
  A raw map or a JSON-decoded list is rejected (`{:error, :invalid}`).

  ## No type guard on the object/array arms

  `:json.decode` decodes JSON objects to Elixir `%{}{}` maps, and `Enum.map`
  over a map yields `{key, value}` tuples — so the object arm's `fn {k,v}`
  body is happy with a map. A `when is_list(members)` guard would BREAK on the
  real (map-shaped) data (verified first-hand during the design).
  """

  @doc """
  Translates a `["type", value]` JSON-array form into a BAP tagged tuple.

      iex> from_json(["string", "us-east"])
      {:string, "us-east"}

      iex> from_json(["integer", 10])
      {:integer, 10}

      iex> from_json(["null"])
      :null
  """
  # The null tagged value is encoded as a SINGLE-element array `["null"]`
  # (BAP's typed JSON form has no value slot for null), so it has its own clause
  # head before the 2-element `[type, value]` match — otherwise the documented
  # arm is unreachable and `from_json(["null"])` raises FunctionClauseError
  # (cross-vendor CV-null finding). The vector carries no null values today,
  # but the translator must be correct for any future vector encoding.
  def from_json(["null"]), do: :null

  def from_json([type, value]) do
    case type do
      "object" -> {:object, Enum.map(value, fn {k, v} -> {k, from_json(v)} end)}
      "string" -> {:string, value}
      "integer" -> {:integer, value}
      "boolean" -> {:boolean, value}
      # BAP's JCS canonicalization encodes an integer-valued float (e.g. 1.0) as
      # `1` (no fractional part), so :json.decode yields an integer for a
      # `["float", 1]` tag. RequestDigest.typed/1 requires is_float/1 on the
      # {:float, _} arm, so coerce the value to a float here (a cross-vendor
      # finding: the prior arm preserved the integer, rejecting the round-trip).
      "float" -> {:float, value * 1.0}
      "array" -> {:array, Enum.map(value, &from_json/1)}
    end
  end
end
