defmodule BoundedAuthorityReportAdapter.Conformance.TagTest do
  @moduledoc """
  Unit tests for the Tag.from_json/1 typed-tuple translator.

  The pinned vector carries only object/string/integer tags, so the
  boolean/float/array/null arms ship with zero executing coverage unless tested
  directly (a cross-vendor finding). These tests cover every arm, including the
  null single-element clause and the float coercion (JCS encodes integer-valued
  floats without the fractional part).
  """

  use ExUnit.Case, async: true

  alias BoundedAuthorityReportAdapter.Conformance.Tag

  describe "the typed-tuple translation" do
    test "object -> {:object, members} (recursive)" do
      assert Tag.from_json(["object", %{"a" => ["string", "x"], "b" => ["integer", 2]}]) ==
               {:object, [{"a", {:string, "x"}}, {"b", {:integer, 2}}]}
    end

    test "string -> {:string, v}" do
      assert Tag.from_json(["string", "us-east"]) == {:string, "us-east"}
    end

    test "integer -> {:integer, v}" do
      assert Tag.from_json(["integer", 10]) == {:integer, 10}
    end

    test "boolean -> {:boolean, v}" do
      assert Tag.from_json(["boolean", true]) == {:boolean, true}
      assert Tag.from_json(["boolean", false]) == {:boolean, false}
    end

    test "float -> {:float, v} (coerces integer-valued floats JCS encodes as integers)" do
      # BAP's JCS encodes 1.0 as `1`, so :json.decode yields an integer 1 for a
      # ["float", 1] tag. The coercion (value * 1.0) makes is_float/1 pass for
      # RequestDigest.typed.
      result = Tag.from_json(["float", 1])
      assert result == {:float, 1.0}
      assert is_float(elem(result, 1))

      result2 = Tag.from_json(["float", 2.5])
      assert result2 == {:float, 2.5}
    end

    test "array -> {:array, items} (recursive)" do
      assert Tag.from_json(["array", [["string", "a"], ["integer", 1]]]) ==
               {:array, [{:string, "a"}, {:integer, 1}]}
    end

    test "null -> :null (single-element clause)" do
      # The null tagged value is a SINGLE-element array ["null"] (no value slot).
      # A dedicated clause head handles it before the 2-element [type, value] match.
      assert Tag.from_json(["null"]) == :null
    end
  end

  describe "the float coercion is load-bearing for RequestDigest" do
    # RequestDigest.typed/1 requires is_float/1 on the {:float, _} arm. Without
    # the coercion, a ["float", 1] tag (JCS-encoded integer) would produce
    # {:float, 1} (an integer), which RequestDigest rejects.
    test "the translated float satisfies RequestDigest.typed" do
      alias BoundedAuthorityProtocol.V1.{Bounds, RequestDigest}

      tagged = Tag.from_json(["float", 1])
      assert {:ok, _} = RequestDigest.digest("op", tagged, Bounds.maximum())
    end
  end
end
