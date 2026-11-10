defmodule BoundedAuthorityReportAdapter.SelectorFloatRefusalTest do
  @moduledoc """
  Grants with non-`:all` selectors on both suite surfaces, and the protocol's erratum 6
  refusal that `sign_grant/3` inherits.

  RFC 8785 writes a float-tagged whole number such as `{:float, 2.0}` as `2`, which decodes
  integer-tagged, so the value a verifier reads differs in tag from the value the issuer
  meant. From protocol 1.0.0 the protocol's grant producer refuses any selector value that
  holds one, at any depth and including range bounds, and `sign_grant/3` returns
  `{:error, {:producer_error, :invalid}}` before `sign/2` is called. Protocol 0.9.1 and
  earlier sign these values.

  `@protocol_refuses_integral_float_selectors` states which of the two the locked protocol
  does. The test asserts it either way, so it fails, instead of skipping, if the locked
  protocol disagrees.
  """

  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.V1
  alias BoundedAuthorityProtocol.V3
  alias BoundedAuthorityReportAdapter.TestKeys

  # RELEASE COMMIT (protocol 1.0): set to true in the commit that moves the requirement to
  # `~> 1.0`. The locked 0.9.1 producer signs these values.
  @protocol_refuses_integral_float_selectors true

  @now 1_750_000_000

  # Selector values holding a float-tagged whole number, valid on both surfaces.
  @integral_float_selectors [
    {:equals, ["quantity"], {:float, 2.0}},
    {:equals, ["quantity"], {:float, 0.0}},
    {:equals, ["quantity"], {:float, -0.0}},
    {:one_of, ["unit"], [{:string, "box"}, {:float, 1.0}]},
    {:equals, ["dimensions"], {:array, [{:integer, 2}, {:float, 3.0}]}},
    {:equals, ["shelf"], {:object, [{"depth", {:float, 4.0}}]}}
  ]

  # Contract-major 3 adds range selectors; their bounds are selector values too.
  @integral_float_ranges [
    {:lte, ["quantity"], {:float, 10.0}},
    {:gte, ["quantity"], {:float, 0.0}}
  ]

  # Never refused: integers, non-integral floats, strings.
  @accepted_selectors [
    {:equals, ["quantity"], {:integer, 2}},
    {:equals, ["ratio"], {:float, 2.5}},
    {:one_of, ["unit"], [{:string, "box"}, {:string, "crate"}]}
  ]

  @accepted_ranges [
    {:lte, ["quantity"], {:integer, 10}},
    {:gte, ["ratio"], {:float, 0.5}}
  ]

  defmodule Issuer do
    @moduledoc false
    # An issuer handle for either suite that reports each sign/2 call to the calling process.
    @behaviour BoundedAuthorityReportAdapter

    @impl true
    def sign(message, {:ed25519, _public_key, private_key}) do
      send(self(), :signed)
      {:ok, :crypto.sign(:eddsa, :none, message, [private_key, :ed25519])}
    end

    def sign(message, {:p256, _public_key, private_key}) do
      send(self(), :signed)
      {:ok, TestKeys.ec_sign_raw_low_s(message, private_key)}
    end

    @impl true
    def public_key({_suite, public_key, _private_key}), do: {:ok, public_key}

    @impl true
    def thumbprint({_suite, public_key, _private_key}),
      do: BoundedAuthorityReportAdapter.public_key_thumbprint(public_key)

    @impl true
    def signing_identity({_suite, public_key, _private_key}),
      do: {:ok, {:issuer, "issuer-key-1", public_key}}
  end

  describe "contract-major 1 (BoundedAuthorityReportAdapter.sign_grant/3)" do
    setup do
      {public_key, private_key} = TestKeys.issuer_keypair()
      {holder_public_key, _private_key} = TestKeys.holder_keypair()

      %{
        issuer: {Issuer, {:ed25519, public_key, private_key}},
        issuer_public_key: public_key,
        holder_thumbprint: TestKeys.holder_thumbprint_raw(holder_public_key)
      }
    end

    test "equals and one_of selectors sign, and the grant verifies", context do
      for selector <- @accepted_selectors do
        assert {:ok, %{grant: grant}} =
                 BoundedAuthorityReportAdapter.sign_grant(
                   grant_input(context, V1.Operation, selector),
                   context.issuer
                 )

        assert {:ok, %V1.GrantFacts{}} =
                 V1.verify_grant(grant, trusted(context), expected_grant())
      end
    end

    test "a float-tagged whole number in a selector value follows the locked protocol",
         context do
      for selector <- @integral_float_selectors do
        result =
          BoundedAuthorityReportAdapter.sign_grant(
            grant_input(context, V1.Operation, selector),
            context.issuer
          )

        assert_inherited(result, selector)
      end
    end
  end

  describe "contract-major 3 (BoundedAuthorityReportAdapter.V3.sign_grant/3)" do
    setup do
      {public_key, private_key} = TestKeys.ec_issuer_keypair()
      {holder_public_key, _private_key} = TestKeys.ec_holder_keypair()

      %{
        issuer: {Issuer, {:p256, public_key, private_key}},
        issuer_public_key: public_key,
        holder_thumbprint: TestKeys.ec_thumbprint_raw(holder_public_key)
      }
    end

    test "equals, one_of and range selectors sign, and the grant verifies", context do
      for selector <- @accepted_selectors ++ @accepted_ranges do
        assert {:ok, %{grant: grant}} =
                 BoundedAuthorityReportAdapter.V3.sign_grant(
                   grant_input(context, V3.Operation, selector),
                   context.issuer
                 )

        assert {:ok, %V3.GrantFacts{}} =
                 V3.verify_grant(grant, trusted(context), expected_grant())
      end
    end

    test "a float-tagged whole number in a selector value or range bound follows the locked protocol",
         context do
      for selector <- @integral_float_selectors ++ @integral_float_ranges do
        result =
          BoundedAuthorityReportAdapter.V3.sign_grant(
            grant_input(context, V3.Operation, selector),
            context.issuer
          )

        assert_inherited(result, selector)
      end
    end
  end

  defp assert_inherited(result, selector) do
    if @protocol_refuses_integral_float_selectors do
      assert result == {:error, {:producer_error, :invalid}},
             "#{inspect(selector)} must be refused by the protocol's producer"

      refute_received :signed, "#{inspect(selector)} reached sign/2 before the refusal"
    else
      assert {:ok, %{grant: _grant}} = result,
             "the locked protocol refused #{inspect(selector)}: it carries erratum 6, so " <>
               "set @protocol_refuses_integral_float_selectors to true"

      assert_received :signed
    end
  end

  defp grant_input(context, operation, selector) do
    %{
      issuer: "https://issuer.example",
      grant_id: "urn:example:grant:inventory-1",
      audiences: ["https://warehouse.example"],
      issued_at: @now,
      not_before: @now,
      expires_at: @now + 3600,
      holder_thumbprint: context.holder_thumbprint,
      operations: [struct!(operation, name: "reserve_stock", selectors: [selector])]
    }
  end

  defp trusted(context),
    do: %V1.TrustedIssuer{key_id: "issuer-key-1", public_key: context.issuer_public_key}

  defp expected_grant do
    %V1.ExpectedGrant{
      issuer: "https://issuer.example",
      audience: "https://warehouse.example",
      evaluation_time: @now,
      clock_skew: 60,
      bounds: V1.Bounds.maximum()
    }
  end
end
