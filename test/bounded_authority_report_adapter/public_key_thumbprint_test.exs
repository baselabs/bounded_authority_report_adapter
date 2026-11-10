defmodule BoundedAuthorityReportAdapter.PublicKeyThumbprintTest do
  @moduledoc """
  `BoundedAuthorityReportAdapter.public_key_thumbprint/1` against an independent RFC 7638
  oracle: the SHA-256 of the required members in lexicographic order, written out here by
  hand rather than through the protocol package's JWK functions the implementation calls.
  """

  use ExUnit.Case, async: true

  alias BoundedAuthorityReportAdapter.TestKeys

  test "an Ed25519 key's thumbprint is the SHA-256 of its OKP members" do
    for seed <- 1..25 do
      {public_key, _private_key} = :crypto.generate_key(:eddsa, :ed25519, <<seed::256>>)
      x = Base.url_encode64(public_key, padding: false)
      expected = :crypto.hash(:sha256, ~s({"crv":"Ed25519","kty":"OKP","x":"#{x}"}))

      assert BoundedAuthorityReportAdapter.public_key_thumbprint(public_key) == {:ok, expected}
      assert TestKeys.holder_thumbprint_raw(public_key) == expected
    end
  end

  test "a P-256 key's thumbprint is the SHA-256 of its EC members" do
    for seed <- 1..25 do
      {<<4, x::binary-32, y::binary-32>> = public_key, _private_key} =
        TestKeys.ec_keypair(<<seed::256>>)

      members =
        ~s({"crv":"P-256","kty":"EC","x":"#{Base.url_encode64(x, padding: false)}",) <>
          ~s("y":"#{Base.url_encode64(y, padding: false)}"})

      expected = :crypto.hash(:sha256, members)

      assert BoundedAuthorityReportAdapter.public_key_thumbprint(public_key) == {:ok, expected}
      assert TestKeys.ec_thumbprint_raw(public_key) == expected
    end
  end

  test "anything else is refused with {:error, :invalid}" do
    {<<4, x::binary-32, y::binary-32>>, _private_key} = TestKeys.ec_holder_keypair()
    <<last_y_byte>> = binary_part(y, 31, 1)
    off_curve = <<4, x::binary, binary_part(y, 0, 31)::binary, Bitwise.bxor(last_y_byte, 1)>>

    for value <- [
          # A small-order Ed25519 point the protocol's strict rule refuses.
          <<0::256>>,
          <<1, 0::248>>,
          off_curve,
          <<4, 0::512>>,
          # A compressed or truncated P-256 encoding.
          <<2, x::binary>>,
          <<1, 2, 3>>,
          "",
          nil,
          :holder,
          {:ok, <<0::256>>}
        ] do
      assert BoundedAuthorityReportAdapter.public_key_thumbprint(value) == {:error, :invalid},
             "#{inspect(value)} must be refused"
    end
  end
end
