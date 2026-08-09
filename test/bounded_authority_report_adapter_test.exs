defmodule BoundedAuthorityReportAdapterTest do
  use ExUnit.Case

  # The scaffold's one load-bearing assertion: the protocol package is reachable
  # from this adapter's dependency closure. The edge-path constraint (ROADMAP B2
  # acceptance: "the adapter depends only on the public protocol package on the
  # edge path") rests on this compile-time fact. The signing-API tests land with
  # the first build slice (B2-RA-01).
  describe "scaffold dependency wiring" do
    test "the public protocol package V1 module is loaded" do
      assert Code.ensure_loaded?(BoundedAuthorityProtocol.V1)
    end

    test "the envelope-verify entry point exists (the contract this adapter wraps)" do
      # BAP's V1 delegates check_envelope/2 to V1.Runtime (a `defdelegate ... to:
      # Runtime`). `function_exported?/3` on a defdelegate returns false until the
      # delegate-target module is loaded — so force-load V1.Runtime first, which
      # makes the export deterministic instead of order-dependent (a plain
      # `function_exported?(V1, :check_envelope, 2)` is flaky across ExUnit's
      # async seed orderings).
      assert {:module, _} = Code.ensure_loaded(BoundedAuthorityProtocol.V1.Runtime)
      assert function_exported?(BoundedAuthorityProtocol.V1, :check_envelope, 2)
    end
  end
end
