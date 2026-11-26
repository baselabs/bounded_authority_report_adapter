# Examples

The [journey notebooks](../docs/notebooks/holder-request.livemd) install the exact published
package, generate real demonstration keys and execute all signing surfaces with verification
and refusal assertions. Each notebook is independent; see the [documentation index](../README.md#documentation).
Run them against this checkout with `elixir scripts/check_livebooks.exs --local` from the
repository root. `--published` runs them unchanged against the released package; the
publication workflow runs it after each upload.

The [edge_agent application](edge_agent/README.md) signs, sends and verifies requests over
real HTTP using Bandit, Plug and Req. Its test suite runs the transport demonstration and
the guide's host admission handoff with real policy and local replay storage. Production
hosts supply their own durable admission, live revocation and execution recovery.

The [action approval example](../docs/guides/framework-integration.md#12-sign-and-verify-an-action-approval)
signs an exact prepared request and verifies it against independent host inputs. The
documentation sample gate runs the example and checks that changing the resource set is refused.
