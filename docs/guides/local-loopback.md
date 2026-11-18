# Local loopback development

`sign_local_loopback_report/3` selects the explicit `ba+loopback-proof` application
profile. It uses Ed25519, a literal loopback HTTP URI and a mandatory server challenge.
It is separate from standard HTTPS DPoP: each verifier rejects the other's proof type.
Neither URI guessing nor a request header selects the profile. Set it at host startup.

Bind only a literal loopback address and derive the canonical target from the actual
listener. Refuse startup on a routable address. The listener generates a fresh challenge,
verifies it against the proof, applies identity, policy and revocation checks, and atomically
consumes it on admission. Duplicate or unknown challenges refuse execution. Reserve the
invocation as well so a fresh challenge cannot repeat an effect.

Single-use means at most one consumption. It does not establish that the first arrival is
the legitimate sender: an interceptor can win and deny that sender. HTTP supplies neither
confidentiality nor server authentication. Use authenticated confidential transport and
appropriate local process isolation when interception is in the threat model. This profile
is a development convenience, not a production transport guarantee.

Run the [loopback notebook](../notebooks/local-loopback.livemd) or the
[tested HTTP example](https://github.com/baselabs/bounded_authority_report_adapter/tree/master/examples/edge_agent).
The example's in-memory state is lost at restart and is not a production admission store.
