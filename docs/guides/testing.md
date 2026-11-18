# Testing your integration

Test the actual handle against real custody. A local cryptographic process is useful for
learning the behavior contract; it cannot validate an external provider's permissions,
latency, rotation, deadlines or availability. Do not replace the provider with a fake.

Cover the intended suite and profile, immutable identity/sign agreement, raw signature
format, malformed inputs, wrong key, wrong holder, changed request, expired windows,
unknown issuer and profile mismatch. A self-round-trip is a regression check, not
independent interoperability evidence; use the protocol's independent conformance corpus
and compare exact bytes where that contract requires them.

Test the host boundary as well: authenticate and bind identity, deny policy, revoke live,
race the same nonce and invocation, restart the store, simulate neither success nor a
commit when the real store returns uncertainty, and reconcile effects before retries.
A fresh proof for an existing invocation must not execute again.

This repository recursively executes authored Elixir samples, runs real HTTP example
tests and both notebook modes, and checks source and rendered links. Run:

```sh
elixir scripts/check_livebooks.exs --local
elixir scripts/check_livebooks.exs --published
MIX_ENV=test mix ci
```

Local mode substitutes this checkout only in the dependency AST. Published mode leaves
notebooks unchanged and asserts the exact Hex version and source origin. Both compare
semantic outputs, reject an incomplete registry, and remove their temporary install cache.
