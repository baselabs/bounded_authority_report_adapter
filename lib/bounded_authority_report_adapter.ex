defmodule BoundedAuthorityReportAdapter do
  @moduledoc """
  holder-side signing adapter for application reports (ROADMAP B2).

  Wraps the public `bounded_authority_protocol` package's grant/proof envelopes
  with **local private-key signing**. The protocol package produces the
  deterministic signing inputs and verifies envelopes; THIS adapter is the
  holder-side glue that calls those producers, signs with the reporter's private
  Ed25519 key (held locally — never in the verifier), and assembles the
  compact envelope.

  ## What this adapter is NOT

    * Not a verifier — verification is embedded in every party via the protocol
      package (`BoundedAuthorityProtocol.V1.check_envelope/2`,
      `verify_grant/3`). The verifier (verifier application) verifies; this adapter
      signs.
    * Not the runtime — issuance, key custody/rotation, and live revocation are
      the `bounded_authority` runtime service's job. This adapter holds a holder
      key and signs on invocation.
    * Not a transport — the application transport libraries (`replicant`, `capstan`)
      stay protocol-free. This adapter is a separate composable lib the edge
      agent calls to envelope a report.

  ## Status (2026-08-09 scaffold)

  Scaffolded; the signing API is not yet implemented. See `docs/ROADMAP.md` for
  the build arc and `docs/charter.md` for the authority model.
  """

  # The one fact the scaffold proves: the protocol package is reachable from
  # this adapter's dependency closure. The signing functions land in the first
  # build slice (B2-RA-01).
end
