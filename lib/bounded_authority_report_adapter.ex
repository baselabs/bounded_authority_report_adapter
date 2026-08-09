defmodule BoundedAuthorityReportAdapter do
  @moduledoc """
  holder-side signing adapter for application reports (ROADMAP B2 / RA1).

  Binds an **issuer-signed grant** to a application report by producing a **holder
  proof**, returning the grant + proof envelope the verifier verifies via
  `BoundedAuthorityProtocol.V1.check_envelope/2`.

  ## The authority model (charter §4 — load-bearing)

  This adapter is the **HOLDER**. It signs ONLY the proof.

    * The **grant** is issued + signed by the **issuer** (the
      `bounded_authority` runtime service), out of band. The adapter receives
      the issuer-signed grant compact as an INPUT — it never signs the grant.
      At verify, `check_envelope` checks the grant signature against the
      issuer's public key (`trusted_issuer.public_key`).
    * The **proof** is signed by the **holder** (this adapter), binding the
      grant to a specific request. At verify, `check_envelope` checks the proof
      signature against the holder's public key (embedded in the proof header).

  Signing the grant with the holder key would produce an envelope no
  correctly-configured verifier accepts — the adapter's one signing artifact is
  the proof.

  ## What this adapter does NOT do (charter §3)

    * Not a verifier — verification lives in every party via the protocol
      package (`BoundedAuthorityProtocol.V1.check_envelope/2`). The verifier verifies; this adapter signs the proof.
    * Not the runtime — grant issuance, key custody/rotation, and revocation
      are the `bounded_authority` runtime's job. This adapter holds a holder
      key handle and signs on invocation; it does not mint capabilities.
    * Not a transport — the application transport libraries stay protocol-free. This
      adapter is a composable lib the edge agent calls to envelope a report.
    * Not hex-published — private BaseLabs library (`docs/strategy.md`).

  ## The key-handle contract (charter §6 invariant 1)

  The holder key NEVER enters this adapter. Callers supply a `{module(), term()}`
  handle whose module implements the `sign/2`, `public_key/1`, and `thumbprint/1`
  callbacks below. The adapter calls the handle's callbacks; the private key
  bytes live in the caller's module/process. A test-only reference
  implementation (`BoundedAuthorityReportAdapter.Keys.RawKey`) ships under
  `test/support/` for local development; production holders implement the
  callbacks with proper key custody (HSM, etc.).
  """

  alias BoundedAuthorityProtocol.V1.Json

  @type key_handle :: {module(), term()}

  @type report :: %{
          grant_compact: binary(),
          operation: binary(),
          method: binary(),
          target_uri: binary(),
          invocation_id: binary(),
          cast_arguments: Json.value(),
          nonce: nil | binary()
        }

  @type envelope :: %{grant: binary(), proof: binary()}

  @type opts :: %{
          optional(:bounds) => BoundedAuthorityProtocol.V1.Bounds.t() | map(),
          optional(:issued_at) => integer(),
          optional(:proof_id) => binary()
        }

  @type sign_error ::
          :invalid_report
          | :invalid_key_handle
          | :signing_failed
          | {:producer_error, :invalid}

  @doc """
  Signs the holder proof for `message` using the holder key behind `handle`.

  The holder's callback performs the actual `:crypto.sign`; the adapter never
  references the private key. Returns the raw 64-byte Ed25519 signature.
  """
  @callback sign(message :: binary(), handle :: term()) ::
              {:ok, binary()} | {:error, term()}

  @doc """
  Returns the 32-byte raw Ed25519 public key for the holder key behind `handle`.
  """
  @callback public_key(handle :: term()) :: {:ok, binary()} | {:error, term()}

  @doc """
  Returns the RFC 7638 thumbprint (raw 32-byte SHA-256 digest) of the holder
  public key behind `handle`. Exposed for caller-side self-checking (e.g.
  asserting the handle matches a grant's `cnf.jkt`); the adapter does NOT
  enforce thumbprint equality — that is the verifier's job (charter §3).
  """
  @callback thumbprint(handle :: term()) :: {:ok, binary()} | {:error, term()}
end
