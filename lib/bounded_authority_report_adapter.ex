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
  Binds an issuer-signed grant to a application report by producing a holder proof.

  Returns `{:ok, %{grant: grant_compact, proof: proof_compact}}` — the grant is
  the pass-through of `report.grant_compact` (issuer-signed, untouched); the
  proof is the holder's binding of that grant to the report, signed via the
  holder key behind `key_handle`.

  ## The flow (design §2 Q5)

    1. Resolve the holder public key from `key_handle` (callback).
    2. Build the `Proof` struct: holder key + the report's request fields +
       `grant_compact` (BAP's `proof_signing_input` derives `ath` = grant hash
       from it, and `ba_req` = request digest from `cast_arguments`).
    3. Produce the deterministic proof signing input via BAP.
    4. Sign the input's `message` via the holder key callback (the one signing
       call — the adapter signs ONLY the proof; the grant is never signed here).
    5. Assemble the compact proof via BAP.
    6. Return `%{grant: report.grant_compact, proof: proof_compact}`.

  ## Options

    * `:bounds` — resource ceilings forwarded to BAP's producer (default `%{}`,
      BAP's maxima). NOTE: `assemble_compact/2` is forced to `%{}` — the public
      `V1.assemble_compact/2` hard-codes it; tightening assemble bounds is a
      named BAP surface gap (design C7), not something this adapter can do.
    * `:issued_at` — the proof's `iat` (default: `System.system_time(:second)`).
      Pin this when the verifier's `evaluation_time` is far from wall-clock
      (e.g. tests) so the proof's time window overlaps the grant's.
    * `:proof_id` — the proof's `jti` (default: a generated UUID v4).

  ## Errors (closed-atom set — no key material or report content in errors)

    * `:invalid_report` — a required report field is missing.
    * `:invalid_key_handle` — the handle's `public_key/1` or `sign/2` rejected.
    * `:signing_failed` — the holder's `sign/2` callback returned an error.
    * `{:producer_error, :invalid}` — BAP's producer or assembler rejected the
      proof (the input violated a bound or field constraint).
  """
  @spec sign_report(report(), key_handle(), opts()) ::
          {:ok, envelope()} | {:error, sign_error()}
  def sign_report(report, key_handle, opts \\ %{}) do
    bounds = Map.get(opts, :bounds, %{})
    issued_at = Map.get(opts, :issued_at, System.system_time(:second))
    proof_id = Map.get(opts, :proof_id) || generate_uuid()

    with {:ok, report} <- validate_report(report),
         {:ok, holder_public_key} <- resolve_public_key(key_handle),
         proof = build_proof(report, holder_public_key, proof_id, issued_at),
         {:ok, signing_input} <- produce_proof_signing_input(proof, bounds),
         {:ok, signature} <- sign_via_handle(key_handle, signing_input.message),
         {:ok, proof_compact} <- assemble_proof(signing_input, signature) do
      {:ok, %{grant: report.grant_compact, proof: proof_compact}}
    end
  end

  defp validate_report(report) when is_map(report) do
    with {:ok, grant_compact} <- required_binary(report, :grant_compact),
         {:ok, operation} <- required_binary(report, :operation),
         {:ok, method} <- required_binary(report, :method),
         {:ok, target_uri} <- required_binary(report, :target_uri),
         {:ok, invocation_id} <- required_binary(report, :invocation_id),
         cast_arguments = Map.get(report, :cast_arguments),
         :ok <- validate_cast_arguments(cast_arguments),
         nonce = Map.get(report, :nonce),
         :ok <- validate_nonce(nonce) do
      {:ok,
       %{
         grant_compact: grant_compact,
         operation: operation,
         method: method,
         target_uri: target_uri,
         invocation_id: invocation_id,
         cast_arguments: cast_arguments,
         nonce: nonce
       }}
    end
  end

  defp validate_report(_report), do: {:error, :invalid_report}

  defp required_binary(report, key) do
    case Map.fetch(report, key) do
      {:ok, value} when is_binary(value) -> {:ok, value}
      _ -> {:error, :invalid_report}
    end
  end

  defp validate_cast_arguments(nil), do: {:error, :invalid_report}

  defp validate_cast_arguments(_value), do: :ok

  defp validate_nonce(nil), do: :ok

  defp validate_nonce(nonce) when is_binary(nonce), do: :ok

  defp validate_nonce(_nonce), do: {:error, :invalid_report}

  defp resolve_public_key({module, handle}) do
    case module.public_key(handle) do
      {:ok, public_key} when is_binary(public_key) -> {:ok, public_key}
      _ -> {:error, :invalid_key_handle}
    end
  end

  defp build_proof(report, holder_public_key, proof_id, issued_at) do
    %BoundedAuthorityProtocol.V1.Proof{
      holder_public_key: holder_public_key,
      proof_id: proof_id,
      method: report.method,
      target_uri: report.target_uri,
      issued_at: issued_at,
      nonce: report.nonce,
      invocation_id: report.invocation_id,
      operation: report.operation,
      grant_compact: report.grant_compact,
      cast_arguments: report.cast_arguments
    }
  end

  defp produce_proof_signing_input(proof, bounds) do
    case BoundedAuthorityProtocol.V1.proof_signing_input(proof, bounds) do
      {:ok, signing_input} -> {:ok, signing_input}
      {:error, :invalid} -> {:error, {:producer_error, :invalid}}
    end
  end

  defp sign_via_handle({module, handle}, message) do
    case module.sign(message, handle) do
      {:ok, signature} when is_binary(signature) -> {:ok, signature}
      {:ok, _invalid_signature} -> {:error, :signing_failed}
      {:error, _reason} -> {:error, :signing_failed}
    end
  end

  defp assemble_proof(signing_input, signature) do
    case BoundedAuthorityProtocol.V1.assemble_compact(signing_input, signature) do
      {:ok, compact} -> {:ok, compact}
      {:error, :invalid} -> {:error, {:producer_error, :invalid}}
    end
  end

  defp generate_uuid do
    # UUID v4 per RFC 4122: 16 random bytes, then overwrite byte 6's high nibble
    # with the version (0100 = 4) and byte 8's high two bits with the variant
    # (10). BAP's proof decoder (`valid_uuid?`) enforces the 8-4-1-3-1-3-12
    # lowercase-hex shape with version char in 1-5 and variant char in 8/9/a/b.
    import Bitwise

    <<b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15>> =
      :crypto.strong_rand_bytes(16)

    versioned_byte = (b6 &&& 0x0F) ||| 0x40
    varianted_byte = (b8 &&& 0x3F) ||| 0x80

    <<b0, b1, b2, b3, b4, b5, versioned_byte, b7, varianted_byte, b9, b10, b11, b12, b13, b14,
      b15>>
    |> Base.encode16(case: :lower)
    |> format_uuid_hex()
  end

  defp format_uuid_hex(
         <<a::binary-size(8), b::binary-size(4), c::binary-size(4), d::binary-size(4),
           e::binary-size(12)>>
       ) do
    "#{a}-#{b}-#{c}-#{d}-#{e}"
  end

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
