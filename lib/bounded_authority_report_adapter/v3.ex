defmodule BoundedAuthorityReportAdapter.V3 do
  @moduledoc """
  The contract-major-3 signing surface — the `BAP3-ES256-SHA256` suite
  (ADR-0021; BAP 0.5.1 / BAP ADR 0035).

  This module is the ES256 sibling of the major-1 surface in
  `BoundedAuthorityReportAdapter`: the same four standard instantiations,
  the same `{module(), term()}` key-handle contract, the same closed-atom
  error sets, the same shared-signing-tail discipline (resolve → sign via the
  handle → verify against the resolved key → assemble via the protocol
  package). The differences are exactly the suite's:

    * **Keys are EC P-256.** A handle serving these entry points returns the
      65-byte uncompressed-SEC1 public key (`0x04 || x || y`) from
      `public_key/1` and the atomic snapshots. The wire shape is the
      discriminator: every resolver here accepts exactly that shape —
      width, `0x04` prefix, and on-curve membership validated through the
      protocol package's certified arithmetic — and rejects an Ed25519
      key (and every other spelling) as `:invalid_key_handle` before `sign/2`
      is reached. The major-1 entry points reject the 65-byte shape
      symmetrically.
    * **`sign/2` returns the RFC 7518 §3.4 raw form** — exactly 64 bytes,
      `r || s`, two fixed-width unsigned big-endian integers. DER (OTP
      `:crypto.sign/5`'s native ECDSA output) is never a v3 wire spelling: a
      DER return is `{:error, :signing_failed}`, never converted here.
    * **Low-S is normalized HERE (the producer's duty).** After `sign/2`
      returns, this library range-checks the raw scalars (`0 < r < n`,
      `0 < s < n` — BEFORE any arithmetic on `s`), applies the one
      conditional subtraction (`s ← n − s` when `s > n/2`), and verifies the
      normalized bytes against the resolved key. A handle that returns a
      high-S spelling still yields a conforming compact; a wrong-key,
      out-of-range, or wrong-suite return fails closed as `:signing_failed`.
      Custody audit note: the compact's signature segment may differ from
      the bytes the signing device emitted and logged (the `s` half);
      reconcile on `(r, message)`.
    * **No local-loopback entry point.** The local-loopback
      application-proof profile is bound to contract-major 1; the protocol's
      v3 façade exposes no loopback functions.

  There is no v3 signing of major-1 or major-2 objects and no major-1
  signing through this module: a v3 proof pairs with a v3 grant
  (`REQ3-EVO-proof-major-equals-grant`), so `sign_report/3` here fails fast
  with `:invalid_report` when `grant_compact` is not a v3 grant — the same
  gate the major-1 surface applies in its own direction.

  The key-handle behavior (the `@callback` set, including the atomic
  `key_identity/1` / `signing_identity/1` snapshots and the C1 issuer-role
  gate on `sign_grant/3`) is defined on `BoundedAuthorityReportAdapter` and
  is shared by both surfaces; see that module's callback docs for the
  suite-parameterized contract.
  """

  alias BoundedAuthorityProtocol.V1
  alias BoundedAuthorityProtocol.V1.Json
  alias BoundedAuthorityProtocol.V3
  alias BoundedAuthorityReportAdapter.Telemetry

  import Bitwise

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

  @type anchor_input :: %{
          anchor_id: binary(),
          chain_id: binary(),
          sequence: non_neg_integer(),
          chain_hash: binary()
        }

  @type anchor_compact :: %{anchor: binary()}

  @type opts :: %{
          optional(:bounds) => V1.Bounds.t() | map(),
          optional(:issued_at) => integer(),
          optional(:proof_id) => binary()
        }

  @type anchor_opts :: %{
          optional(:bounds) => V1.Bounds.t() | map(),
          optional(:anchored_at) => integer()
        }

  @type sign_error ::
          :invalid_report
          | :invalid_key_handle
          | :signing_failed
          | {:producer_error, :invalid}

  @type anchor_sign_error ::
          :invalid_anchor
          | :invalid_key_handle
          | :signing_failed
          | {:producer_error, :invalid}

  @type grant_input :: %{
          issuer: binary(),
          grant_id: binary(),
          audiences: [binary()],
          issued_at: integer(),
          not_before: integer(),
          expires_at: integer(),
          holder_thumbprint: binary(),
          operations: [V3.Operation.t()]
        }

  @type grant_opts :: %{
          optional(:bounds) => V1.Bounds.t() | map()
        }

  @type grant_compact :: %{grant: binary()}

  @type grant_sign_error ::
          :invalid_grant
          | :invalid_key_handle
          | :signing_failed
          | {:producer_error, :invalid}

  @type transition_input :: %{
          transition_id: binary(),
          chain_id: binary(),
          effective_at: integer(),
          next_key_id: binary(),
          next_public_key: binary()
        }

  @type transition_opts :: %{
          optional(:bounds) => V1.Bounds.t() | map()
        }

  @type transition_compact :: %{key_transition: binary()}

  @type transition_sign_error ::
          :invalid_transition
          | :invalid_key_handle
          | :signing_failed
          | {:producer_error, :invalid}

  # NIST P-256 (secp256r1) group order and the integer-floor half — the
  # low-S normalization boundary (ADR-0021 Decision 4: `n` is odd, so
  # `s = ⌊n/2⌋` stays untouched and `s = ⌊n/2⌋ + 1` maps to exactly `⌊n/2⌋`).
  @ec_n 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
  @ec_half_n div(@ec_n, 2)
  @scalar_bytes 32

  @doc """
  Binds an issuer-signed v3 grant to an application report by producing the
  holder proof under the `BAP3-ES256-SHA256` suite. Returns
  `{:ok, %{grant: grant_compact, proof: proof_compact}}` — the grant passes
  through untouched; the proof is the holder's EC-key binding, verified
  green downstream via `BoundedAuthorityProtocol.V3.check_envelope/2`.

  The `key_handle` must be a P-256 handle: `public_key/1` returns the
  65-byte uncompressed-SEC1 point, and `sign/2` returns the raw `r || s`
  form (64 bytes; DER is rejected as `:signing_failed`). Low-S
  normalization is this library's duty and happens here.

  ## Options

    * `:bounds` — resource ceilings forwarded unchanged to BAP's producer
      and assembler (default `%{}`, BAP's maxima).
    * `:issued_at` — the proof's `iat` (default: `System.system_time(:second)`).
    * `:proof_id` — the proof's `jti` (default: a generated UUID v4).

  ## Errors (closed-atom set — no key material or report content in errors)

    * `:invalid_report` — a required field is missing, or `grant_compact` is
      not a v3 grant (the mixed-major fail-fast: a v1 grant here would make
      a mixed-major credential no verifier accepts).
    * `:invalid_key_handle` — the handle is malformed, or its `public_key/1`
      rejected / returned anything other than a valid 65-byte P-256 point.
    * `:signing_failed` — `sign/2` rejected, returned a non-64-byte
      signature (including DER), returned out-of-range scalars, violated the
      `{:ok, _} | {:error, _}` contract, or the signature did not verify
      against the resolved holder public key.
    * `{:producer_error, :invalid}` — BAP's producer or assembler rejected
      the proof.
  """
  @spec sign_report(report(), key_handle(), opts()) ::
          {:ok, envelope()} | {:error, sign_error()}
  def sign_report(report, key_handle, opts \\ %{}) do
    Telemetry.sign_span(:report, fn -> do_sign_report(report, key_handle, opts) end)
  end

  defp do_sign_report(report, key_handle, opts) do
    opts = normalize_opts(opts)
    bounds = Map.get(opts, :bounds, %{})
    issued_at = Map.get(opts, :issued_at, System.system_time(:second))
    proof_id = Map.get(opts, :proof_id) || generate_uuid()

    with {:ok, report} <- validate_report(report),
         {:ok, holder_public_key} <- resolve_public_key(key_handle),
         proof = build_proof(report, holder_public_key, proof_id, issued_at),
         {:ok, signing_input} <- produce_proof_signing_input(proof, bounds),
         {:ok, proof_compact} <-
           sign_and_assemble(key_handle, signing_input, holder_public_key, bounds) do
      {:ok, %{grant: report.grant_compact, proof: proof_compact}}
    end
  end

  @doc """
  Signs a v3 grant — the issuer's authority assertion under the ES256 suite.
  The C1 gate is the major-1 surface's, over P-256 material: the handle's
  atomic `signing_identity/1` must resolve `{:issuer, key_id, public_key}`
  with a valid 65-byte P-256 key; a `:holder` declaration, a missing
  callback, or any other key shape is `{:error, :invalid_key_handle}` before `sign/2`.
  The signed header's `kid` comes from the snapshot, never caller input.
  Verifiable via `BoundedAuthorityProtocol.V3.verify_grant/3`.
  """
  @spec sign_grant(grant_input(), key_handle(), grant_opts()) ::
          {:ok, grant_compact()} | {:error, grant_sign_error()}
  def sign_grant(grant_input, key_handle, opts \\ %{}) do
    Telemetry.sign_span(:grant, fn -> do_sign_grant(grant_input, key_handle, opts) end)
  end

  defp do_sign_grant(grant_input, key_handle, opts) do
    raw_opts = opts
    opts = normalize_opts(opts)
    bounds = Map.get(opts, :bounds, %{})

    # The role-attestation gate option is the v1 surface's (RA11); the bap-role-attestation/1
    # profile is Ed25519-bound at schema 1, so no P-256 subject key can be attested under it.
    # A supplied option FAILS CLOSED rather than being silently ignored (cross-vendor review
    # M3 — silent-accept is the wrong failure mode for an unsupportable security option) —
    # checked on the RAW opts so the keyword-list idiom cannot slip past the normalizer (B1).
    if option_present?(raw_opts, :role_attestation) do
      {:error, :invalid_role_attestation}
    else
      with {:ok, {key_id, public_key}} <- resolve_signing_identity(key_handle),
           {:ok, grant} <- build_grant(grant_input, key_id),
           {:ok, signing_input} <- produce_grant_signing_input(grant, bounds),
           {:ok, grant_compact} <-
             sign_and_assemble(key_handle, signing_input, public_key, bounds) do
        {:ok, %{grant: grant_compact}}
      end
    end
  end

  defp option_present?(opts, key) when is_map(opts), do: Map.has_key?(opts, key)
  defp option_present?(opts, key) when is_list(opts), do: Keyword.has_key?(opts, key)
  defp option_present?(_opts, _key), do: false

  @doc """
  Signs a v3 boundary anchor — a durable chain checkpoint under the ES256
  suite, verifiable via `BoundedAuthorityProtocol.V3.verify_historical_anchor/3`.
  Both key identifiers (`kid` + the 65-byte public key) come from the
  handle's ONE atomic `key_identity/1` snapshot (the rotation-race defense);
  caller-supplied key material is ignored.
  """
  @spec sign_anchor(anchor_input(), key_handle(), anchor_opts()) ::
          {:ok, anchor_compact()} | {:error, anchor_sign_error()}
  def sign_anchor(anchor_input, key_handle, opts \\ %{}) do
    Telemetry.sign_span(:anchor, fn -> do_sign_anchor(anchor_input, key_handle, opts) end)
  end

  defp do_sign_anchor(anchor_input, key_handle, opts) do
    opts = normalize_opts(opts)
    bounds = Map.get(opts, :bounds, %{})
    anchored_at = Map.get(opts, :anchored_at, System.system_time(:second))

    with {:ok, {key_id, public_key}} <- resolve_key_identity(key_handle),
         {:ok, anchor} <- build_anchor(anchor_input, public_key, key_id, anchored_at),
         {:ok, signing_input} <- produce_anchor_signing_input(anchor, bounds),
         {:ok, anchor_compact} <-
           sign_and_assemble(key_handle, signing_input, public_key, bounds) do
      {:ok, %{anchor: anchor_compact}}
    end
  end

  @doc """
  Signs a v3 key transition — the current retiring P-256 key's assertion of
  its successor, verifiable via `BoundedAuthorityProtocol.V3.verify_key_transition/4`.
  Role-agnostic (mirrors `sign_anchor/3`): the current key's identity comes
  from the atomic `key_identity/1` snapshot; `next_{key_id, public_key}` are
  caller-supplied, and `next_public_key` must itself be a valid 65-byte
  P-256 point (the successor of a v3 chain key is a v3 chain key).
  """
  @spec sign_key_transition(transition_input(), key_handle(), transition_opts()) ::
          {:ok, transition_compact()} | {:error, transition_sign_error()}
  def sign_key_transition(transition_input, key_handle, opts \\ %{}) do
    Telemetry.sign_span(:key_transition, fn ->
      do_sign_key_transition(transition_input, key_handle, opts)
    end)
  end

  defp do_sign_key_transition(transition_input, key_handle, opts) do
    opts = normalize_opts(opts)
    bounds = Map.get(opts, :bounds, %{})

    with {:ok, {current_key_id, current_public_key}} <- resolve_key_identity(key_handle),
         {:ok, transition} <-
           build_key_transition(transition_input, current_key_id, current_public_key),
         {:ok, signing_input} <- produce_key_transition_signing_input(transition, bounds),
         {:ok, compact} <-
           sign_and_assemble(key_handle, signing_input, current_public_key, bounds) do
      {:ok, %{key_transition: compact}}
    end
  end

  # ---------------------------------------------------------------------------
  # The v3 shared signing tail: sign via handle → raw range check → low-S
  # normalization → verify the NORMALIZED bytes against the resolved key →
  # assemble through BAP's v3 façade. There is no producer-side backstop
  # downstream: BAP 0.5.1's v3 assembler accepts any 64-byte signature blob,
  # so the range/low-S duty is wholly this library's (ADR-0021 Decision 4).
  #
  # The ECDSA verify guard is deliberately independent of BAP's
  # V3.Es256 (which stays verify-side): equivalence is carried by the
  # differential-agreement test, and the whole call is rescue/catch-contained
  # so a raising backend returns the closed error value
  # (REQ3-SIGNING-backend-reject) — including an off-curve key that slipped
  # past the resolver arithmetic on a stricter backend.
  # ---------------------------------------------------------------------------

  defp sign_and_assemble(key_handle, signing_input, public_key, bounds) do
    with {:ok, signature} <- sign_via_handle(key_handle, signing_input.message),
         {:ok, canonical} <- canonicalize_low_s(signature),
         :ok <- verify_es256(signing_input.message, canonical, public_key) do
      case V3.assemble_compact(signing_input, canonical, bounds) do
        {:ok, compact} -> {:ok, compact}
        {:error, :invalid} -> {:error, {:producer_error, :invalid}}
      end
    end
  end

  defp sign_via_handle({module, handle}, message) do
    # The 64-byte width guard admits both suites' signatures (Ed25519 and
    # raw r || s are each exactly 64 bytes) — which is WHY the per-suite
    # verify below is the real discriminator, and why a DER return (71
    # bytes, 0x30-led; a 64-byte DER is also constructible) can only be
    # closed by the scalar checks + verify, never by width alone.
    case safe_callback(module, :sign, [message, handle]) do
      {:ok, signature} when is_binary(signature) and byte_size(signature) == 64 ->
        {:ok, signature}

      _callback_contract_violation ->
        {:error, :signing_failed}
    end
  end

  # Decode → RANGE-CHECK THE RAW RETURN → conditional subtraction. The range
  # check runs BEFORE any arithmetic on `s`: on `s ≥ n` the subtraction
  # `n − s` goes negative, whose re-encoding is primitive-dependent
  # (`:binary.encode_unsigned/1` raises; a bit-syntax re-encode silently
  # wraps) — the ordering is what keeps the "never a raise" contract.
  defp canonicalize_low_s(<<r::binary-@scalar_bytes, s::binary-@scalar_bytes>>) do
    ri = :binary.decode_unsigned(r)
    si = :binary.decode_unsigned(s)

    if ri > 0 and ri < @ec_n and si > 0 and si < @ec_n do
      canonical_s = if si > @ec_half_n, do: @ec_n - si, else: si
      {:ok, r <> unsigned_big_32(canonical_s)}
    else
      {:error, :signing_failed}
    end
  end

  defp canonicalize_low_s(_signature), do: {:error, :signing_failed}

  defp verify_es256(message, <<r::binary-@scalar_bytes, s::binary-@scalar_bytes>>, public_key) do
    ri = :binary.decode_unsigned(r)
    si = :binary.decode_unsigned(s)

    backend_ok =
      ri > 0 and ri < @ec_n and si > 0 and si <= @ec_half_n and
        :crypto.verify(
          :ecdsa,
          :sha256,
          message,
          der_signature(r, s),
          [public_key, :prime256v1]
        )

    if backend_ok, do: :ok, else: {:error, :signing_failed}
  rescue
    _backend_failure -> {:error, :signing_failed}
  catch
    _kind, _reason -> {:error, :signing_failed}
  end

  defp verify_es256(_message, _signature, _public_key), do: {:error, :signing_failed}

  # Minimal DER ECDSA-Sig-Value (an internal backend spelling only): SEQUENCE
  # over minimal-octet INTEGERs, a leading 0x00 sign guard when a scalar's
  # high bit is set (≈50% of scalars — omitting it fails valid signatures
  # against their own key), short-form lengths only (each INTEGER content is
  # at most 33 bytes, so the long form is unreachable by construction).
  defp der_signature(r, s) do
    body = der_integer(r) <> der_integer(s)
    <<48, der_length(byte_size(body))::binary, body::binary>>
  end

  defp der_integer(bytes) do
    minimal = trim_leading_zeros(bytes, 0)
    first = :binary.first(minimal)

    content =
      if first >= 0x80 do
        <<0>> <> minimal
      else
        minimal
      end

    <<2, der_length(byte_size(content))::binary, content::binary>>
  end

  defp trim_leading_zeros(<<0, rest::binary>>, acc) when acc < @scalar_bytes - 1,
    do: trim_leading_zeros(rest, acc + 1)

  defp trim_leading_zeros(bytes, _acc) when bytes != <<>>,
    do: bytes

  defp der_length(len) when len < 128, do: <<len>>

  defp unsigned_big_32(int) do
    bytes = :binary.encode_unsigned(int)
    String.duplicate(<<0>>, @scalar_bytes - byte_size(bytes)) <> bytes
  end

  # ---------------------------------------------------------------------------
  # The v3 resolvers — the key-type discriminator (ADR-0021 Decision 2). The
  # accepted shape is EXACTLY the 65-byte uncompressed-SEC1 point, and the
  # point must be valid: width alone does not discriminate (a secp256k1 point
  # is also 65 bytes with an 0x04 prefix), so validation routes through the
  # protocol package's certified arithmetic (V3.EcJwk.encode_public/2:
  # prefix + coordinate range + on-curve). On the GRANT path this is the
  # key's first consumer — the v3 grant bytes carry only kid and
  # holder_thumbprint, so BAP's own producer never touches the issuer key.
  # ---------------------------------------------------------------------------

  defp resolve_public_key({module, handle}) when is_atom(module) do
    case safe_callback(module, :public_key, [handle]) do
      {:ok, public_key} -> p256_public_key(public_key)
      _malformed_or_failed -> {:error, :invalid_key_handle}
    end
  end

  defp resolve_public_key(_handle), do: {:error, :invalid_key_handle}

  defp resolve_key_identity({module, handle}) when is_atom(module) do
    case safe_callback(module, :key_identity, [handle]) do
      {:ok, {key_id, public_key}}
      when is_binary(key_id) and byte_size(key_id) > 0 ->
        case p256_public_key(public_key) do
          {:ok, public_key} -> {:ok, {key_id, public_key}}
          {:error, :invalid_key_handle} = rejected -> rejected
        end

      _malformed_or_unimplemented ->
        {:error, :invalid_key_handle}
    end
  end

  defp resolve_key_identity(_handle), do: {:error, :invalid_key_handle}

  # The grant's atomic signing identity — the C1 role gate (the :issuer
  # match) and the P-256 key validation applied to the SAME atomic snapshot.
  # The role and width literals share this clause head: a wrong-width
  # :issuer snapshot is rejected exactly like a :holder one, before sign/2.
  defp resolve_signing_identity({module, handle}) when is_atom(module) do
    case safe_callback(module, :signing_identity, [handle]) do
      {:ok, {:issuer, key_id, public_key}}
      when is_binary(key_id) and byte_size(key_id) > 0 ->
        case p256_public_key(public_key) do
          {:ok, public_key} -> {:ok, {key_id, public_key}}
          {:error, :invalid_key_handle} = rejected -> rejected
        end

      _holder_role_or_malformed_or_unimplemented ->
        {:error, :invalid_key_handle}
    end
  end

  defp resolve_signing_identity(_handle), do: {:error, :invalid_key_handle}

  # The one certified point-validation call: V3.EcJwk.encode_public/2 checks
  # the width, the 0x04 prefix, the coordinate range, and on-curve membership
  # by pure arithmetic. A compile-time dependency on a module outside the
  # versioned façade — recorded in ADR-0021 Decision 2; if the protocol
  # package moves it, this library stops compiling rather than silently
  # accepting bad keys.
  defp p256_public_key(public_key) when is_binary(public_key) and byte_size(public_key) == 65 do
    case V3.EcJwk.encode_public(public_key, %{}) do
      {:ok, _certified_jwk} -> {:ok, public_key}
      {:error, :invalid} -> {:error, :invalid_key_handle}
    end
  end

  defp p256_public_key(_wrong_shape), do: {:error, :invalid_key_handle}

  defp safe_callback(module, function, args) do
    apply(module, function, args)
  rescue
    _error -> {:error, :callback_failed}
  catch
    # A production key-handle callback (HSM / key server) that times out
    # does so via exit/1 — contain it to the closed callback-failure shape.
    :exit, _reason -> {:error, :callback_failed}
    :throw, _reason -> {:error, :callback_failed}
  end

  # ---------------------------------------------------------------------------
  # Input validation + struct building (the major-1 surface's shapes, with
  # the v3 divergences: the mixed-major fail-fast gate, %V3.Proof{}/%V3.Grant{},
  # and the 65-byte successor pre-check).
  # ---------------------------------------------------------------------------

  defp validate_report(report) when is_map(report) do
    with {:ok, grant_compact} <- required_binary(report, :grant_compact),
         :ok <- matching_grant_major(grant_compact),
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

  # The mixed-major fail-fast (ADR-0021 Decision 8): a v3 proof pairs with a
  # v3 grant, and BAP's proof producer only HASHES grant_compact — without
  # this gate a v1 (or v2) grant would sail through into a credential no
  # verifier accepts. The gate is the major's own bounded DECODER, not the
  # header walk: v1 and v2 grants share the EdDSA header, so the major is
  # only distinguishable in the payload's `v` claim, which each major's
  # closed decode rejects on mismatch (cross-vendor code review, B2).
  defp matching_grant_major(grant_compact) do
    case V3.decode_grant(grant_compact, %{}) do
      {:ok, _decoded_grant} -> :ok
      {:error, :invalid} -> {:error, :invalid_report}
    end
  end

  defp required_binary(input, key) do
    case Map.fetch(input, key) do
      {:ok, value} when is_binary(value) -> {:ok, value}
      _ -> {:error, :invalid_report}
    end
  end

  defp validate_cast_arguments(nil), do: {:error, :invalid_report}
  defp validate_cast_arguments(_value), do: :ok

  defp validate_nonce(nil), do: :ok
  defp validate_nonce(nonce) when is_binary(nonce), do: :ok
  defp validate_nonce(_nonce), do: {:error, :invalid_report}

  defp build_proof(report, holder_public_key, proof_id, issued_at) do
    %V3.Proof{
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
    case V3.proof_signing_input(proof, bounds) do
      {:ok, signing_input} -> {:ok, signing_input}
      {:error, :invalid} -> {:error, {:producer_error, :invalid}}
    end
  end

  defp build_grant(grant_input, key_id) when is_map(grant_input) do
    with {:ok, issuer} <- required_grant_binary(grant_input, :issuer),
         {:ok, grant_id} <- required_grant_binary(grant_input, :grant_id),
         {:ok, audiences} <- required_grant_audiences(grant_input),
         {:ok, issued_at} <- required_grant_integer(grant_input, :issued_at),
         {:ok, not_before} <- required_grant_integer(grant_input, :not_before),
         {:ok, expires_at} <- required_grant_integer(grant_input, :expires_at),
         {:ok, holder_thumbprint} <- required_grant_binary(grant_input, :holder_thumbprint),
         {:ok, operations} <- required_grant_operations(grant_input) do
      {:ok,
       %V3.Grant{
         key_id: key_id,
         issuer: issuer,
         grant_id: grant_id,
         audiences: audiences,
         issued_at: issued_at,
         not_before: not_before,
         expires_at: expires_at,
         holder_thumbprint: holder_thumbprint,
         operations: operations
       }}
    end
  end

  defp build_grant(_grant_input, _key_id), do: {:error, :invalid_grant}

  defp required_grant_binary(grant_input, key) do
    case Map.fetch(grant_input, key) do
      {:ok, value} when is_binary(value) -> {:ok, value}
      _ -> {:error, :invalid_grant}
    end
  end

  defp required_grant_integer(grant_input, key) do
    case Map.fetch(grant_input, key) do
      {:ok, value} when is_integer(value) -> {:ok, value}
      _ -> {:error, :invalid_grant}
    end
  end

  defp required_grant_audiences(grant_input) do
    # An IMPROPER list (["a" | :tail]) passes is_list/1 but raises inside
    # Enum.all?/2 — the closed-error contract requires rejecting it as data
    # (cross-vendor code review, B2; the same defect existed on the v1 path).
    case Map.fetch(grant_input, :audiences) do
      {:ok, audiences} when is_list(audiences) and audiences != [] ->
        if proper_list?(audiences) and Enum.all?(audiences, &is_binary/1),
          do: {:ok, audiences},
          else: {:error, :invalid_grant}

      _ ->
        {:error, :invalid_grant}
    end
  end

  defp proper_list?([]), do: true

  defp proper_list?([_head | rest]), do: proper_list?(rest)

  defp proper_list?(_improper), do: false

  defp required_grant_operations(grant_input) do
    case Map.fetch(grant_input, :operations) do
      {:ok, operations} when is_list(operations) and operations != [] -> {:ok, operations}
      _ -> {:error, :invalid_grant}
    end
  end

  defp produce_grant_signing_input(grant, bounds) do
    case V3.grant_signing_input(grant, bounds) do
      {:ok, signing_input} -> {:ok, signing_input}
      {:error, :invalid} -> {:error, {:producer_error, :invalid}}
    end
  end

  defp build_anchor(anchor_input, public_key, key_id, anchored_at) when is_map(anchor_input) do
    with {:ok, anchor_id} <- required_anchor_binary(anchor_input, :anchor_id),
         {:ok, chain_id} <- required_anchor_binary(anchor_input, :chain_id),
         {:ok, sequence} <- required_sequence(anchor_input, :sequence),
         {:ok, chain_hash} <- required_anchor_binary(anchor_input, :chain_hash) do
      {:ok,
       %V1.BoundaryAnchor{
         anchor_id: anchor_id,
         anchored_at: anchored_at,
         chain_id: chain_id,
         sequence: sequence,
         chain_hash: chain_hash,
         key_id: key_id,
         public_key: public_key
       }}
    end
  end

  defp build_anchor(_anchor_input, _public_key, _key_id, _anchored_at),
    do: {:error, :invalid_anchor}

  defp required_anchor_binary(anchor_input, key) do
    case Map.fetch(anchor_input, key) do
      {:ok, value} when is_binary(value) -> {:ok, value}
      _ -> {:error, :invalid_anchor}
    end
  end

  defp required_sequence(anchor_input, key) do
    case Map.fetch(anchor_input, key) do
      {:ok, value} when is_integer(value) and value >= 0 -> {:ok, value}
      _ -> {:error, :invalid_anchor}
    end
  end

  defp produce_anchor_signing_input(anchor, bounds) do
    case V3.boundary_anchor_signing_input(anchor, bounds) do
      {:ok, signing_input} -> {:ok, signing_input}
      {:error, :invalid} -> {:error, {:producer_error, :invalid}}
    end
  end

  # next_public_key gets the same point validation as the resolved keys
  # (design Q7's fail-fast principle, v3-shaped): the successor of a v3 chain
  # key is itself a v3 chain key.
  defp build_key_transition(transition_input, current_key_id, current_public_key)
       when is_map(transition_input) do
    with {:ok, transition_id} <- required_transition_binary(transition_input, :transition_id),
         {:ok, chain_id} <- required_transition_binary(transition_input, :chain_id),
         {:ok, effective_at} <- required_transition_integer(transition_input, :effective_at),
         {:ok, next_key_id} <- required_transition_binary(transition_input, :next_key_id),
         {:ok, next_public_key} <- required_transition_public_key(transition_input) do
      {:ok,
       %V1.KeyTransition{
         transition_id: transition_id,
         chain_id: chain_id,
         effective_at: effective_at,
         current_key_id: current_key_id,
         current_public_key: current_public_key,
         next_key_id: next_key_id,
         next_public_key: next_public_key
       }}
    end
  end

  defp build_key_transition(_transition_input, _current_key_id, _current_public_key),
    do: {:error, :invalid_transition}

  defp required_transition_binary(transition_input, key) do
    case Map.fetch(transition_input, key) do
      {:ok, value} when is_binary(value) -> {:ok, value}
      _ -> {:error, :invalid_transition}
    end
  end

  defp required_transition_integer(transition_input, key) do
    case Map.fetch(transition_input, key) do
      {:ok, value} when is_integer(value) -> {:ok, value}
      _ -> {:error, :invalid_transition}
    end
  end

  defp required_transition_public_key(transition_input) do
    case Map.fetch(transition_input, :next_public_key) do
      {:ok, value} ->
        case p256_public_key(value) do
          {:ok, public_key} -> {:ok, public_key}
          {:error, :invalid_key_handle} -> {:error, :invalid_transition}
        end

      :error ->
        {:error, :invalid_transition}
    end
  end

  defp produce_key_transition_signing_input(transition, bounds) do
    case V3.key_transition_signing_input(transition, bounds) do
      {:ok, signing_input} -> {:ok, signing_input}
      {:error, :invalid} -> {:error, {:producer_error, :invalid}}
    end
  end

  defp normalize_opts(opts) when is_map(opts), do: opts
  defp normalize_opts(_opts), do: %{}

  defp generate_uuid do
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
end
