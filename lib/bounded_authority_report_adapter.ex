defmodule BoundedAuthorityReportAdapter do
  @moduledoc """
  Universal companion signer to `BoundedAuthorityProtocol` (ROADMAP B2).

  BAP produces the deterministic signing input for each protocol object (proof,
  grant, boundary anchor, key transition) but refuses to sign — it is a pure
  verifier + signing-input producer. THIS library is the signing glue: it takes a
  key-handle + a BAP signing input, signs the input's `message` via the handle's
  local key, and assembles the compact via BAP. The signing tail — resolve the
  key, sign via the handle, verify the signature against the resolved key, assemble
  — is shared across every object the library signs.

  ## What has landed

    * **Proof signing** (`sign_report/3`, RA1) — binds an issuer-signed grant to a
      application report by producing a holder proof, returning the `{grant, proof}`
      envelope the verifier verifies via `check_envelope/2`.
    * **Boundary-anchor signing** (`sign_anchor/3`, RA4) — signs a boundary anchor
      (a durable chain checkpoint), returning the compact a verifier checks via
      `verify_historical_anchor/3`.
    * **Grant signing** (`sign_grant/3`, RA7) — the issuer-role instantiation: signs
      a grant (the issuer's authority assertion), returning the compact a verifier
      checks via `verify_grant/3`. The handle's `signing_identity/1` must resolve to
      the `:issuer` role (the C1 gate — ADR-0006's grant-signing pre-commitment).

  The pattern generalizes to any BAP protocol object; key-transition signing is the
  one remaining named future slice (see ADR-0006 / ADR-0007).

  ## The key-handle contract (charter §6 invariant 1)

  The private key NEVER enters this library. Callers supply a `{module(), term()}`
  handle whose module implements the callbacks below. The library calls the handle's
  callbacks; the private key bytes live in the caller's module/process.

    * `sign/2`, `public_key/1` — required for every signing operation.
    * `thumbprint/1` — required (exposed for caller-side self-checking).
    * `key_identity/1` — **optional** (declared via `@optional_callbacks`); required
      only by `sign_anchor/3`, which resolves the key's registry id (`kid`) AND its
      public key as ONE atomic snapshot (defense-in-depth: prevents a stateful
      handle from splitting them across a rotation race). A proof-only handle need
      not implement it.
    * `signing_identity/1` — **optional**; required only by `sign_grant/3`, which
      resolves the key's **role** (`:issuer` or `:holder`) AND its registry id AND
      public key as ONE atomic snapshot. The role gate (C1) + the rotation-race
      defense both ride this single call: a stateful handle cannot return `:issuer`
      then rotate to a different key between role resolution and signing. An
      issuer-role handle implements it; a proof/anchor-only handle need not.

  A test-only reference implementation (`BoundedAuthorityReportAdapter.Keys.RawKey`)
  ships under `test/support/` for local development; production holders implement the
  callbacks with proper key custody (HSM, etc.).

  ## What this library does NOT do

    * Not a verifier — verification lives in every party via the protocol package
      (`check_envelope/2`, `verify_historical_anchor/3`). Consumers verify; this
      library signs.
    * Not the runtime — grant issuance, key custody/rotation, and revocation are
      the `bounded_authority` runtime's job. This library holds a key handle and
      signs on invocation; it does not mint capabilities.
    * Not a transport — the application transport libraries stay protocol-free. This
      library is a composable lib an edge agent (or any signing party) calls.
    * Not hex-published — private BaseLabs library until consumed + exercised +
      tuned across the projects that use it (see `docs/strategy.md`).
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

  @type anchor_input :: %{
          anchor_id: binary(),
          chain_id: binary(),
          sequence: non_neg_integer(),
          chain_hash: binary()
        }

  @type anchor_compact :: %{anchor: binary()}

  @type opts :: %{
          optional(:bounds) => BoundedAuthorityProtocol.V1.Bounds.t() | map(),
          optional(:issued_at) => integer(),
          optional(:proof_id) => binary()
        }

  @type anchor_opts :: %{
          optional(:bounds) => BoundedAuthorityProtocol.V1.Bounds.t() | map(),
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
          operations: [BoundedAuthorityProtocol.V1.Operation.t()]
        }

  @type grant_opts :: %{
          optional(:bounds) => BoundedAuthorityProtocol.V1.Bounds.t() | map()
        }

  @type grant_compact :: %{grant: binary()}

  @type grant_sign_error ::
          :invalid_grant
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
    4. Sign + assemble via the shared signing tail (`sign_and_assemble/3`) — the
       adapter signs ONLY the proof; the grant is never signed here.
    5. Return `%{grant: report.grant_compact, proof: proof_compact}`.

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
    * `:invalid_key_handle` — the handle is malformed, or the handle's
      `public_key/1` rejected / returned a non-32-byte key.
    * `:signing_failed` — the holder's `sign/2` callback rejected, returned a
      non-64-byte signature, violated the `{:ok, _} | {:error, _}` contract, or
      the signature did not verify against the resolved holder public key.
    * `{:producer_error, :invalid}` — BAP's producer or assembler rejected the
      proof (the input violated a bound or field constraint).
  """
  @spec sign_report(report(), key_handle(), opts()) ::
          {:ok, envelope()} | {:error, sign_error()}
  def sign_report(report, key_handle, opts \\ %{}) do
    opts = normalize_opts(opts)
    bounds = Map.get(opts, :bounds, %{})
    issued_at = Map.get(opts, :issued_at, System.system_time(:second))
    proof_id = Map.get(opts, :proof_id) || generate_uuid()

    with {:ok, report} <- validate_report(report),
         {:ok, holder_public_key} <- resolve_public_key(key_handle),
         proof = build_proof(report, holder_public_key, proof_id, issued_at),
         {:ok, signing_input} <- produce_proof_signing_input(proof, bounds),
         {:ok, proof_compact} <- sign_and_assemble(key_handle, signing_input, holder_public_key) do
      {:ok, %{grant: report.grant_compact, proof: proof_compact}}
    end
  end

  @doc """
  Signs a boundary anchor — a durable chain checkpoint a verifier checks via
  `BoundedAuthorityProtocol.V1.verify_historical_anchor/3`.

  Returns `{:ok, %{anchor: anchor_compact}}`. The caller supplies the anchor's
  *content* (`anchor_id`, `chain_id`, `sequence`, `chain_hash`); BOTH key
  identifiers (`public_key`, `key_id`) are resolved from `key_handle` — never
  trusted from the caller — so the signed header's `kid` + `key_fingerprint` are
  consistent with the key `sign/2` actually used.

  ## Why both key identifiers come from the handle

  BAP puts `key_id` in the anchor's SIGNED header (`typ: ba+chain-anchor`) and, at
  verify, binds it to the verifier's `HistoricalPublicKey.key_id`. Letting the
  caller supply `key_id` would let an anchor assert "kid K" while being signed by a
  different key. Deriving `key_id` from the same handle as `public_key` makes that
  inconsistency impossible by construction (the one thing NOT sign-enforced — that
  `key_id` *names* the key in any external registry — is verify-enforced by BAP).

  ## Defense-in-depth — the atomic `key_identity/1` snapshot

  `sign_anchor/3` resolves `key_id` AND `public_key` in a SINGLE `key_identity/1`
  call, so a stateful handle cannot split them across a rotation race (the
  separate-callback design a cross-vendor review probe once exploited). The
  remaining surface — `sign/2` signing with a key different from the snapshot's
  `public_key` — is caught by the `verify_signature` guard in the shared tail, so
  a post-snapshot rotation fails loudly as `:signing_failed`, never a silent
  false-success. The one thing still NOT sign-enforced — that `key_id` *names*
  the key in any external registry — is verify-enforced by BAP
  (`verify_historical_anchor/3` binds `key_id` + `public_key` + `key_fingerprint`
  together via the verifier's `HistoricalPublicKey`).

  ## Options

    * `:anchored_at` — the anchor's timestamp (default:
      `System.system_time(:second)`). Pin this when the verifier's evaluation time
      is far from wall-clock so it falls inside the key's validity window.
    * `:bounds` — resource ceilings forwarded to BAP's producer (default `%{}`).

  ## Errors (closed-atom set — no key material or anchor content in errors)

    * `:invalid_anchor` — a required content field is missing or malformed.
    * `:invalid_key_handle` — the handle is malformed, lacks `key_identity/1`, or its
      `public_key/1` / `key_identity/1` rejected / returned an invalid value.
    * `:signing_failed` — the `sign/2` callback rejected, returned a non-64-byte
      signature, violated the `{:ok, _} | {:error, _}` contract, or the signature
      did not verify against the resolved public key.
    * `{:producer_error, :invalid}` — BAP's producer or assembler rejected the
      anchor (the input violated a bound or field constraint).
  """
  @spec sign_anchor(anchor_input(), key_handle(), anchor_opts()) ::
          {:ok, anchor_compact()} | {:error, anchor_sign_error()}
  def sign_anchor(anchor_input, key_handle, opts \\ %{}) do
    opts = normalize_opts(opts)
    bounds = Map.get(opts, :bounds, %{})
    anchored_at = Map.get(opts, :anchored_at, System.system_time(:second))

    with {:ok, {key_id, public_key}} <- resolve_key_identity(key_handle),
         {:ok, anchor} <- build_anchor(anchor_input, public_key, key_id, anchored_at),
         {:ok, signing_input} <- produce_anchor_signing_input(anchor, bounds),
         {:ok, anchor_compact} <- sign_and_assemble(key_handle, signing_input, public_key) do
      {:ok, %{anchor: anchor_compact}}
    end
  end

  @doc """
  Signs a grant — the issuer's authority assertion. The issuer-role instantiation of
  the universal companion-signer tail (ADR-0006; this slice is recorded in ADR-0007).
  Returns `%{grant: grant_compact}`, verifiable via `BoundedAuthorityProtocol.V1.verify_grant/3`
  and envelope-compatible with `check_envelope/2` (it flows through the envelope when
  paired with a holder proof from `sign_report/3`).

  ## C1 gate (ADR-0006 pre-commitment) — what it does and does NOT guarantee

  `sign_grant/3` resolves the handle's atomic signing identity `{:issuer | :holder,
  key_id, public_key}` from ONE `signing_identity/1` call. If the resolved role is not
  `:issuer` (or the callback is absent), it returns `{:error, :invalid_key_handle}`
  BEFORE `sign/2` is called — so a handle that declares `:holder` (or implements no
  `signing_identity/1`) cannot sign a grant through this API. That is the C1
  pre-commitment realized structurally.

  This is NOT cryptographic key-role separation. A handle that consistently
  mis-declares its role — whose `signing_identity/1` returns
  `{:issuer, holder_key_id, holder_public_key}` while `sign/2` holds the matching
  holder private key — signs a grant successfully, because every value is internally
  consistent. The adapter resolves only the handle's `public_key` and signs against
  it; it cannot prove key identity. Key-role separation (an issuer key and a holder
  key are cryptographically distinct custodied entities) is the key-custody
  boundary's job — the runtime / HSM / key server behind the handle (charter §4).

  ## Key-identifier sourcing (ADR-0006 decision 3)

  The grant's signed-header `kid` (`key_id`) comes from the atomic `signing_identity/1`
  snapshot, NEVER from caller input — a caller-supplied `:key_id` in the grant map is
  ignored. `holder_thumbprint` IS caller-supplied (the grant's subject — the holder the
  capability is issued to; the issuer knows it at minting).

  ## Options

    * `:bounds` — resource ceilings forwarded to the producer (default `%{}`).

  ## Errors (closed-atom set — no key material or grant content in errors)

    * `:invalid_grant` — a required grant field is missing or malformed.
    * `:invalid_key_handle` — the handle is malformed, lacks `signing_identity/1`, the
      resolved role is not `:issuer`, or the snapshot returned an invalid value.
    * `:signing_failed` — `sign/2` rejected, returned a non-64-byte signature, violated
      the `{:ok, _} | {:error, _}` contract, or the signature did not verify against the
      snapshot's `public_key`.
    * `{:producer_error, :invalid}` — BAP's producer or assembler rejected the grant.
  """
  @spec sign_grant(grant_input(), key_handle(), grant_opts()) ::
          {:ok, grant_compact()} | {:error, grant_sign_error()}
  def sign_grant(grant_input, key_handle, opts \\ %{}) do
    opts = normalize_opts(opts)
    bounds = Map.get(opts, :bounds, %{})

    with {:ok, {key_id, public_key}} <- resolve_signing_identity(key_handle),
         {:ok, grant} <- build_grant(grant_input, key_id),
         {:ok, signing_input} <- produce_grant_signing_input(grant, bounds),
         {:ok, grant_compact} <- sign_and_assemble(key_handle, signing_input, public_key) do
      {:ok, %{grant: grant_compact}}
    end
  end

  # ---------------------------------------------------------------------------
  # The shared signing tail (the universal-companion primitive).
  #
  # sign_via_handle → verify_signature → assemble_compact. Every object this
  # library signs flows through here. verify_signature is the wrong-key guard
  # (the RA1 cross-vendor CV-finding): a signature that does not verify against
  # the resolved public key is :signing_failed, never a silent false-success.
  # ---------------------------------------------------------------------------

  defp sign_and_assemble(key_handle, signing_input, public_key) do
    with {:ok, signature} <- sign_via_handle(key_handle, signing_input.message),
         :ok <- verify_signature(signing_input.message, signature, public_key) do
      assemble_compact(signing_input, signature)
    end
  end

  # Cross-vendor closeout finding (CV round 2): the adapter validated only the
  # signature's 64-byte length, never that it verifies against the resolved
  # holder public key. A callback signing with the wrong key (a rotation/
  # misconfiguration race — the handle's public_key/1 returns key A, but sign/2
  # uses key B) produced a {pub_A, sig_B} envelope that the adapter returned as
  # {:ok, envelope}, deferring the failure to check_envelope downstream. Verify
  # the signature against the public key HERE so a wrong-key sign is :signing_failed,
  # not a silent false-success.
  defp verify_signature(message, signature, holder_public_key)
       when is_binary(message) and is_binary(signature) and is_binary(holder_public_key) do
    if :crypto.verify(:eddsa, :none, message, signature, [holder_public_key, :ed25519]),
      do: :ok,
      else: {:error, :signing_failed}
  end

  defp verify_signature(_message, _signature, _public_key), do: {:error, :signing_failed}

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

  defp resolve_public_key({module, handle}) when is_atom(module) do
    # The callback is caller-supplied; a missing module, a function-clause
    # raise inside it, or any other fault must map to the closed-atom error
    # rather than escape sign_report/3 (mirrors BAP's fixed/1 wrapper). The
    # public key must be a 32-byte Ed25519 key — a short/malformed key fails
    # HERE as :invalid_key_handle, not downstream as a producer error.
    case safe_callback(module, :public_key, [handle]) do
      {:ok, public_key} when is_binary(public_key) and byte_size(public_key) == 32 ->
        {:ok, public_key}

      _malformed_key_or_callback ->
        {:error, :invalid_key_handle}
    end
  end

  defp resolve_public_key(_handle), do: {:error, :invalid_key_handle}

  # The anchor's key identity — the signed-header `kid` AND the 32-byte public
  # key — resolved as ONE atomic snapshot. This is defense-in-depth at sign time:
  # a single key_identity/1 call cannot split key_id from public_key across a
  # rotation race (the separate-callback design Codex's cross-vendor probe
  # exploited). The remaining surface — sign/2 signing with a key different from
  # the snapshot's public_key — is caught by verify_signature in the shared tail.
  # key_identity/1 is an OPTIONAL callback (@optional_callbacks); a proof-only
  # handle does not implement it, so sign_anchor on such a handle fails HERE as
  # :invalid_key_handle (the UndefinedFunctionError from apply/3 is caught by
  # safe_callback). BAP's producer validates the full ascii/length constraint on
  # key_id; here we assert a non-empty key_id + a 32-byte public_key.
  defp resolve_key_identity({module, handle}) when is_atom(module) do
    case safe_callback(module, :key_identity, [handle]) do
      {:ok, {key_id, public_key}}
      when is_binary(key_id) and byte_size(key_id) > 0 and is_binary(public_key) and
             byte_size(public_key) == 32 ->
        {:ok, {key_id, public_key}}

      _malformed_or_unimplemented ->
        {:error, :invalid_key_handle}
    end
  end

  defp resolve_key_identity(_handle), do: {:error, :invalid_key_handle}

  # The grant's atomic signing identity — the role (:issuer | :holder) AND the key's
  # registry id AND its 32-byte public key — resolved as ONE snapshot, with the role
  # gate folded into the match. This is the C1 enforcement (ADR-0006's grant-signing
  # pre-commitment): ONLY a snapshot whose role is :issuer passes; a :holder snapshot,
  # a malformed snapshot, a callback failure, or a missing signing_identity/1 (the
  # UndefinedFunctionError from apply/3 caught by safe_callback) all collapse to
  # :invalid_key_handle BEFORE sign/2 is ever reached.
  #
  # Resolving role + key identity in a SINGLE call (vs. separate role/1 + key_identity/1
  # callbacks) is load-bearing: a stateful handle cannot return :issuer then rotate to a
  # holder key between role resolution and signing — the snapshot is one observation, and
  # the verify_signature guard in the shared tail catches any sign/2-vs-snapshot drift.
  # (design-adversarial Challenge 1 — the separate-callback design was rejected for the
  # TOCTOU it opened.)
  defp resolve_signing_identity({module, handle}) when is_atom(module) do
    case safe_callback(module, :signing_identity, [handle]) do
      {:ok, {:issuer, key_id, public_key}}
      when is_binary(key_id) and byte_size(key_id) > 0 and is_binary(public_key) and
             byte_size(public_key) == 32 ->
        {:ok, {key_id, public_key}}

      _holder_role_or_malformed_or_unimplemented ->
        {:error, :invalid_key_handle}
    end
  end

  defp resolve_signing_identity(_handle), do: {:error, :invalid_key_handle}

  defp safe_callback(module, function, args) do
    apply(module, function, args)
  rescue
    _error -> {:error, :callback_failed}
  catch
    # A production key-handle callback (HSM / key server) that times out does
    # so via exit/1 (e.g. a GenServer.call timeout) — rescue catches exceptions
    # only, so :exit/:throw would escape sign_report/3 and crash the caller.
    # Map them to the same callback-failure shape the rescue uses. This is the
    # production path the moduledoc steers real holders toward.
    :exit, _reason -> {:error, :callback_failed}
    :throw, _reason -> {:error, :callback_failed}
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

  defp build_anchor(anchor_input, public_key, key_id, anchored_at) when is_map(anchor_input) do
    with {:ok, anchor_id} <- required_anchor_binary(anchor_input, :anchor_id),
         {:ok, chain_id} <- required_anchor_binary(anchor_input, :chain_id),
         {:ok, sequence} <- required_sequence(anchor_input, :sequence),
         {:ok, chain_hash} <- required_anchor_binary(anchor_input, :chain_hash) do
      {:ok,
       %BoundedAuthorityProtocol.V1.BoundaryAnchor{
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
    case BoundedAuthorityProtocol.V1.boundary_anchor_signing_input(anchor, bounds) do
      {:ok, signing_input} -> {:ok, signing_input}
      {:error, :invalid} -> {:error, {:producer_error, :invalid}}
    end
  end

  # The grant's content is validated for presence + shape HERE (clean :invalid_grant on a
  # missing/malformed field); BAP's producer validates SEMANTICS (identifier grammar, time
  # coherence, the 32-byte holder_thumbprint, operation shape) and a semantic violation
  # surfaces as {:producer_error, :invalid}. key_id is NEVER read from grant_input — it
  # comes from the handle's signing_identity/1 snapshot (the _key_id param), so a caller
  # :key_id smuggled into the map is silently ignored (ADR-0006 decision 3).
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
       %BoundedAuthorityProtocol.V1.Grant{
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
    case Map.fetch(grant_input, :audiences) do
      {:ok, audiences} when is_list(audiences) and audiences != [] ->
        if Enum.all?(audiences, &is_binary/1),
          do: {:ok, audiences},
          else: {:error, :invalid_grant}

      _ ->
        {:error, :invalid_grant}
    end
  end

  defp required_grant_operations(grant_input) do
    # Operations are %V1.Operation{} structs; shape + the unique-name constraint are
    # BAP's to enforce at produce-time. Here we assert a non-empty list is present.
    case Map.fetch(grant_input, :operations) do
      {:ok, operations} when is_list(operations) and operations != [] -> {:ok, operations}
      _ -> {:error, :invalid_grant}
    end
  end

  defp produce_grant_signing_input(grant, bounds) do
    case BoundedAuthorityProtocol.V1.grant_signing_input(grant, bounds) do
      {:ok, signing_input} -> {:ok, signing_input}
      {:error, :invalid} -> {:error, {:producer_error, :invalid}}
    end
  end

  defp sign_via_handle({module, handle}, message) do
    # `key_handle` shape is validated upstream by resolve_public_key/1 (the only
    # path here is through the `with` after a successful resolve), so the handle
    # is guaranteed a valid {atom, term} 2-tuple. The callback itself is still
    # caller-supplied, so wrap it the same way (a raise inside sign/2 maps to
    # :signing_failed rather than escaping).
    case safe_callback(module, :sign, [message, handle]) do
      {:ok, signature} when is_binary(signature) and byte_size(signature) == 64 ->
        {:ok, signature}

      # A signature that isn't a 64-byte binary (short, wrong type, or the
      # callback returned a non-{:ok,_}/{:error,_} shape like :ok / nil / a bare
      # binary) is a callback contract violation -> :signing_failed, never a raise.
      _callback_contract_violation ->
        {:error, :signing_failed}
    end
  end

  defp assemble_compact(signing_input, signature) do
    # Generic over the signing input's kind (:proof, :boundary_anchor, ...) —
    # V1.assemble_compact/2 dispatches on kind and validates via the matching
    # codec. Both sign_report/3 and sign_anchor/3 flow through here.
    case BoundedAuthorityProtocol.V1.assemble_compact(signing_input, signature) do
      {:ok, compact} -> {:ok, compact}
      {:error, :invalid} -> {:error, {:producer_error, :invalid}}
    end
  end

  # Coerce a non-map opts (a caller bug) to the empty map rather than crashing with a
  # value-echoing BadMapError inside Map.get/3 — the closed-atom error discipline. opts is
  # caller-supplied config (bounds windows, timestamps); a non-map is a type violation per
  # every *_opts() @spec, and the defaults are a safe fallback. Applied to all three sign_*
  # entry points (sign_report/3, sign_anchor/3, sign_grant/3) — the same contract everywhere.
  defp normalize_opts(opts) when is_map(opts), do: opts
  defp normalize_opts(_opts), do: %{}

  defp generate_uuid do
    # UUID v4 per RFC 4122: 16 random bytes, then overwrite byte 6's high nibble
    # with the version (0100 = 4) and byte 8's high two bits with the variant
    # (10). The proof's `jti` (proof_id) is gated by BAP's `valid_identifier?`
    # → `StringOrUri.valid?` (a looser URI-safe-string check, not UUID-only), so
    # a UUID is chosen by convention (DPoP `jti` is conventionally a UUID), not
    # because BAP requires it — but the canonical UUID shape also satisfies the
    # `valid_uuid?` gate that the caller's `invocation_id` must pass.
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

  @doc """
  Returns the key's identity — its registry `kid` AND its 32-byte raw Ed25519
  public key — as a single atomic `{key_id, public_key}` snapshot. Required only
  by `sign_anchor/3`, which resolves both in ONE call so a stateful handle
  cannot split `kid` from `public_key` across a rotation race (defense-in-depth
  at sign time; any `sign/2`-vs-snapshot mismatch is then caught by the
  `verify_signature` guard). **Optional** callback — a proof-only handle (used
  only with `sign_report/3`) need not implement it.
  """
  @callback key_identity(handle :: term()) ::
              {:ok, {key_id :: binary(), public_key :: binary()}} | {:error, term()}

  @doc """
  Returns the key's **signing identity** for a role-gated operation — its **role**
  (`:issuer` or `:holder`) AND its registry `kid` AND its 32-byte raw Ed25519 public
  key — as a single atomic `{:role, key_id, public_key}` snapshot. Required only by
  `sign_grant/3`, which both (a) gates on `role == :issuer` (the C1 pre-commitment —
  a handle that declares `:holder`, or omits this callback, is rejected before
  `sign/2`; see `sign_grant/3`'s `@doc` for the precise property — this is
  declaration-rejection, not cryptographic key-role separation) and (b) uses the snapshot's
  `key_id` + `public_key` — all from ONE call, so a stateful handle cannot return
  `:issuer` then rotate to a different key between role resolution and signing (the
  rotation-race defense; any `sign/2`-vs-snapshot mismatch is caught by the
  `verify_signature` guard). **Optional** callback — a proof-only or anchor-only handle
  need not implement it (and is then rejected by `sign_grant/3` as `:invalid_key_handle`).
  """
  @callback signing_identity(handle :: term()) ::
              {:ok, {:issuer | :holder, key_id :: binary(), public_key :: binary()}}
              | {:error, term()}

  @optional_callbacks [key_identity: 1, signing_identity: 1]
end
