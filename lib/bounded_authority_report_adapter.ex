defmodule BoundedAuthorityReportAdapter do
  @moduledoc """
  The signer for the Bounded Authority Protocol, contract-major 1 (the
  `BAP1-Ed25519-SHA256` suite, Ed25519 keys).

  The protocol package (`BoundedAuthorityProtocol`) produces the exact bytes to sign for
  each protocol object and verifies signed objects, but never signs. This module signs:
  it takes a key handle and the object's fields, asks the protocol package for the signing
  input, signs its `message` through the handle, verifies the signature against the
  handle's public key, and assembles the compact form through the protocol package. Every
  entry point shares that path.

  ## Entry points

  | Function | Signs | Handle callbacks | Verify with |
  |---|---|---|---|
  | `sign_report/3` | a holder proof over an issuer's grant | `sign/2`, `public_key/1` | `BoundedAuthorityProtocol.V1.check_envelope/2` |
  | `sign_local_loopback_report/3` | a holder proof for a loopback listener | `sign/2`, `public_key/1` | `BoundedAuthorityProtocol.ApplicationProfile.LocalLoopbackHttp.V1.check_envelope/2` |
  | `sign_grant/3` | a grant (issuer role only) | `sign/2`, `signing_identity/1` | `BoundedAuthorityProtocol.V1.verify_grant/3` |
  | `sign_anchor/3` | a boundary anchor (chain checkpoint) | `sign/2`, `key_identity/1` | `BoundedAuthorityProtocol.V1.verify_historical_anchor/3` |
  | `sign_key_transition/3` | a key transition (rotation) | `sign/2`, `key_identity/1` | `BoundedAuthorityProtocol.V1.verify_key_transition/4` |
  | `sign_content_assertion/3` | a content assertion | `sign/2`, `key_identity/1` | `BoundedAuthorityProtocol.ContentAssertion.V1.verify_assertion/2` |

  `BoundedAuthorityReportAdapter.V3` is the ES256 sibling (contract-major 3, P-256 keys)
  of `sign_report/3`, `sign_grant/3`, `sign_anchor/3` and `sign_key_transition/3`. Both
  modules use the same key-handle behavior. This module's entry points accept Ed25519 keys
  only, and `V3`'s accept P-256 keys only.

  The examples in each function's documentation continue the README's quick start: they
  use its development key handle, `MyApp.DevKey`, with handle terms `{role, name}`, its
  `alias BoundedAuthorityProtocol.V1`, and its `now`. The test suite runs every one.

  ## The key-handle behavior

  The private key never enters this library. A caller passes a `{module(), term()}`
  handle whose module implements the callbacks below; the term is a key reference only
  that module understands. Callbacks may reach a remote custodian (an HSM, a KMS, a key
  server). A callback that raises, throws or exits is contained: the entry point returns
  `{:error, :signing_failed}` for `sign/2` and `{:error, :invalid_key_handle}` for the
  others.

    * `sign/2` and `public_key/1` are required by every entry point.
    * `thumbprint/1` is required by the behavior, but no entry point calls it. It
      returns the RFC 7638 thumbprint the issuer puts in a grant's `cnf.jkt`, so callers
      can check a handle against a grant.
    * `key_identity/1` is optional. `sign_anchor/3`, `sign_key_transition/3` and
      `sign_content_assertion/3` require it: they read the key id and the public key in
      one call, so a handle over a rotating key store cannot return the id of one key
      version and the public key of another.
    * `signing_identity/1` is optional. `sign_grant/3` requires it: it reads the declared
      role, the key id and the public key in one call, and signs only when the role is
      `:issuer`.

  Key and signature shapes depend on the surface. Under this module, public keys are raw
  32-byte Ed25519 keys that pass the protocol's strict acceptance rule
  (`BoundedAuthorityProtocol.Ed25519.acceptable_public_key?/1`), and `sign/2` returns a
  64-byte Ed25519 signature. Under `BoundedAuthorityReportAdapter.V3`, public keys are
  65-byte uncompressed SEC1 P-256 points (`0x04 || x || y`, checked to be on the curve),
  and `sign/2` returns the 64-byte raw `r || s` form of RFC 7518 §3.4 (a DER signature is
  refused; the adapter converts a high-S signature to low-S).

  The repository has test-only reference handles under `test/support/`; they are not
  shipped in the package. Production handles call your key custody.

  ## Options

  Every entry point takes its options as a map or as a keyword list, and the two are the
  same call: `sign_report(report, handle, issued_at: t)` is
  `sign_report(report, handle, %{issued_at: t})`. Each entry point accepts only the option
  keys its documentation lists, and checks each value's kind. These are refused with the
  entry point's input error (`:invalid_report`, `:invalid_grant` and so on) before any
  callback is called:

    * an unknown key, including a misspelling (`role_attestaton:`) and a string key
      (`%{"issued_at" => t}`);
    * a present value of the wrong kind (`proof_id: nil`, `issued_at: "now"`,
      `bounds: :maximum`): a present option is never replaced by its default;
    * a list that is not a keyword list with unique atom keys, a struct, and any other
      value that is not a map (`nil`, an atom, a number, a tuple, a binary).

  The rule holds all the way down: a `:bounds` or `:role_attestation` value may itself be a
  map or a keyword list, and a malformed one is refused before any callback. A malformed
  `:role_attestation` value on `sign_grant/3` is `:invalid_role_attestation`. Calling an
  entry point without the options argument means `%{}`.

  ## Errors

  Every entry point returns `{:ok, map}` or `{:error, reason}`, where `reason` is a closed
  atom or the tuple `{:producer_error, :invalid}`. Errors never carry key material,
  message bytes or input values. Each function's documentation lists its set, and the
  `*_sign_error` types name them. The errors guide explains each one.

  ## What this library does not do

    * It does not verify credentials. Verifiers use the protocol package
      (`check_envelope/2`, `verify_grant/3`, `verify_historical_anchor/3`,
      `verify_key_transition/4`, `verify_assertion/2`). The one signature this library
      checks is its own, before returning it.
    * It does not issue, track or revoke grants, and it does not hold or rotate keys. That
      is the job of your authority service and your key custody.
    * It does not transport or store anything. It returns compact strings.
  """

  alias BoundedAuthorityProtocol.ApplicationProfile.LocalLoopbackHttp.V1, as: LocalLoopbackHttp
  alias BoundedAuthorityProtocol.ContentAssertion.V1, as: ContentAssertionV1
  alias BoundedAuthorityProtocol.RoleAttestation.V1, as: RoleAttestationV1
  alias BoundedAuthorityProtocol.V1.Json
  alias BoundedAuthorityReportAdapter.Options
  alias BoundedAuthorityReportAdapter.Telemetry

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

  @typedoc """
  The report shape `sign_local_loopback_report/3` consumes — the same field set
  as `report()`, except the nonce is REQUIRED (a non-empty binary; enforced at
  runtime — a typespec cannot express non-emptiness).
  """
  @type local_loopback_report :: %{
          grant_compact: binary(),
          operation: binary(),
          method: binary(),
          target_uri: binary(),
          invocation_id: binary(),
          cast_arguments: Json.value(),
          nonce: binary()
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
          optional(:bounds) => BoundedAuthorityProtocol.V1.Bounds.t() | map(),
          optional(:role_attestation) => %{
            optional(:now) => integer(),
            compact: binary(),
            attestor: BoundedAuthorityProtocol.V1.HistoricalPublicKey.t()
          }
        }

  @type grant_compact :: %{grant: binary()}

  @type grant_sign_error ::
          :invalid_grant
          | :invalid_key_handle
          | :invalid_role_attestation
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
          optional(:bounds) => BoundedAuthorityProtocol.V1.Bounds.t() | map()
        }

  @type transition_compact :: %{key_transition: binary()}

  @type transition_sign_error ::
          :invalid_transition
          | :invalid_key_handle
          | :signing_failed
          | {:producer_error, :invalid}

  @type content_assertion_input :: %{
          jti: binary(),
          iss: binary(),
          aud: binary(),
          sub: binary(),
          profile: binary(),
          profile_digest: binary(),
          content_digest: binary(),
          gen: integer(),
          prev: binary(),
          iat: integer(),
          nbf: integer(),
          exp: integer()
        }

  @type content_assertion_opts :: %{
          optional(:bounds) => BoundedAuthorityProtocol.V1.Bounds.t() | map()
        }

  @type content_assertion_compact :: %{content_assertion: binary()}

  @type content_assertion_sign_error ::
          :invalid_content_assertion
          | :invalid_key_handle
          | :signing_failed
          | {:producer_error, :invalid}

  @doc """
  Signs a holder proof that binds an issuer-signed grant to one request.

  Returns `{:ok, %{grant: grant_compact, proof: proof_compact}}`. The grant is
  `report.grant_compact`, passed through unchanged; this function never signs a grant.
  The proof is signed through the holder's key handle and binds the grant (by hash), the
  request method, target URI, invocation id, operation, arguments (by digest) and nonce.
  A verifier checks the pair with `BoundedAuthorityProtocol.V1.check_envelope/2`.

  ## Parameters

    * `report` — a map with:
      * `:grant_compact` — the issuer-signed contract-major-1 grant, as a compact string.
        A grant of another major is refused.
      * `:operation` — the operation name the grant authorizes.
      * `:method` — the HTTP method, for example `"POST"`.
      * `:target_uri` — the canonical HTTPS URI of the request.
      * `:invocation_id` — a canonical lowercase UUID, unique per request.
      * `:cast_arguments` — the request body in the protocol's tagged form, from
        `BoundedAuthorityProtocol.V1.Json.decode/2` of the raw body bytes. Not `nil`.
      * `:nonce` — the request nonce as a string, or `nil` when the verifier does not
        require one.
    * `key_handle` — the holder's `{module, term}` handle; calls `public_key/1` and `sign/2`.
    * `opts` — a map or a keyword list (see "Options" in the module documentation):
      * `:bounds` — resource limits passed unchanged to the protocol package's producer
        and assembler; default `%{}`, the protocol's maximums.
      * `:issued_at` — the proof's `iat` in Unix seconds; default
        `System.system_time(:second)`. Set it when the verifier's evaluation time is far
        from the wall clock (tests, offline flows).
      * `:proof_id` — the proof's `jti`; default a fresh UUID v4.

  ## Errors

    * `:invalid_report` — `report` is not a map, a required field is missing or not a
      string, `cast_arguments` is `nil`, the nonce is neither `nil` nor a string,
      `grant_compact` is not a contract-major-1 grant, or `opts` is invalid (see "Options"
      in the module documentation).
    * `:invalid_key_handle` — the handle is not a `{module, term}` pair, or `public_key/1`
      failed or returned something other than an acceptable 32-byte Ed25519 key.
    * `:signing_failed` — `sign/2` failed, returned something other than
      `{:ok, <<_::512>>}`, or returned a signature that does not verify against the
      handle's public key.
    * `{:producer_error, :invalid}` — the protocol package refused the proof, for example
      a target URI that is not canonical HTTPS, an invocation id that is not a canonical
      UUID, or a value over the bounds.

  ## Example

  ```elixir
  {:ok, cast_arguments} = V1.Json.decode(~s({"document":"minutes-2026-10-02.pdf"}))

  report = %{
    grant_compact: grant,
    operation: "archive_document",
    method: "POST",
    target_uri: "https://records.example/archive",
    invocation_id: "4b5c6d7e-8f90-4a1b-9c2d-3e4f5a6b7c8d",
    cast_arguments: cast_arguments,
    nonce: "nonce-archive-2"
  }

  {:ok, %{grant: ^grant, proof: proof}} =
    BoundedAuthorityReportAdapter.sign_report(report, holder, %{issued_at: now})

  BoundedAuthorityReportAdapter.sign_report(%{report | grant_compact: "not.a.grant"}, holder)
  #=> {:error, :invalid_report}
  ```
  """
  @spec sign_report(report(), key_handle(), opts() | keyword()) ::
          {:ok, envelope()} | {:error, sign_error()}
  def sign_report(report, key_handle, opts \\ %{}) do
    Telemetry.sign_span(:report, fn ->
      with {:ok, opts} <- normalize_opts(opts, :invalid_report, :report),
           do: do_sign_report(report, key_handle, opts)
    end)
  end

  defp do_sign_report(report, key_handle, opts) do
    bounds = Map.get(opts, :bounds, %{})
    issued_at = Map.get(opts, :issued_at, System.system_time(:second))
    proof_id = Map.get(opts, :proof_id) || generate_uuid()

    with {:ok, report} <- validate_report(report),
         {:ok, holder_public_key} <- resolve_public_key(key_handle),
         proof = build_proof(report, holder_public_key, proof_id, issued_at),
         {:ok, signing_input} <- produce_proof_signing_input(proof, bounds),
         {:ok, proof_compact} <-
           sign_and_assemble(
             key_handle,
             signing_input,
             holder_public_key,
             bounds,
             &assemble_standard_compact/3
           ) do
      {:ok, %{grant: report.grant_compact, proof: proof_compact}}
    end
  end

  @doc """
  Signs a holder proof for a development listener on the literal loopback interface.

  This is the signer for the protocol's local-loopback HTTP profile
  (`bap-application-proof/local-loopback-http/1`, protected `typ: "ba+loopback-proof"`).
  It returns the same `{:ok, %{grant: grant, proof: proof_compact}}` shape as
  `sign_report/3`, and a verifier checks it with
  `BoundedAuthorityProtocol.ApplicationProfile.LocalLoopbackHttp.V1.check_envelope/2`.
  The two proof families reject each other's bytes: the standard `check_envelope/2`
  rejects a loopback proof, and the loopback verifier rejects a standard proof.

  Loopback HTTP is plain HTTP: it has no confidentiality and no server authentication,
  and it is not a substitute for HTTPS. The verifier (the listener) owns the nonce,
  replay protection and the expected target. Choosing this profile is choosing this
  function: there is no profile option on `sign_report/3`, and nothing is inferred from
  the URI, headers or environment.

  ## Parameters

  The same as `sign_report/3`, with two differences:

    * `:nonce` is required: a non-empty string, normally the listener's single-use
      challenge.
    * `:target_uri` must be a canonical literal-loopback HTTP URI:
      `http://127.0.0.1[:port]/path` or `http://[::1][:port]/path`, with a decimal port,
      no `:80`, a lowercase scheme and a normalized path. The URI is passed to the
      protocol package unchanged, and any other form (`localhost`, other `127.0.0.0/8`
      addresses, numeric or mapped forms, userinfo, queries, fragments, `https`) is
      refused. Nothing is rewritten.

  Options are the same as `sign_report/3`'s.

  ## Errors

    * `:invalid_report` — as for `sign_report/3`, or the nonce is missing, empty or not a
      string.
    * `:invalid_key_handle` and `:signing_failed` — as for `sign_report/3`.
    * `{:producer_error, :invalid}` — the protocol package refused the proof: a target
      URI that is not a canonical literal-loopback HTTP URI, a nonce over the bounds or
      not valid UTF-8, or another value over the bounds.

  ## Example

  ```elixir
  {:ok, %{grant: tool_grant}} =
    BoundedAuthorityReportAdapter.sign_grant(
      %{
        issuer: "https://issuer.example",
        grant_id: "urn:example:grant:local-tools-1",
        audiences: ["https://tools.example"],
        issued_at: now,
        not_before: now,
        expires_at: now + 3600,
        holder_thumbprint: holder_thumbprint,
        operations: [%V1.Operation{name: "run_local_tool", selectors: [:all]}]
      },
      issuer
    )

  report = %{
    grant_compact: tool_grant,
    operation: "run_local_tool",
    method: "POST",
    target_uri: "http://127.0.0.1:4000/tools/summarize",
    invocation_id: "5c6d7e8f-9a0b-4c1d-8e2f-3a4b5c6d7e8f",
    cast_arguments: {:object, [{"file", {:string, "notes.txt"}}]},
    nonce: "listener-challenge-1"
  }

  {:ok, %{proof: _proof}} = BoundedAuthorityReportAdapter.sign_local_loopback_report(report, holder)

  BoundedAuthorityReportAdapter.sign_local_loopback_report(
    %{report | target_uri: "http://localhost:4000/tools/summarize"},
    holder
  )
  #=> {:error, {:producer_error, :invalid}}
  ```
  """
  @doc since: "0.5.0"
  @spec sign_local_loopback_report(local_loopback_report(), key_handle(), opts() | keyword()) ::
          {:ok, envelope()} | {:error, sign_error()}
  def sign_local_loopback_report(report, key_handle, opts \\ %{}) do
    Telemetry.sign_span(:local_loopback_report, fn ->
      with {:ok, opts} <- normalize_opts(opts, :invalid_report, :report),
           do: do_sign_local_loopback_report(report, key_handle, opts)
    end)
  end

  defp do_sign_local_loopback_report(report, key_handle, opts) do
    bounds = Map.get(opts, :bounds, %{})
    issued_at = Map.get(opts, :issued_at, System.system_time(:second))
    proof_id = Map.get(opts, :proof_id) || generate_uuid()

    with {:ok, report} <- validate_local_loopback_report(report),
         {:ok, holder_public_key} <- resolve_public_key(key_handle),
         proof = build_proof(report, holder_public_key, proof_id, issued_at),
         {:ok, signing_input} <- produce_local_loopback_signing_input(proof, bounds),
         {:ok, proof_compact} <-
           sign_and_assemble(
             key_handle,
             signing_input,
             holder_public_key,
             bounds,
             &LocalLoopbackHttp.assemble_compact/3
           ) do
      {:ok, %{grant: report.grant_compact, proof: proof_compact}}
    end
  end

  @doc """
  Signs a boundary anchor: a signed checkpoint of an append-only chain (an audit log, for
  example), naming the chain, a sequence number and the hash of the chain so far.

  Returns `{:ok, %{anchor: anchor_compact}}`. A verifier checks it with
  `BoundedAuthorityProtocol.V1.verify_historical_anchor/3`.

  The signed header names the signing key by its id and fingerprint. Both come from the
  handle's `key_identity/1`, read once together with the public key; a key id or public
  key in the input is ignored. So an anchor cannot name one key while being signed by
  another: if `sign/2` signs with a different key than the snapshot names, the signature
  check fails and the result is `{:error, :signing_failed}`. Whether the key id names
  that key in your registry is for the verifier to check, through the
  `BoundedAuthorityProtocol.V1.HistoricalPublicKey` it trusts.

  ## Parameters

    * `anchor_input` — a map with `:anchor_id` (string), `:chain_id` (string),
      `:sequence` (a non-negative integer) and `:chain_hash` (the raw 32-byte chain hash;
      all zeros only at sequence 0).
    * `key_handle` — the chain key's handle; calls `key_identity/1` and `sign/2`.
    * `opts` — a map or a keyword list (see "Options" in the module documentation):
      * `:anchored_at` — the anchor's timestamp in Unix seconds; default
        `System.system_time(:second)`. It must fall inside the key's validity window at
        verification.
      * `:bounds` — resource limits passed unchanged to the protocol package; default
        `%{}`.

  ## Errors

    * `:invalid_anchor` — `anchor_input` is not a map, a field is missing or of the
      wrong basic type, or `opts` is invalid (see "Options" above).
    * `:invalid_key_handle` — the handle is not a `{module, term}` pair, has no
      `key_identity/1`, or returned an empty key id or a public key that is not an
      acceptable 32-byte Ed25519 key.
    * `:signing_failed` — as for `sign_report/3`.
    * `{:producer_error, :invalid}` — the protocol package refused the anchor, for
      example a `chain_hash` that is not 32 bytes or an all-zero hash at a nonzero
      sequence.

  ## Example

  ```elixir
  chain_key = {MyApp.DevKey, {:holder, "audit-chain-key-1"}}

  {:ok, %{anchor: _anchor}} =
    BoundedAuthorityReportAdapter.sign_anchor(
      %{
        anchor_id: "urn:example:anchor:audit-log-42",
        chain_id: "urn:example:chain:audit-log",
        sequence: 42,
        chain_hash: :crypto.hash(:sha256, "audit log entries 1 through 42")
      },
      chain_key,
      %{anchored_at: now}
    )

  BoundedAuthorityReportAdapter.sign_anchor(%{anchor_id: "urn:example:anchor:43"}, chain_key)
  #=> {:error, :invalid_anchor}
  ```
  """
  @spec sign_anchor(anchor_input(), key_handle(), anchor_opts() | keyword()) ::
          {:ok, anchor_compact()} | {:error, anchor_sign_error()}
  def sign_anchor(anchor_input, key_handle, opts \\ %{}) do
    Telemetry.sign_span(:anchor, fn ->
      with {:ok, opts} <- normalize_opts(opts, :invalid_anchor, :anchor),
           do: do_sign_anchor(anchor_input, key_handle, opts)
    end)
  end

  defp do_sign_anchor(anchor_input, key_handle, opts) do
    bounds = Map.get(opts, :bounds, %{})
    anchored_at = Map.get(opts, :anchored_at, System.system_time(:second))

    with {:ok, {key_id, public_key}} <- resolve_key_identity(key_handle),
         {:ok, anchor} <- build_anchor(anchor_input, public_key, key_id, anchored_at),
         {:ok, signing_input} <- produce_anchor_signing_input(anchor, bounds),
         {:ok, anchor_compact} <-
           sign_and_assemble(
             key_handle,
             signing_input,
             public_key,
             bounds,
             &assemble_standard_compact/3
           ) do
      {:ok, %{anchor: anchor_compact}}
    end
  end

  @doc """
  Signs a grant: the issuer's statement that one holder key may perform the listed
  operations, for the listed audiences, within a time window.

  Returns `{:ok, %{grant: grant_compact}}`. A verifier checks it with
  `BoundedAuthorityProtocol.V1.verify_grant/3`, or together with a holder proof from
  `sign_report/3` through `BoundedAuthorityProtocol.V1.check_envelope/2`.

  ## The issuer-role gate

  The handle's `signing_identity/1` returns `{role, key_id, public_key}` in one call. This
  function signs only when the role is `:issuer`; a handle that declares `:holder`, or
  has no `signing_identity/1`, gets `{:error, :invalid_key_handle}` before `sign/2` is
  called. The grant's `kid` header is the `key_id` from that call; a `:key_id` in the
  input is ignored.

  The gate checks a declaration; it cannot prove which key the handle holds. A handle
  that returns `:issuer` for a holder's key, and signs with that key, signs a grant.
  Keeping issuer keys in issuer custody is the custody layer's job, and the verifier's
  trusted issuer key is the real boundary.

  ## The role-attestation gate (optional)

  With the `:role_attestation` option, the declared role must also be backed by a role
  attestation (`bap-role-attestation/1`) signed by an attestor the caller trusts. The
  function calls `BoundedAuthorityProtocol.RoleAttestation.V1.verify_attestation/2` with
  the subject taken from the handle's `signing_identity/1` result, never from the option,
  so a handle cannot present another key's attestation. The protocol package checks the
  attestor's signature, the subject, that the attestor is not attesting its own key, that
  the attestation's window lies inside the attestor key's validity window, and that
  `now` falls in `[nbf, exp)`. This function then requires the attested role to be
  `"issuer"`. All of it happens before `sign/2` is called. Without the option, only the
  declaration gate applies.

  ## Parameters

    * `grant_input` — a map with `:issuer` (string), `:grant_id` (string), `:audiences`
      (a non-empty list of strings), `:issued_at`, `:not_before` and `:expires_at`
      (integers, Unix seconds), `:holder_thumbprint` (the holder key's raw 32-byte
      RFC 7638 thumbprint) and `:operations` (a non-empty list of
      `BoundedAuthorityProtocol.V1.Operation` structs). The protocol package checks the
      values: identifier grammar, a coherent time window, unique operation names.
    * `key_handle` — the issuer's handle; calls `signing_identity/1` and `sign/2`.
    * `opts` — a map or a keyword list (see "Options" in the module documentation):
      * `:bounds` — resource limits passed unchanged to the protocol package; default
        `%{}`, the protocol's maximums.
      * `:role_attestation` — `%{compact: binary(), attestor:
        BoundedAuthorityProtocol.V1.HistoricalPublicKey.t(), now: integer()}`: the
        attestation compact, the trusted attestor key with its validity window, and the
        evaluation time in Unix seconds (default `System.system_time(:second)`). `:now`
        is a trust input: it decides which instant the attestation must cover, so a
        caller that chooses a past `:now` accepts an attestation that has since expired.
        Given as a map or a keyword list; other keys in it are ignored.

  ## Errors

    * `:invalid_grant` — `grant_input` is not a map, a field is missing or of the wrong
      basic type (including an empty or improper `:audiences` list or an empty
      `:operations` list), or `opts` is invalid (see "Options" above).
    * `:invalid_key_handle` — the handle is not a `{module, term}` pair, has no
      `signing_identity/1`, declares a role other than `:issuer`, or returned a malformed
      snapshot or a public key the strict Ed25519 rule refuses.
    * `:invalid_role_attestation` — the option is malformed (including an explicit
      `nil`; refused before any callback), the protocol package rejected the attestation, or the attested role is not
      `"issuer"`.
    * `:signing_failed` — `sign/2` failed, returned something other than a 64-byte
      signature, or returned a signature that does not verify against the snapshot's
      public key.
    * `{:producer_error, :invalid}` — the protocol package refused the grant, for example
      an inverted time window or a `holder_thumbprint` that is not 32 bytes.

  ## Example

  ```elixir
  grant_input = %{
    issuer: "https://issuer.example",
    grant_id: "urn:example:grant:archive-2",
    audiences: ["https://records.example"],
    issued_at: now,
    not_before: now,
    expires_at: now + 3600,
    holder_thumbprint: holder_thumbprint,
    operations: [%V1.Operation{name: "archive_document", selectors: [:all]}]
  }

  {:ok, %{grant: new_grant}} = BoundedAuthorityReportAdapter.sign_grant(grant_input, issuer)

  {:ok, issuer_public_key} = MyApp.DevKey.public_key({:issuer, "issuer-key-1"})

  {:ok, _grant_facts} =
    V1.verify_grant(
      new_grant,
      %V1.TrustedIssuer{key_id: "issuer-key-1", public_key: issuer_public_key},
      %V1.ExpectedGrant{
        issuer: "https://issuer.example",
        audience: "https://records.example",
        evaluation_time: now,
        clock_skew: 60,
        bounds: V1.Bounds.maximum()
      }
    )

  BoundedAuthorityReportAdapter.sign_grant(grant_input, holder)
  #=> {:error, :invalid_key_handle}
  ```
  """
  @spec sign_grant(grant_input(), key_handle(), grant_opts() | keyword()) ::
          {:ok, grant_compact()} | {:error, grant_sign_error()}
  def sign_grant(grant_input, key_handle, opts \\ %{}) do
    Telemetry.sign_span(:grant, fn ->
      with {:ok, opts} <- normalize_opts(opts, :invalid_grant, :grant),
           do: do_sign_grant(grant_input, key_handle, opts)
    end)
  end

  # RA11 (ADR-0008; BAP 0.6.0 `bap-role-attestation/1`): the BA-attested role gate. A
  # SECOND sign-time gating verify — charter §3 as sharpened by ADR-0008 ("BARA does
  # sign-time gating verifies (wrong-key, role-attestation); it does not do content
  # verification"). The caller supplies the BA-signed attestation compact and the trusted
  # attestor context (the BA trust-root, `HistoricalPublicKey`); the EXPECTED subject
  # binding is the handle's atomic `signing_identity/1` snapshot — never caller input — so
  # a handle cannot present another key's attestation (the lying-handle defeat). BAP's
  # `verify_attestation/2` proves the BA signature, the subject binding, structural
  # self-attestation rejection, window containment, and the half-open now-window under the
  # caller's bounds; this gate adds the role check (the attested role must be "issuer").
  # Absent option: the declaration-only C1 gate stands unchanged. Any failure here — a
  # malformed option shape, a verify failure, a non-issuer role — is the single closed
  # `{:error, :invalid_role_attestation}`, fired BEFORE `sign/2` (the counting-handle
  # tripwire) and before any BAP producer call.
  # The gate reads the normalized options map, so a keyword list carries the option exactly
  # as a map does (a keyword list was once dropped by a normalizer default, which let a
  # holder-role attestation through: cross-vendor review B1). A map value of nil is
  # malformed, not absent; the option absent means the gate is off (the declaration-only
  # C1 gate stands).
  defp role_attestation_gate(opts, key_id, public_key, bounds) do
    case Map.fetch(opts, :role_attestation) do
      {:ok, attestation} -> run_role_attestation_gate(attestation, key_id, public_key, bounds)
      :error -> :ok
    end
  end

  defp run_role_attestation_gate(attestation, key_id, public_key, bounds) do
    with {:ok, {compact, expected}} <-
           expected_attestation(attestation, key_id, public_key, bounds),
         {:ok, %RoleAttestationV1.AttestationFacts{role: "issuer"}} <-
           RoleAttestationV1.verify_attestation(compact, expected) do
      :ok
    else
      _ -> {:error, :invalid_role_attestation}
    end
  end

  defp expected_attestation(attestation, key_id, public_key, bounds) do
    with true <- is_map(attestation),
         compact when is_binary(compact) <- Map.get(attestation, :compact),
         attestor <-
           Map.get(attestation, :attestor),
         true <- is_struct(attestor, BoundedAuthorityProtocol.V1.HistoricalPublicKey),
         now <- Map.get(attestation, :now, System.system_time(:second)),
         true <- is_integer(now) do
      {:ok,
       {compact,
        %RoleAttestationV1.ExpectedAttestation{
          attestor: attestor,
          subject_key_id: key_id,
          subject_public_key: public_key,
          now: now,
          bounds: bounds
        }}}
    else
      _ -> :error
    end
  end

  defp do_sign_grant(grant_input, key_handle, opts) do
    bounds = Map.get(opts, :bounds, %{})

    with {:ok, {key_id, public_key}} <- resolve_signing_identity(key_handle),
         :ok <- role_attestation_gate(opts, key_id, public_key, bounds),
         {:ok, grant} <- build_grant(grant_input, key_id),
         {:ok, signing_input} <- produce_grant_signing_input(grant, bounds),
         {:ok, grant_compact} <-
           sign_and_assemble(
             key_handle,
             signing_input,
             public_key,
             bounds,
             &assemble_standard_compact/3
           ) do
      {:ok, %{grant: grant_compact}}
    end
  end

  @doc """
  Signs a key transition: the retiring key's signed statement naming its successor.

  Returns `{:ok, %{key_transition: compact}}`. A verifier checks it with
  `BoundedAuthorityProtocol.V1.verify_key_transition/4`.

  The current (retiring) key's id and public key come from the handle's `key_identity/1`,
  read once; `:current_key_id` or `:current_public_key` in the input is ignored. The
  successor's id and public key come from the input. Like `sign_anchor/3`, this function
  checks no role: the signature by the current key is what makes the transition
  authentic, and the verifier decides whether it trusts that key.

  ## Parameters

    * `transition_input` — a map with `:transition_id` (string), `:chain_id` (string),
      `:effective_at` (integer, Unix seconds), `:next_key_id` (string) and
      `:next_public_key` (the successor's raw 32-byte Ed25519 public key).
    * `key_handle` — the current key's handle; calls `key_identity/1` and `sign/2`.
    * `opts` — a map or a keyword list (see "Options" in the module documentation) with
      `:bounds`, passed unchanged to the protocol package; default `%{}`.

  ## Errors

    * `:invalid_transition` — `transition_input` is not a map, a field is missing or of
      the wrong basic type, `:next_public_key` is not 32 bytes, or `opts` is invalid (see
      "Options" in the module documentation).
    * `:invalid_key_handle` — as for `sign_anchor/3`.
    * `:signing_failed` — as for `sign_report/3`.
    * `{:producer_error, :invalid}` — the protocol package refused the transition, for
      example a successor key equal to the current key.

  ## Example

  ```elixir
  current_key = {MyApp.DevKey, {:holder, "audit-chain-key-1"}}
  {:ok, next_public_key} = MyApp.DevKey.public_key({:holder, "audit-chain-key-2"})

  transition = %{
    transition_id: "urn:example:transition:audit-log-1",
    chain_id: "urn:example:chain:audit-log",
    effective_at: now,
    next_key_id: "audit-chain-key-2",
    next_public_key: next_public_key
  }

  {:ok, %{key_transition: _compact}} =
    BoundedAuthorityReportAdapter.sign_key_transition(transition, current_key)

  {:ok, current_public_key} = MyApp.DevKey.public_key({:holder, "audit-chain-key-1"})

  BoundedAuthorityReportAdapter.sign_key_transition(
    %{transition | next_public_key: current_public_key},
    current_key
  )
  #=> {:error, {:producer_error, :invalid}}
  ```
  """
  @spec sign_key_transition(transition_input(), key_handle(), transition_opts() | keyword()) ::
          {:ok, transition_compact()} | {:error, transition_sign_error()}
  def sign_key_transition(transition_input, key_handle, opts \\ %{}) do
    Telemetry.sign_span(:key_transition, fn ->
      with {:ok, opts} <- normalize_opts(opts, :invalid_transition, :key_transition),
           do: do_sign_key_transition(transition_input, key_handle, opts)
    end)
  end

  defp do_sign_key_transition(transition_input, key_handle, opts) do
    bounds = Map.get(opts, :bounds, %{})

    with {:ok, {current_key_id, current_public_key}} <- resolve_key_identity(key_handle),
         {:ok, transition} <-
           build_key_transition(transition_input, current_key_id, current_public_key),
         {:ok, signing_input} <- produce_key_transition_signing_input(transition, bounds),
         {:ok, compact} <-
           sign_and_assemble(
             key_handle,
             signing_input,
             current_public_key,
             bounds,
             &assemble_standard_compact/3
           ) do
      {:ok, %{key_transition: compact}}
    end
  end

  @doc """
  Signs a content assertion: a standalone statement binding the SHA-256 digest of exact
  content bytes to an issuer, an audience, a lineage subject, a semantic profile, a
  validity window and a predecessor.

  Returns `{:ok, %{content_assertion: compact}}`. A consumer checks it with
  `BoundedAuthorityProtocol.ContentAssertion.V1.verify_assertion/2`, supplying the
  trusted key, the expected context and the digest of the bytes it holds. The assertion
  grants nothing; it says only that this key signed this digest under these terms.

  The protected key id comes from the handle's `key_identity/1`, read once with the
  public key; an identity field in the input is ignored. This function does not read
  the content, interpret the profile, check a predecessor or consult a role. The
  protocol package checks the values (digest sizes, the first-in-lineage rule, the time
  window) when it produces the signing input.

  ## Parameters

    * `assertion_input` — a map with `:jti`, `:iss`, `:aud`, `:sub` and `:profile`
      (strings), `:profile_digest` and `:content_digest` (raw 32-byte SHA-256 digests;
      compute the content digest with
      `BoundedAuthorityProtocol.ContentAssertion.V1.content_digest/2`), `:gen` (the
      position in the lineage, 1 for the first), `:prev` (the previous assertion's
      digest, or 32 zero bytes when `gen` is 1), and `:iat`, `:nbf` and `:exp`
      (integers, Unix seconds).
    * `key_handle` — the signer's handle; calls `key_identity/1` and `sign/2`.
    * `opts` — a map or a keyword list with `:bounds`, passed unchanged to the protocol
      package; default `%{}`. Unlike the other entry points, any other `opts` value
      (including a struct) is an error.

  ## Errors

    * `:invalid_content_assertion` — `opts` is invalid (see "Options" in the module
      documentation), or `assertion_input` is not a map or has a field that is missing or of
      the wrong basic type.
    * `:invalid_key_handle` — as for `sign_anchor/3`.
    * `:signing_failed` — as for `sign_report/3`.
    * `{:producer_error, :invalid}` — the protocol package refused the assertion, for
      example a digest that is not 32 bytes, a nonzero `prev` at `gen: 1`, or an
      inverted window.

  ## Example

  ```elixir
  alias BoundedAuthorityProtocol.ContentAssertion

  {:ok, content_digest} = ContentAssertion.V1.content_digest("2026 field survey, final", %{})

  input = %{
    jti: "urn:example:assertion:survey-1",
    iss: "urn:example:research-group",
    aud: "urn:example:journal",
    sub: "urn:example:dataset:field-survey",
    profile: "urn:example:profile:survey/1",
    profile_digest: :crypto.hash(:sha256, "survey profile, version 1"),
    content_digest: content_digest,
    gen: 1,
    prev: <<0::256>>,
    iat: now,
    nbf: now,
    exp: now + 3600
  }

  signer = {MyApp.DevKey, {:holder, "research-key-1"}}

  {:ok, %{content_assertion: _compact}} =
    BoundedAuthorityReportAdapter.sign_content_assertion(input, signer)

  BoundedAuthorityReportAdapter.sign_content_assertion(input, signer, [:bounds])
  #=> {:error, :invalid_content_assertion}
  ```
  """
  @spec sign_content_assertion(
          content_assertion_input(),
          key_handle(),
          content_assertion_opts() | keyword()
        ) ::
          {:ok, content_assertion_compact()} | {:error, content_assertion_sign_error()}
  def sign_content_assertion(assertion_input, key_handle, opts \\ %{}) do
    Telemetry.sign_span(:content_assertion, fn ->
      with {:ok, opts} <- content_assertion_opts(opts),
           do: do_sign_content_assertion(assertion_input, key_handle, opts)
    end)
  end

  defp do_sign_content_assertion(assertion_input, key_handle, opts) do
    bounds = Map.get(opts, :bounds, %{})

    with {:ok, {key_id, public_key}} <- resolve_key_identity(key_handle),
         {:ok, assertion} <- build_content_assertion(assertion_input, key_id),
         {:ok, signing_input} <- produce_content_assertion_signing_input(assertion, bounds),
         {:ok, compact} <-
           sign_and_assemble(
             key_handle,
             signing_input,
             public_key,
             bounds,
             &ContentAssertionV1.assemble_compact/3
           ) do
      {:ok, %{content_assertion: compact}}
    end
  end

  defp content_assertion_opts(opts),
    do: normalize_opts(opts, :invalid_content_assertion, :content_assertion)

  # ---------------------------------------------------------------------------
  # The shared signing tail (the universal-companion primitive).
  #
  # sign_via_handle → verify_signature → assemble_compact. Every object this
  # library signs flows through here. verify_signature is the wrong-key guard
  # (the RA1 cross-vendor CV-finding): a signature that does not verify against
  # the resolved public key is :signing_failed, never a silent false-success.
  #
  # The assembler parameter selects BAP's compact assembler for the signing
  # input's profile — the standard kind goes to V1.assemble_compact/3, the
  # local-loopback kind to the profile's assemble_compact/3. BAP enforces the
  # pairing structurally (each assembler accepts exactly its own input kinds),
  # so a mis-wired pair fails closed as {:producer_error, :invalid} rather than
  # producing wrong-profile bytes.
  # ---------------------------------------------------------------------------

  @compile {:inline, assemble_standard_compact: 3}

  defp assemble_standard_compact(signing_input, signature, bounds) do
    BoundedAuthorityProtocol.V1.assemble_compact(signing_input, signature, bounds)
  end

  @spec sign_and_assemble(
          key_handle(),
          BoundedAuthorityProtocol.V1.SigningInput.t(),
          binary(),
          term(),
          (BoundedAuthorityProtocol.V1.SigningInput.t(), binary(), term() ->
             {:ok, binary()} | {:error, :invalid})
        ) :: {:ok, binary()} | {:error, :signing_failed | {:producer_error, :invalid}}

  defp sign_and_assemble(key_handle, signing_input, public_key, bounds, assembler)
       when is_function(assembler, 3) do
    with {:ok, signature} <- sign_via_handle(key_handle, signing_input.message),
         :ok <- verify_signature(signing_input.message, signature, public_key) do
      case assembler.(signing_input, signature, bounds) do
        {:ok, compact} -> {:ok, compact}
        {:error, :invalid} -> {:error, {:producer_error, :invalid}}
      end
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
  #
  # The check is BAP's strict rule S1 (`BoundedAuthorityProtocol.Ed25519.verify_strict/3`),
  # not the raw backend: a cofactorless backend accepts a signature whose `R` is a small-order
  # point (the nonce `r = 0` signature `R = identity` under a genuine key), which no verifier
  # under S1 accepts. A signature this library returns therefore verifies under S1.
  defp verify_signature(message, signature, holder_public_key)
       when is_binary(message) and is_binary(signature) and is_binary(holder_public_key) do
    if BoundedAuthorityProtocol.Ed25519.verify_strict(message, signature, holder_public_key),
      do: :ok,
      else: {:error, :signing_failed}
  end

  defp verify_signature(_message, _signature, _public_key), do: {:error, :signing_failed}

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

  # The mixed-major fail-fast, v1 direction (ADR-0021 Decision 8): a v1
  # proof pairs with a v1 grant, and BAP's proof producer only hashes
  # grant_compact — without this gate a v2 or v3 grant would pass through
  # into an envelope no verifier accepts. The gate is the major's own
  # bounded DECODER, not the header walk: v1 and v2 grants share the EdDSA
  # header, so the major is only distinguishable in the payload's `v` claim,
  # which the closed v1 decode rejects on mismatch (cross-vendor code
  # review, B2). Anything but a v1 grant fails HERE as :invalid_report, per
  # this repo's fail-fast principle. This is the ONE deliberate behavior
  # change on the major-1 surface (previously such an envelope failed
  # downstream at check_envelope/2).
  defp matching_grant_major(grant_compact) do
    case BoundedAuthorityProtocol.V1.decode_grant(grant_compact, %{}) do
      {:ok, _decoded_grant} -> :ok
      {:error, :invalid} -> {:error, :invalid_report}
    end
  end

  # The local-loopback report: the SAME field checks as validate_report/1 (the
  # shared helpers carry every invariant), plus the profile's ONE divergence —
  # the nonce is REQUIRED (nil is fine on the standard profile, which treats it
  # as optional; the loopback profile's replay defense assumes it). Presence +
  # shape here; profile semantics + bounds stay BAP's at produce time.
  defp validate_local_loopback_report(report) when is_map(report) do
    with {:ok, report} <- validate_report(report),
         :ok <- require_non_empty_nonce(report.nonce) do
      {:ok, report}
    end
  end

  defp validate_local_loopback_report(_report), do: {:error, :invalid_report}

  defp require_non_empty_nonce(nonce) when is_binary(nonce) and byte_size(nonce) > 0, do: :ok

  defp require_non_empty_nonce(_nonce), do: {:error, :invalid_report}

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
        accept_key(public_key)

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
        with {:ok, public_key} <- accept_key(public_key), do: {:ok, {key_id, public_key}}

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
        with {:ok, public_key} <- accept_key(public_key), do: {:ok, {key_id, public_key}}

      _holder_role_or_malformed_or_unimplemented ->
        {:error, :invalid_key_handle}
    end
  end

  defp resolve_signing_identity(_handle), do: {:error, :invalid_key_handle}

  # Every Ed25519 key a handle presents passes BAP's key acceptance (rule S1): canonical,
  # not small-order, on the curve. A handle presenting the identity point, a point of order
  # 2, 4 or 8, a `y >= p` alias or an off-curve string is refused as the same closed
  # `:invalid_key_handle` a malformed key gets, BEFORE `sign/2` is reached. Without this gate
  # `sign_grant/3` and `sign_content_assertion/3` (whose structs carry no key, so no BAP
  # producer ever sees it) would sign under such a key. ES256 keys take the `V3` resolvers,
  # where P-256 point validation already applies.
  defp accept_key(public_key) do
    if BoundedAuthorityProtocol.Ed25519.acceptable_public_key?(public_key),
      do: {:ok, public_key},
      else: {:error, :invalid_key_handle}
  end

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

  # The local-loopback profile's producer — the same fold, through the profile
  # facade. Admission (canonical literal-loopback URI) and the profile's
  # mandatory-nonce semantics are enforced HERE, in BAP, by delegation — this
  # library passes the caller's target_uri through unchanged.
  defp produce_local_loopback_signing_input(proof, bounds) do
    case LocalLoopbackHttp.proof_signing_input(proof, bounds) do
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

  # The transition's content is validated for presence + shape HERE (clean :invalid_transition
  # on a missing/malformed field; next_public_key is pre-checked for 32 bytes — design Q7: the
  # adapter pre-checks PUBLIC KEYS for 32 bytes, the way resolve_public_key/1 +
  # resolve_key_identity/1 do; digests like grant's holder_thumbprint defer to BAP). BAP's
  # producer validates SEMANTICS — identifier grammar, time bounds, and distinct_fingerprints
  # (a self-transition where next_public_key == current_public_key surfaces here as
  # {:producer_error, :invalid}). current_{key_id, public_key} come from the handle's atomic
  # key_identity/1 snapshot (the _current_* params), so a caller :current_key_id /
  # :current_public_key smuggled into the map is silently ignored (ADR-0006 decision 3).
  defp build_key_transition(transition_input, current_key_id, current_public_key)
       when is_map(transition_input) do
    with {:ok, transition_id} <- required_transition_binary(transition_input, :transition_id),
         {:ok, chain_id} <- required_transition_binary(transition_input, :chain_id),
         {:ok, effective_at} <- required_transition_integer(transition_input, :effective_at),
         {:ok, next_key_id} <- required_transition_binary(transition_input, :next_key_id),
         {:ok, next_public_key} <- required_transition_public_key(transition_input) do
      {:ok,
       %BoundedAuthorityProtocol.V1.KeyTransition{
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

  # next_public_key is a raw 32-byte Ed25519 public key (the successor). Pre-checked HERE
  # (fail-fast :invalid_transition) rather than deferred to BAP's producer — public keys get
  # the adapter's 32-byte guard (design Q7 principle).
  defp required_transition_public_key(transition_input) do
    case Map.fetch(transition_input, :next_public_key) do
      {:ok, value} when is_binary(value) and byte_size(value) == 32 -> {:ok, value}
      _ -> {:error, :invalid_transition}
    end
  end

  defp produce_key_transition_signing_input(transition, bounds) do
    case BoundedAuthorityProtocol.V1.key_transition_signing_input(transition, bounds) do
      {:ok, signing_input} -> {:ok, signing_input}
      {:error, :invalid} -> {:error, {:producer_error, :invalid}}
    end
  end

  defp build_content_assertion(input, key_id) when is_map(input) do
    binary_fields = [:jti, :iss, :aud, :sub, :profile, :profile_digest, :content_digest, :prev]
    integer_fields = [:gen, :iat, :nbf, :exp]

    if Enum.all?(binary_fields, &is_binary(Map.get(input, &1))) and
         Enum.all?(integer_fields, &is_integer(Map.get(input, &1))) do
      {:ok,
       %ContentAssertionV1.ContentAssertion{
         attestor_key_id: key_id,
         jti: input.jti,
         iss: input.iss,
         aud: input.aud,
         sub: input.sub,
         profile: input.profile,
         profile_digest: input.profile_digest,
         content_digest: input.content_digest,
         gen: input.gen,
         prev: input.prev,
         iat: input.iat,
         nbf: input.nbf,
         exp: input.exp
       }}
    else
      {:error, :invalid_content_assertion}
    end
  end

  defp build_content_assertion(_input, _key_id), do: {:error, :invalid_content_assertion}

  defp produce_content_assertion_signing_input(assertion, bounds) do
    case ContentAssertionV1.assertion_signing_input(assertion, bounds) do
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

  # Options at the boundary (BoundedAuthorityReportAdapter.Options), before any callback: a
  # plain map or a keyword list with only the keys this kind of entry point accepts, each
  # with a value of the right kind. Anything else is the entry point's closed input error;
  # a malformed :role_attestation value is :invalid_role_attestation.
  defp normalize_opts(opts, input_error, object) do
    case Options.normalize(opts, Options.schema(object)) do
      {:ok, opts} -> {:ok, opts}
      {:error, :role_attestation} -> {:error, :invalid_role_attestation}
      {:error, _option} -> {:error, input_error}
    end
  end

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
  Signs `message` with the handle's private key and returns the raw 64-byte signature.

  Under this module's entry points the signature is Ed25519. Under
  `BoundedAuthorityReportAdapter.V3` it is ES256 in the raw `r || s` form of RFC 7518
  §3.4: two 32-byte big-endian integers. A DER-encoded ECDSA signature (what
  `:crypto.sign/4` returns) is refused, so convert it first; a high-S signature is
  accepted and converted to low-S.

  The adapter checks the returned signature against the handle's public key before it
  uses it. Any return other than `{:ok, <<_::512>>}` is `{:error, :signing_failed}`.
  """
  @callback sign(message :: binary(), handle :: term()) ::
              {:ok, binary()} | {:error, term()}

  @doc """
  Returns the handle's public key: a raw 32-byte Ed25519 key under this module's entry
  points, or a 65-byte uncompressed SEC1 P-256 point (`0x04 || x || y`) under
  `BoundedAuthorityReportAdapter.V3`. The key's shape selects the surface: each surface
  accepts its own shape and refuses the other.

  An Ed25519 key must also pass the protocol's strict acceptance rule
  (`BoundedAuthorityProtocol.Ed25519.acceptable_public_key?/1`): a canonical encoding of a
  point on the curve that is not one of the eight small-order points. A P-256 key must be
  on the curve. Any other key is refused with `{:error, :invalid_key_handle}` before
  `sign/2` is called. The same rules apply to the keys `key_identity/1` and
  `signing_identity/1` return.
  """
  @callback public_key(handle :: term()) :: {:ok, binary()} | {:error, term()}

  @doc """
  Returns the RFC 7638 thumbprint of the handle's public key, as the raw 32-byte SHA-256
  digest: over the OKP members (`{"crv":"Ed25519","kty":"OKP","x":X}`) for an Ed25519
  key, or the EC members (`{"crv":"P-256","kty":"EC","x":X,"y":Y}`) for a P-256 key. An
  issuer puts this value in a grant's `cnf.jkt`.

  No entry point calls this callback. It lets callers check a handle against a grant, and
  `mix bounded_authority_report_adapter.doctor` checks it against `public_key/1`. Compute
  it with the protocol package's `BoundedAuthorityProtocol.V1.Jwk.encode_public/2` and
  `BoundedAuthorityProtocol.V1.Jwk.thumbprint/2` (or the `BoundedAuthorityProtocol.V3.EcJwk`
  pair for P-256), and decode the base64url result.
  """
  @callback thumbprint(handle :: term()) :: {:ok, binary()} | {:error, term()}

  @doc """
  Returns the key's registry id and its public key, `{key_id, public_key}`, from one
  read. The key id must be a non-empty string; the public key follows the rules of
  `c:public_key/1`.

  Optional. `sign_anchor/3`, `sign_key_transition/3` and `sign_content_assertion/3`
  require it, and refuse a handle without it with `{:error, :invalid_key_handle}`.
  Return both values from one read of your key store: a handle that reads them
  separately can return the id of one key version and the public key of the next.
  """
  @callback key_identity(handle :: term()) ::
              {:ok, {key_id :: binary(), public_key :: binary()}} | {:error, term()}

  @doc """
  Returns the key's declared role, registry id and public key,
  `{role, key_id, public_key}`, from one read. The role is `:issuer` or `:holder`.

  Optional. Only `sign_grant/3` requires it, and it signs only when the role is
  `:issuer`; a handle without this callback, or one that declares `:holder`, gets
  `{:error, :invalid_key_handle}` before `sign/2` is called. The adapter cannot check that
  the declaration is true; see `sign_grant/3` for what the gate does and does not
  guarantee.
  """
  @callback signing_identity(handle :: term()) ::
              {:ok, {:issuer | :holder, key_id :: binary(), public_key :: binary()}}
              | {:error, term()}

  @optional_callbacks [key_identity: 1, signing_identity: 1]
end
