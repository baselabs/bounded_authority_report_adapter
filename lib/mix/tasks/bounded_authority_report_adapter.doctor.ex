defmodule Mix.Tasks.BoundedAuthorityReportAdapter.Doctor do
  @shortdoc "Preflight-checks a key-handle module against the adapter's contract"

  @moduledoc """
  Preflight-checks a key-handle module against the adapter's behaviour contract.

      mix bounded_authority_report_adapter.doctor --handle MyApp.HolderKey [--ref term] [--live] [--major 1|3]

  The adapter has two suite surfaces (ADR-0021): the major-1 surface
  (`BoundedAuthorityReportAdapter`, Ed25519, 32-byte keys) and the major-3
  surface (`BoundedAuthorityReportAdapter.V3`, `ES256`, 65-byte
  uncompressed-SEC1 P-256 keys). The doctor accepts a valid key of EITHER
  shape by default; pass `--major 1` or `--major 3` to apply that surface's
  strict key-type gate as a fatal (with a confirming advisory when the key
  matches).

  FATAL (non-zero exit):

    * the module is not loaded / does not exist;
    * `sign/2`, `public_key/1`, or `thumbprint/1` is missing;
    * `public_key/1` returns neither a 32-byte Ed25519 key nor a valid
      65-byte on-curve P-256 point for the supplied ref (with `--major`,
      a valid key of the WRONG type for that major is fatal too);
    * `thumbprint/1` disagrees with the RFC 7638 digest derived from
      `public_key/1` (the OKP preimage for Ed25519 keys, the EC preimage
      for P-256 keys) — the issuer mints `cnf.jkt` from that digest, so a
      mismatched implementation fails every envelope at verification.

  ADVISORY (reported, exit stays zero if nothing fatal):

    * `key_identity/1` absent — blocks `sign_anchor/3` + `sign_key_transition/3`;
    * `signing_identity/1` absent — blocks `sign_grant/3`;
    * with `--ref` + `--live`: a synthetic-message `sign/2` probe whose
      signature does not verify against `public_key/1`'s key (the same
      wrong-key guard the adapter enforces on every real sign; the probe
      verifies with the key's own suite algorithm). The probe signs a
      DOCTOR-GENERATED synthetic message only — never caller data. For a
      P-256 handle, a high-S probe return is its own advisory: the adapter
      normalizes it (the low-S producer duty is the adapter's, per ADR-0021
      Decision 4), but a custodian that can emit low-S directly should.

  `--ref` is an Elixir term, evaluated in the doctor's VM (`--ref "{:demo, 1}"`) —
  a dev-tool affordance over your own configuration, nothing more. Read/probe
  only: the doctor never writes, never configures, and never signs caller
  material.
  """

  use Mix.Task

  alias BoundedAuthorityProtocol.V1
  alias BoundedAuthorityProtocol.V3

  @required_callbacks [sign: 2, public_key: 1, thumbprint: 1]

  @synthetic_probe_message "bounded-authority-report-adapter doctor synthetic probe"

  @valid_majors [1, 3]

  @impl Mix.Task
  def run(args) do
    {opts, _parsed, invalid} =
      OptionParser.parse(args,
        strict: [handle: :string, ref: :string, live: :boolean, major: :integer]
      )

    with :ok <- reject_invalid_options(invalid),
         {:ok, module} <- fetch_module(opts),
         {:ok, major} <- fetch_major(opts),
         ref <- fetch_ref(opts) do
      report = check(module, ref, Keyword.get(opts, :live, false), major)
      report_and_exit(report, module, ref, major)
    else
      {:error, line} ->
        Mix.shell().error("[FATAL] #{line}")
        exit({:shutdown, 1})
    end
  end

  defp report_and_exit(report, module, ref, major) do
    for line <- report.fatals, do: Mix.shell().error("[FATAL] #{line}")
    for line <- report.advisories, do: Mix.shell().info("[advisory] #{line}")
    print_default_shape_line(report, module, ref, major)
    verdict(report)
  end

  defp print_default_shape_line(_report, _module, _ref, major) when major in [1, 3], do: :ok

  defp print_default_shape_line(%{fatals: []}, module, ref, nil) do
    case shape_report(module, ref, nil) do
      nil -> :ok
      line -> Mix.shell().info("[info] #{line}")
    end
  end

  defp print_default_shape_line(_report, _module, _ref, _major), do: :ok

  defp verdict(%{fatals: fatals}) when fatals != [] do
    Mix.shell().error("doctor: #{length(fatals)} fatal finding(s) — fix before wiring")
    exit({:shutdown, 1})
  end

  defp verdict(%{advisories: advisories}) when advisories != [] do
    Mix.shell().info("doctor: no fatal findings; #{length(advisories)} advisory note(s)")
  end

  defp verdict(_clean) do
    Mix.shell().info("doctor: clean")
  end

  @doc """
  The pure preflight over a loaded handle module. Returns `%{fatals: [String.t()],
  advisories: [String.t()]}` — no printing, no exits, no side effects beyond the
  callbacks it probes.
  """
  @spec check(module(), term(), boolean()) :: %{fatals: [String.t()], advisories: [String.t()]}
  def check(module, ref, live?), do: check(module, ref, live?, nil)

  @doc """
  The pure preflight with an optional strict major gate (`1` or `3`): the
  default accepts either valid key shape and reports which surfaces it
  unlocks; a major applies that surface's key-type gate as a fatal.
  """
  @spec check(module(), term(), boolean(), 1 | 3 | nil) :: %{
          fatals: [String.t()],
          advisories: [String.t()]
        }

  def check(module, ref, live?, major) do
    {thumbprint_fatal_list, thumbprint_advisory_list} = thumbprint_findings(module, ref)
    fatals = fatals(module, ref, major) ++ thumbprint_fatal_list
    advisories = thumbprint_advisory_list ++ advisories(module)

    advisories =
      cond do
        not live? ->
          shape_advisory(module, ref, major) ++ advisories

        fatals != [] ->
          ["--live skipped: fatal findings above" | advisories]

        true ->
          live_probe_advisories(module, ref) ++ shape_advisory(module, ref, major) ++ advisories
      end

    %{fatals: fatals, advisories: advisories}
  end

  defp fatals(module, ref, major) do
    module_fatals(module) ++ callback_fatals(module) ++ public_key_fatals(module, ref, major)
  end

  defp module_fatals(module) do
    if Code.ensure_loaded?(module) do
      []
    else
      ["handle module #{inspect(module)} is not loaded / does not exist"]
    end
  end

  defp callback_fatals(module) do
    if Code.ensure_loaded?(module) do
      for {name, arity} <- @required_callbacks,
          not function_exported?(module, name, arity),
          do: "missing required callback #{name}/#{arity}"
    else
      # Every callback check is vacuous against an unloaded module.
      []
    end
  end

  # The key-type gate: only meaningful once public_key/1 exists. A key valid
  # for NEITHER shape is always fatal; with --major, a valid key of the wrong
  # type for that major is fatal too (ADR-0021 Decision 2).
  defp public_key_fatals(module, ref, major) do
    if Code.ensure_loaded?(module) and function_exported?(module, :public_key, 1) do
      case safe_call(module, :public_key, [ref]) do
        {:ok, key} -> key_shape_fatals(key, major)
        normal when not is_tuple(normal) or elem(normal, 0) != :ok -> unwrapped_fatal(normal)
        _error -> ["public_key/1 rejected or exited for the supplied ref"]
      end
    else
      []
    end
  end

  defp key_shape_fatals(key, major) do
    case classify_public_key(key) do
      {:ed25519, _} ->
        if major == 3, do: [wrong_type_fatal(3, "a 32-byte Ed25519 key")], else: []

      {:p256, _} ->
        if major == 1, do: [wrong_type_fatal(1, "a 65-byte P-256 point")], else: []

      :invalid ->
        [
          "public_key/1 must return a 32-byte Ed25519 public key or a valid " <>
            "65-byte on-curve P-256 point (0x04 || x || y) for the supplied ref, " <>
            "got #{redact(key)}"
        ]
    end
  end

  defp unwrapped_fatal(normal) do
    [
      "public_key/1 returned #{redact(normal)} — the contract is " <>
        "{:ok, public_key}, and the adapter rejects unwrapped returns"
    ]
  end

  defp wrong_type_fatal(major, got) do
    "wrong key type for --major #{major}: got #{got}; that surface's entry " <>
      "points accept only their own suite's key shape (ADR-0021)"
  end

  # The thumbprint-match gate: the issuer mints cnf.jkt from the RFC 7638
  # digest over the SUITE'S preimage, so a thumbprint implementation that
  # hashes anything else fails every envelope at verification with no
  # producer-side catch. Returns {fatals, advisories}: a REJECTED/raised
  # thumbprint callback is fatal (swallowing it made the check vacuously
  # clean); a mismatch is fatal only for a STABLE key — a stateful handle
  # that rotated between the two calls reports an inconclusive rotation
  # advisory instead (cross-vendor code review, B2).
  defp thumbprint_findings(module, ref) do
    if Code.ensure_loaded?(module) and function_exported?(module, :public_key, 1) and
         function_exported?(module, :thumbprint, 1) do
      with {:ok, key} <- safe_call(module, :public_key, [ref]),
           {:ok, expected} <- expected_thumbprint(key),
           thumbprint_result <- safe_call(module, :thumbprint, [ref]) do
        thumbprint_verdict(module, ref, key, expected, thumbprint_result)
      else
        # The key-shape failure is already reported by the shape gate above.
        _ -> {[], []}
      end
    else
      {[], []}
    end
  end

  defp thumbprint_verdict(_module, _ref, _key, expected, {:ok, actual})
       when actual == expected,
       do: {[], []}

  defp thumbprint_verdict(module, ref, key, _expected, {:ok, _mismatch}),
    do: rotation_aware_mismatch(module, ref, key)

  defp thumbprint_verdict(_module, _ref, _key, _expected, _thumbprint_failed) do
    {[
       "thumbprint/1 rejected, raised, or exited for the supplied ref — the " <>
         "callback must return the RFC 7638 digest"
     ], []}
  end

  defp rotation_aware_mismatch(module, ref, key) do
    case safe_call(module, :public_key, [ref]) do
      {:ok, ^key} ->
        {[
           "thumbprint/1 does not match the RFC 7638 digest derived from public_key/1 " <>
             "(the suite's preimage: OKP members for Ed25519 keys, EC members for P-256 " <>
             "keys) — the issuer's cnf.jkt is minted from that digest, so a mismatched " <>
             "implementation fails every envelope at verification"
         ], []}

      _rotated ->
        {[],
         [
           "public_key/1 changed between samples — the handle rotated during the " <>
             "preflight; the thumbprint comparison is inconclusive (not a defect)"
         ]}
    end
  end

  defp expected_thumbprint(key) do
    case classify_public_key(key) do
      {:ed25519, pub} -> V1.Jwk.public_key_thumbprint_raw(pub, %{})
      {:p256, pub} -> ec_thumbprint_raw(pub)
      :invalid -> :error
    end
  end

  defp ec_thumbprint_raw(pub) do
    with {:ok, preimage} <- V3.EcJwk.encode_public(pub, %{}) do
      {:ok, :crypto.hash(:sha256, preimage)}
    end
  end

  # Shape classification — the doctor's mirror of the adapter's resolver
  # discrimination (diagnostics infer the suite from the key's wire shape;
  # defensible because a report is not wire bytes — ADR-0021's rejected-
  # alternative note). P-256 validation is BAP's certified arithmetic.
  defp classify_public_key(key) when is_binary(key) and byte_size(key) == 32,
    do: {:ed25519, key}

  defp classify_public_key(key) when is_binary(key) and byte_size(key) == 65 do
    case V3.EcJwk.encode_public(key, %{}) do
      {:ok, _certified_jwk} -> {:p256, key}
      {:error, :invalid} -> :invalid
    end
  end

  defp classify_public_key(_other), do: :invalid

  defp advisories(module) do
    if Code.ensure_loaded?(module) do
      blocked = [
        {{:key_identity, 1}, "blocks sign_anchor/3 and sign_key_transition/3"},
        {{:signing_identity, 1}, "blocks sign_grant/3"}
      ]

      for {{name, arity}, consequence} <- blocked,
          not function_exported?(module, name, arity),
          do: "#{name}/#{arity} absent — #{consequence}"
    else
      []
    end
  end

  # Which surface the found key unlocks — reported under --major (the caller
  # asked about a specific surface; this confirms the gate applied). A --major
  # MISMATCH already red the fatal above; default mode stays silent so a
  # fully-wired handle of either type still reports clean.
  defp shape_advisory(_module, _ref, nil), do: []

  defp shape_advisory(module, ref, major) when major in [1, 3] do
    case shape_report(module, ref, major) do
      nil -> []
      line -> [line]
    end
  end

  @doc """
  The key-type report line for the handle's resolved key (nil when the key
  shape is invalid or does not match the requested `major`). `run/1` prints
  it in default mode as info; the pure `check/4` carries it as an advisory
  only under `--major`, so a fully-wired handle of either type still
  reports clean.
  """
  @spec shape_report(module(), term(), 1 | 3 | nil) :: String.t() | nil

  def shape_report(module, ref, major) do
    with {:ok, key} <- safe_call(module, :public_key, [ref]),
         {:ok, line} <- shape_line(key, major) do
      line
    else
      _ -> nil
    end
  end

  defp shape_line(key, major) do
    case classify_public_key(key) do
      {:ed25519, _} when major in [nil, 1] ->
        {:ok,
         "key type: Ed25519 (32-byte) — unlocks the major-1 surface " <>
           "(BoundedAuthorityReportAdapter); the V3 surface requires a P-256 key"}

      {:p256, _} when major in [nil, 3] ->
        {:ok,
         "key type: P-256 (65-byte, on-curve) — unlocks the major-3 surface " <>
           "(BoundedAuthorityReportAdapter.V3, ES256); the major-1 surface requires " <>
           "an Ed25519 key"}

      _ ->
        :error
    end
  end

  # The wrong-key probe: sign a DOCTOR-GENERATED synthetic message and verify
  # the signature against public_key/1's key with the KEY'S OWN suite
  # algorithm — the adapter's own guard, checked before the first real
  # signing call ever happens.
  defp live_probe_advisories(module, ref) do
    with {:ok, public_key} <- safe_call(module, :public_key, [ref]),
         classified when is_tuple(classified) <- classify_public_key(public_key),
         {:ok, signature} when is_binary(signature) and byte_size(signature) == 64 <-
           safe_call(module, :sign, [@synthetic_probe_message, ref]),
         {:ok, high_s?} <-
           probe_verdict(classified, @synthetic_probe_message, signature) do
      if high_s?,
        do: [
          "--live probe: sign/2 returns a HIGH-S spelling — the adapter normalizes it " <>
            "(the low-S producer duty is the adapter's, ADR-0021 Decision 4), but a " <>
            "custodian that can emit low-S directly should"
        ],
        else: []
    else
      _ ->
        [
          "--live probe: sign/2 against public_key/1 failed the wrong-key verify " <>
            "(the adapter maps this to :signing_failed on every real sign)"
        ]
    end
  end

  # {:ok, high_s?} on a verified probe; :error (the wrong-key advisory) on any
  # rejection or backend raise — the doctor's mirror of the adapter's v3 tail.
  defp probe_verdict({:ed25519, public_key}, message, signature) do
    if :crypto.verify(:eddsa, :none, message, signature, [public_key, :ed25519]) do
      {:ok, false}
    else
      :error
    end
  rescue
    _backend_failure -> :error
  catch
    _kind, _reason -> :error
  end

  defp probe_verdict({:p256, public_key}, message, signature) do
    with :ok <- probe_canonical(signature),
         true <-
           :crypto.verify(
             :ecdsa,
             :sha256,
             message,
             der_signature(signature),
             [public_key, :prime256v1]
           ) do
      {:ok, probe_high_s?(signature)}
    else
      _ -> :error
    end
  rescue
    _backend_failure -> :error
  catch
    _kind, _reason -> :error
  end

  @ec_n 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
  @ec_half_n div(@ec_n, 2)

  # The probe accepts any VALID spelling (high or low S) — it reports high-S
  # as an advisory rather than a failure, because the adapter normalizes.
  defp probe_canonical(<<r::binary-32, s::binary-32>>) do
    ri = :binary.decode_unsigned(r)
    si = :binary.decode_unsigned(s)

    if ri > 0 and ri < @ec_n and si > 0 and si < @ec_n,
      do: :ok,
      else: :error
  end

  defp probe_canonical(_), do: :error

  defp probe_high_s?(<<_r::binary-32, s::binary-32>>),
    do: :binary.decode_unsigned(s) > @ec_half_n

  # Minimal-octet DER for the ECDSA backend (an internal spelling only; same
  # construction the adapter's v3 tail uses).
  defp der_signature(<<r::binary-32, s::binary-32>>) do
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

  defp trim_leading_zeros(<<0, rest::binary>>, acc) when acc < 31,
    do: trim_leading_zeros(rest, acc + 1)

  defp trim_leading_zeros(bytes, _acc) when bytes != <<>>,
    do: bytes

  defp der_length(len) when len < 128, do: <<len>>

  # Shape-only redaction for fatal messages: never print the value a
  # misconfigured handle returned — it may be key material.
  defp redact(value) when is_binary(value), do: "a #{byte_size(value)}-byte binary"
  defp redact(value) when is_list(value), do: "a list"
  defp redact(value) when is_map(value), do: "a map"
  defp redact(value) when is_atom(value), do: "the atom #{inspect(value)}"
  defp redact(value) when is_integer(value), do: "the integer #{value}"
  defp redact(_value), do: "an unprintable term"

  defp safe_call(module, fun, args) do
    apply(module, fun, args)
  rescue
    _exception -> {:error, :doctor_probe_raised}
  catch
    _kind, _reason -> {:error, :doctor_probe_exited}
  end

  defp fetch_module(opts) do
    case Keyword.fetch(opts, :handle) do
      {:ok, name} -> {:ok, Module.concat([name])}
      :error -> {:error, "--handle <Module> is required"}
    end
  end

  # Malformed flags (e.g. --major bogus, --major 3.0, a bare --major) must
  # be fatal usage errors, not silently dropped to the permissive default
  # (cross-vendor code review, B2).
  defp reject_invalid_options([]), do: :ok

  defp reject_invalid_options(invalid) do
    {:error, "unrecognized or malformed option(s): #{inspect(invalid)}"}
  end

  defp fetch_major(opts) do
    case Keyword.get(opts, :major) do
      nil -> {:ok, nil}
      major when major in @valid_majors -> {:ok, major}
      _invalid -> {:error, "--major must be 1 or 3"}
    end
  end

  defp fetch_ref(opts) do
    case Keyword.fetch(opts, :ref) do
      {:ok, term} ->
        {ref, _binding} = Code.eval_string(term)
        ref

      :error ->
        :doctor_ref
    end
  end
end
