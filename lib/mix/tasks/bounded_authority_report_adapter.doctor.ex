defmodule Mix.Tasks.BoundedAuthorityReportAdapter.Doctor do
  @shortdoc "Preflight-checks a key-handle module against the adapter's contract"

  @moduledoc """
  Preflight-checks a key-handle module against the adapter's behaviour contract.

      mix bounded_authority_report_adapter.doctor --handle MyApp.HolderKey [--ref term] [--live]

  FATAL (non-zero exit):

    * the module is not loaded / does not exist;
    * `sign/2`, `public_key/1`, or `thumbprint/1` is missing;
    * `public_key/1` returns something other than a 32-byte Ed25519 public key
      for the supplied ref.

  ADVISORY (reported, exit stays zero if nothing fatal):

    * `key_identity/1` absent — blocks `sign_anchor/3` + `sign_key_transition/3`;
    * `signing_identity/1` absent — blocks `sign_grant/3`;
    * with `--ref` + `--live`: a synthetic-message `sign/2` probe whose signature
      does not verify against `public_key/1`'s key (the same wrong-key guard the
      adapter enforces on every real sign). The probe signs a DOCTOR-GENERATED
      synthetic message only — never caller data.

  `--ref` is an Elixir term, evaluated in the doctor's VM (`--ref "{:demo, 1}"`) —
  a dev-tool affordance over your own configuration, nothing more. Read/probe
  only: the doctor never writes, never configures, and never signs caller
  material.
  """

  use Mix.Task

  @required_callbacks [sign: 2, public_key: 1, thumbprint: 1]

  @synthetic_probe_message "bounded-authority-report-adapter doctor synthetic probe"

  @impl Mix.Task
  def run(args) do
    {opts, _parsed, _invalid} =
      OptionParser.parse(args, strict: [handle: :string, ref: :string, live: :boolean])

    with {:ok, module} <- fetch_module(opts),
         ref <- fetch_ref(opts) do
      report = check(module, ref, Keyword.get(opts, :live, false))

      for line <- report.fatals, do: Mix.shell().error("[FATAL] #{line}")
      for line <- report.advisories, do: Mix.shell().info("[advisory] #{line}")

      cond do
        report.fatals != [] ->
          Mix.shell().error(
            "doctor: #{length(report.fatals)} fatal finding(s) — fix before wiring"
          )

          exit({:shutdown, 1})

        report.advisories != [] ->
          Mix.shell().info(
            "doctor: no fatal findings; #{length(report.advisories)} advisory note(s)"
          )

        true ->
          Mix.shell().info("doctor: clean")
      end
    else
      {:error, line} ->
        Mix.shell().error("[FATAL] #{line}")
        exit({:shutdown, 1})
    end
  end

  @doc """
  The pure preflight over a loaded handle module. Returns `%{fatals: [String.t()],
  advisories: [String.t()]}` — no printing, no exits, no side effects beyond the
  callbacks it probes.
  """
  @spec check(module(), term(), boolean()) :: %{fatals: [String.t()], advisories: [String.t()]}
  def check(module, ref, live?) do
    fatals = fatals(module, ref)
    advisories = advisories(module)

    advisories =
      if live? and fatals == [] do
        live_probe_advisory(module, ref) ++ advisories
      else
        if live?, do: ["--live skipped: fatal findings above" | advisories], else: advisories
      end

    %{fatals: fatals, advisories: advisories}
  end

  defp fatals(module, ref) do
    module_fatals(module) ++ callback_fatals(module) ++ public_key_fatals(module, ref)
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

  # The 32-byte public-key gate: only meaningful once public_key/1 exists.
  defp public_key_fatals(module, ref) do
    if Code.ensure_loaded?(module) and function_exported?(module, :public_key, 1) do
      case safe_call(module, :public_key, [ref]) do
        {:ok, key} when is_binary(key) and byte_size(key) == 32 ->
          []

        {:ok, other} ->
          # Redacted by shape, never by value: the misconfiguration class here
          # is a handle wired to the wrong custody slot, and the value could be
          # private-key material destined for CI logs.
          [
            "public_key/1 must return a 32-byte Ed25519 public key for the supplied " <>
              "ref, got #{redact(other)}"
          ]

        normal when not is_tuple(normal) or elem(normal, 0) != :ok ->
          [
            "public_key/1 returned #{redact(normal)} — the contract is " <>
              "{:ok, public_key}, and the adapter rejects unwrapped returns"
          ]

        _error ->
          ["public_key/1 rejected or exited for the supplied ref"]
      end
    else
      []
    end
  end

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

  # The wrong-key probe: sign a DOCTOR-GENERATED synthetic message and verify
  # the signature against public_key/1's key — the adapter's own guard, checked
  # before the first real signing call ever happens.
  defp live_probe_advisory(module, ref) do
    with {:ok, public_key} when is_binary(public_key) and byte_size(public_key) == 32 <-
           safe_call(module, :public_key, [ref]),
         {:ok, signature} when is_binary(signature) and byte_size(signature) == 64 <-
           safe_call(module, :sign, [@synthetic_probe_message, ref]),
         :ok <- verify_probe(public_key, signature) do
      []
    else
      _ ->
        [
          "--live probe: sign/2 against public_key/1 failed the wrong-key verify " <>
            "(the adapter maps this to :signing_failed on every real sign)"
        ]
    end
  end

  # Contained like the callback calls: a stateful handle that changes shape
  # BETWEEN the two probe calls would otherwise crash the doctor out of
  # :crypto.verify with a raw badarg instead of a finding.
  defp verify_probe(public_key, signature) do
    if :crypto.verify(:eddsa, :none, @synthetic_probe_message, signature, [
         public_key,
         :ed25519
       ]) do
      :ok
    else
      {:error, :wrong_key}
    end
  rescue
    _exception -> {:error, :verify_raised}
  catch
    _kind, _reason -> {:error, :verify_exited}
  end

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
