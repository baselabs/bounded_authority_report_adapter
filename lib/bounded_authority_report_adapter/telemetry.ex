defmodule BoundedAuthorityReportAdapter.Telemetry do
  @moduledoc """
  The closed, value-free telemetry surface of the signing entry points: ten entry points
  across the two suite surfaces, six object kinds. The object names the kind of object
  signed, never the entry point or the suite.

  The library emits events but does not attach a handler; an application sees nothing
  until it attaches one (`:telemetry.attach_many/4` or a `Telemetry.Metrics` reporter; the
  telemetry guide has a runnable handler). Two events are emitted:

    * `[:bounded_authority_report_adapter, :sign, :start]` —
      measurements `%{count: 1}`, metadata `%{object: object}`.
    * `[:bounded_authority_report_adapter, :sign, :stop]` —
      measurements `%{duration: native_monotonic_delta}`, metadata
      `%{object: object, result_class: class}`.

  ## The value-free invariant (a named misuse)

  Metadata carries exactly two closed atoms and NOTHING else — never key ids,
  thumbprints, message bytes, report content, caller opts, or error VALUES
  (`{:producer_error, :invalid}` is the class `:producer_error`, full stop; a
  wrong-key failure is `:signing_failed`, not the keys involved). Adding a
  value-carrying field to an emission is a named MISUSE of this surface, not an
  extension: the library's internal emitters are shape-validated and refuse
  anything outside the closed shapes rather than emitting it.

  ## Stability

  From 1.0.0 the two event names, their measurement keys, the two metadata keys, and the
  values of `objects/0` and `classes/0` are part of the stability contract (see the
  upgrading guide). Adding a metadata key, or renaming or removing an event, object or
  class, is a breaking change. A minor release may add an object (with a new signing entry
  point) or a class (with a new error), announced in the CHANGELOG, so a handler should
  accept atoms it does not know.

  The emitters (`sign_span/2`, `emit_start/1`, `emit_stop/3`) were documented before 1.0
  and are internal from 1.0 on; they remain callable but are not part of the contract.
  To observe signing, attach a handler to the two events. To test a handler, call a
  signing entry point, or call `:telemetry.execute/3` with the documented event name,
  measurements and metadata.

  Hiding the emitters is surface minimisation, not a security boundary: any code in the
  VM can call `:telemetry.execute/3` with these event names. A handler must not treat an
  event as proof that a signing call happened, or as evidence of which code emitted it.

  ## Telemetry never outranks the signature

  Each signing entry point returns the signer's result UNCHANGED. A failure inside the
  emission is swallowed; a raise inside the SIGNER propagates — only the emission is
  guarded, never the crypto.
  """

  @prefix [:bounded_authority_report_adapter, :sign]

  # The single source of truth for both axes. docs/telemetry.md's tables are
  # diffed against these by telemetry_test.exs — a drift reds the suite.
  @objects [:report, :anchor, :grant, :key_transition, :local_loopback_report, :content_assertion]
  @classes [
    :ok,
    :invalid_input,
    :invalid_key_handle,
    :invalid_role_attestation,
    :signing_failed,
    :producer_error
  ]

  @doc """
  The closed object axis: one atom per signing object kind.

      iex> BoundedAuthorityReportAdapter.Telemetry.objects()
      [:report, :anchor, :grant, :key_transition, :local_loopback_report, :content_assertion]
  """
  @spec objects() :: [atom()]
  def objects, do: @objects

  @doc """
  The closed result-class axis: the classified outcome of a signing call.

      iex> BoundedAuthorityReportAdapter.Telemetry.classes()
      [:ok, :invalid_input, :invalid_key_handle, :invalid_role_attestation, :signing_failed, :producer_error]
  """
  @spec classes() :: [atom()]
  def classes, do: @classes

  # Internal from 1.0 (was documented before): runs `fun` inside a `:sign` span — emits
  # :start, runs it, emits :stop with the monotonic duration and the classified result, and
  # returns whatever `fun` returned, unchanged. Telemetry failures are swallowed inside the
  # emitters; a raise inside `fun` propagates. An `object` outside objects/0 raises
  # FunctionClauseError.
  @doc false
  @spec sign_span(atom(), (-> term())) :: term()
  def sign_span(object, fun) when object in @objects and is_function(fun, 0) do
    started = System.monotonic_time()
    emit_start(object)

    result = fun.()

    _ = emit_stop(object, System.monotonic_time() - started, classify(result))
    result
  end

  # Internal from 1.0: emits the :start event, or refuses an unknown object with
  # {:error, :telemetry_invalid} instead of emitting it.
  @doc false
  @spec emit_start(atom()) :: :ok | {:error, :telemetry_invalid}
  def emit_start(object) do
    case validate_object(object) do
      :ok ->
        :telemetry.execute(@prefix ++ [:start], %{count: 1}, %{object: object})
        :ok

      :error ->
        {:error, :telemetry_invalid}
    end
  rescue
    _exception -> {:error, :telemetry_invalid}
  catch
    _kind, _reason -> {:error, :telemetry_invalid}
  end

  # Internal from 1.0: emits the :stop event. Refuses an unknown object or class, or a
  # duration that is not a non-negative integer, with {:error, :telemetry_invalid}: a
  # metadata key outside the closed shape is not expressible through this emitter.
  @doc false
  @spec emit_stop(atom(), integer(), atom()) :: :ok | {:error, :telemetry_invalid}
  def emit_stop(object, duration, result_class) do
    with :ok <- validate_object(object),
         true <- result_class in @classes,
         true <- is_integer(duration) and duration >= 0 do
      :telemetry.execute(@prefix ++ [:stop], %{duration: duration}, %{
        object: object,
        result_class: result_class
      })

      :ok
    else
      _invalid -> {:error, :telemetry_invalid}
    end
  rescue
    _exception -> {:error, :telemetry_invalid}
  catch
    _kind, _reason -> {:error, :telemetry_invalid}
  end

  # The closed classification. The per-object input errors collapse to
  # :invalid_input; error VALUES never ride along. The catch-all is unreachable
  # per the entry points' closed @specs — an off-spec shape is a signing-path
  # anomaly, never classified as success.
  defp classify({:ok, _envelope}), do: :ok
  defp classify({:error, :invalid_report}), do: :invalid_input
  defp classify({:error, :invalid_anchor}), do: :invalid_input
  defp classify({:error, :invalid_grant}), do: :invalid_input
  defp classify({:error, :invalid_transition}), do: :invalid_input
  defp classify({:error, :invalid_content_assertion}), do: :invalid_input
  defp classify({:error, :invalid_key_handle}), do: :invalid_key_handle
  defp classify({:error, :invalid_role_attestation}), do: :invalid_role_attestation
  defp classify({:error, :signing_failed}), do: :signing_failed
  defp classify({:error, {:producer_error, :invalid}}), do: :producer_error
  defp classify(_off_spec), do: :signing_failed

  defp validate_object(object) when object in @objects, do: :ok
  defp validate_object(_object), do: :error
end
