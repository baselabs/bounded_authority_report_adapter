defmodule BoundedAuthorityReportAdapter.Telemetry do
  @moduledoc """
  The closed, value-free telemetry surface for the five signing entry points.

  The library emits events but does NOT attach a handler — a fresh application
  sees nothing until it attaches one (`:telemetry.attach/4` or a
  `Telemetry.Metrics` reporter; `docs/telemetry.md` carries the runnable
  example). What is emitted is deliberately tiny:

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
  extension: the emitters are shape-validated (`emit_start/1`, `emit_stop/3`)
  and REFUSE anything outside the closed shapes with
  `{:error, :telemetry_invalid}` rather than emitting it.

  ## Telemetry never outranks the signature

  `sign_span/2` returns the signer's result UNCHANGED. A failure inside the
  emission is swallowed (`{:error, :telemetry_invalid}`); a raise inside the
  SIGNER propagates — only the emission is guarded, never the crypto.
  """

  @prefix [:bounded_authority_report_adapter, :sign]

  # The single source of truth for both axes. docs/telemetry.md's tables are
  # diffed against these by telemetry_test.exs — a drift reds the suite.
  @objects [:report, :anchor, :grant, :key_transition, :local_loopback_report]
  @classes [:ok, :invalid_input, :invalid_key_handle, :signing_failed, :producer_error]

  @doc "The closed object axis (one atom per signing entry point)."
  @spec objects() :: [atom()]
  def objects, do: @objects

  @doc "The closed result-class axis (the classified outcome of a signing span)."
  @spec classes() :: [atom()]
  def classes, do: @classes

  @doc """
  Runs `fun` inside a `:sign` span: emits `:start`, runs it, emits `:stop`
  with the monotonic duration and the classified result, and returns whatever
  `fun` returned — unchanged. `object` must be one of `objects/0`.

  Telemetry failures are swallowed inside the emitters; a raise inside `fun`
  propagates (the emission is guarded, the crypto is not).
  """
  @spec sign_span(atom(), (-> term())) :: term()
  def sign_span(object, fun) when object in @objects and is_function(fun, 0) do
    started = System.monotonic_time()
    emit_start(object)

    result = fun.()

    _ = emit_stop(object, System.monotonic_time() - started, classify(result))
    result
  end

  @doc """
  Emits `[:bounded_authority_report_adapter, :sign, :start]` with
  `%{count: 1}` / `%{object: object}`. Refuses an unknown object with
  `{:error, :telemetry_invalid}` instead of emitting garbage.
  """
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

  @doc """
  Emits `[:bounded_authority_report_adapter, :sign, :stop]` with
  `%{duration: duration}` / `%{object: object, result_class: result_class}`.
  Refuses an unknown object or class, or a non-nonnegative-integer duration,
  with `{:error, :telemetry_invalid}` instead of emitting garbage — this
  validation is the mechanical value-free guarantee: a metadata key outside
  the closed shape is not expressible through this emitter.
  """
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

  # The closed classification. The four per-object input errors collapse to
  # :invalid_input; error VALUES never ride along. The catch-all is unreachable
  # per the entry points' closed @specs — an off-spec shape is a signing-path
  # anomaly, never classified as success.
  defp classify({:ok, _envelope}), do: :ok
  defp classify({:error, :invalid_report}), do: :invalid_input
  defp classify({:error, :invalid_anchor}), do: :invalid_input
  defp classify({:error, :invalid_grant}), do: :invalid_input
  defp classify({:error, :invalid_transition}), do: :invalid_input
  defp classify({:error, :invalid_key_handle}), do: :invalid_key_handle
  defp classify({:error, :signing_failed}), do: :signing_failed
  defp classify({:error, {:producer_error, :invalid}}), do: :producer_error
  defp classify(_off_spec), do: :signing_failed

  defp validate_object(object) when object in @objects, do: :ok
  defp validate_object(_object), do: :error
end
