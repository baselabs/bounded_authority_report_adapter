# Recipes

<!-- doc-session: grants-and-roles.md -->

Run the [README quick start](../../README.md#quick-start) and the
[grant selector example](grants-and-roles.md#operations-and-selectors) first in the same
session. These tasks use real development keys, never a simulated service.

## Recipe: error handling, with telemetry for alerts

Requires: `:telemetry`, which this package already depends on.

Two channels, two jobs. A signing call's return value drives control flow: errors are closed atoms or the fixed tuple `{:producer_error, :invalid}`, so a `case` can decide what to do. Telemetry drives alerts: the `:stop`
event's `result_class` lets one handler watch every signing call for the custody alarm,
`:signing_failed`, without wrapping each call site. The event carries no values, so
it never says which key or request failed; the caller still has the return value.

```elixir
defmodule MyApp.Signing do
  @doc "Signs a holder proof and maps each closed error to what the caller does next."
  def sign_report(report, handle) do
    case BoundedAuthorityReportAdapter.sign_report(report, handle) do
      {:ok, envelope} -> {:ok, envelope}
      # The request was wrong: report it to whoever built it. Retrying cannot help.
      {:error, :invalid_report} -> {:error, :bad_request}
      {:error, {:producer_error, :invalid}} -> {:error, :bad_request}
      # Custody is wrong or down: fail this call; the telemetry handler raises the alarm.
      {:error, :invalid_key_handle} -> {:error, :signing_unavailable}
      {:error, :signing_failed} -> {:error, :signing_unavailable}
    end
  end
end

defmodule MyApp.CustodyAlarm do
  @event [:bounded_authority_report_adapter, :sign, :stop]

  def attach(notify) do
    :telemetry.attach("my-app-custody-alarm", @event, &__MODULE__.handle_event/4, notify)
  end

  # Total by construction: it matches the alarm and ignores every other class, including
  # classes a later minor release may add.
  def handle_event(_event, _measurements, %{result_class: :signing_failed} = metadata, notify) do
    send(notify, {:custody_alarm, metadata.object})
  end

  def handle_event(_event, _measurements, _metadata, _notify), do: :ok
end

# A misconfigured handle: it reports one key and signs with another.
defmodule MyApp.SwappedKey do
  @behaviour BoundedAuthorityReportAdapter

  @impl true
  def sign(message, name), do: MyApp.DevKey.sign(message, {:holder, name <> "-old"})

  @impl true
  def public_key(name), do: MyApp.DevKey.public_key({:holder, name})

  @impl true
  def thumbprint(name), do: MyApp.DevKey.thumbprint({:holder, name})
end

:ok = MyApp.CustodyAlarm.attach(self())

{:ok, cast_arguments} = V1.Json.decode(~s({"warehouse":"north","unit":"box","quantity":3}))

report = %{
  grant_compact: stock_grant,
  operation: "reserve_stock",
  method: "POST",
  target_uri: "https://inventory.example/reservations",
  invocation_id: "9e8d7c6b-5a4f-4e3d-8c2b-1a0f9e8d7c6b",
  cast_arguments: cast_arguments,
  nonce: "nonce-alarm-1"
}

results = {
  MyApp.Signing.sign_report(report, {MyApp.SwappedKey, "holder-key-1"}),
  MyApp.Signing.sign_report(%{report | invocation_id: "not-a-uuid"}, holder),
  receive do
    {:custody_alarm, object} -> {:alarm, object}
  after
    0 -> :no_alarm
  end
}

:telemetry.detach("my-app-custody-alarm")
results
#=> {{:error, :signing_unavailable}, {:error, :bad_request}, {:alarm, :report}}
```

Keep handlers total and cheap: `:telemetry` detaches a handler that raises, after which the
alarm stops firing ([telemetry](telemetry.md#if-your-handler-raises)).


## Connect a host

Use the [framework and runtime guide](framework-integration.md#11-complete-host-admission-before-any-effect)
for the complete authorization, revocation and replay handoff. The
[tested HTTP example](https://github.com/baselabs/bounded_authority_report_adapter/tree/master/examples/edge_agent)
demonstrates cryptographic transport and single-VM replay rejection.

## Port a signing implementation

Produce the exact protocol signing input, sign it with the selected suite, normalize ES256
to low-S raw `r || s`, and assemble compact JWS. Compare exact bytes against the independent
protocol conformance corpus; self-round-trips alone do not establish interoperability.
Resolve each key's id and public key from one immutable version and self-verify every
signature before returning it.
