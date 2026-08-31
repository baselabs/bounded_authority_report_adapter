# Sign telemetry

The adapter emits a closed, value-free telemetry surface for its four signing
entry points (`sign_report/3`, `sign_anchor/3`, `sign_grant/3`,
`sign_key_transition/3`). The library does NOT attach a handler — a fresh
application sees nothing until it attaches one.

## Events

| Event | Measurements | Metadata |
|---|---|---|
| `[:bounded_authority_report_adapter, :sign, :start]` | `%{count: 1}` | `%{object: object}` |
| `[:bounded_authority_report_adapter, :sign, :stop]` | `%{duration: native_monotonic_delta}` | `%{object: object, result_class: result_class}` |

`duration` is the monotonic time delta of the WHOLE signing span (entry point
to closed-atom return), in `:erlang.monotonic_time/0` units — aggregate only,
never per-callback timing (a per-HSM-operation split would leak which custody
operation was slow or failing).

## The closed axes

Objects (one per signing entry point):

| Object | Entry point |
|---|---|
| `:report` | `sign_report/3` |
| `:anchor` | `sign_anchor/3` |
| `:grant` | `sign_grant/3` |
| `:key_transition` | `sign_key_transition/3` |
| `:local_loopback_report` | `sign_local_loopback_report/3` |

Result classes (the classified outcome of a span):

| Class | Meaning | What to alert on |
|---|---|---|
| `:ok` | The signing round-trip returned `{:ok, _}`. | Baseline; alert on rate DROPS. |
| `:invalid_input` | The caller-supplied object failed validation (`:invalid_report`, `:invalid_anchor`, `:invalid_grant`, or `:invalid_transition`). | Rate = caller input quality. Not a custody problem. |
| `:invalid_key_handle` | The key handle is malformed, or a handle callback (`public_key/1`, `key_identity/1`, `signing_identity/1`) rejected / returned an invalid value / exited. | Rate = handle wiring or custody-endpoint health. |
| `:signing_failed` | `sign/2` rejected, violated its contract, returned a non-64-byte signature, OR the signature did not verify against the resolved public key (wrong-key). | Rate = **custody misconfiguration** — the highest-priority signal this surface offers; a sustained nonzero rate means the handle is signing with the wrong key or failing outright. |
| `:producer_error` | The protocol's producer or assembler rejected the signing input (bounds, field constraints). | Rate = caller input quality against the protocol contract. |

Error VALUES never ride along: `{:producer_error, :invalid}` is emitted as the
class `:producer_error`, full stop; a wrong-key failure is `:signing_failed`,
not the keys involved.

## The value-free invariant (a named misuse)

Metadata carries exactly the two closed atoms above and NOTHING else — never
key ids, thumbprints, message bytes, report content, caller opts, or error
values. Adding a value-carrying field to an emission is a **named misuse** of
this surface, not an extension: the emitters (`Telemetry.emit_start/1`,
`Telemetry.emit_stop/3`) are shape-validated and refuse anything outside the
closed shapes with `{:error, :telemetry_invalid}` instead of emitting it. A
compacted JWS's bytes, a report's fields, and a key id are all caller material
the event stream must never carry — downstream sinks (logs, metrics labels)
are not trusted to redact.

## Attaching a handler

```elixir
# once at boot (e.g. your application's start/2):
:telemetry.attach_many(
  "my-app-bara-sign-metrics",
  [
    [:bounded_authority_report_adapter, :sign, :start],
    [:bounded_authority_report_adapter, :sign, :stop]
  ],
  fn [:bounded_authority_report_adapter, :sign, phase], measurements, metadata, _config ->
    case phase do
      :start -> MyApp.Counter.inc(:sign_attempts, metadata.object)
      :stop ->
        MyApp.SignMetrics.record(
          metadata.object,
          metadata.result_class,
          measurements.duration
        )
    end
  end,
  nil
)
```

Or consume via a `Telemetry.Metrics` reporter:

```elixir
summary("bounded_authority_report_adapter.sign.stop.duration",
  unit: {:native, :millisecond},
  tags: [:object, :result_class]
)
```

## Why no spans

There is deliberately NO `:telemetry.span/3` usage and no span context in the
metadata: span contexts and exception reasons carry VALUES (messages, stacks,
caller terms), which is exactly what the value-free invariant forbids. A
two-event pair with closed-atom metadata gives the same timing signal without
a value channel. For the same reason the emitters never pass the signer's
error term into telemetry.

## Telemetry never outranks the signature

`Telemetry.sign_span/2` returns the signer's result unchanged. A failure
inside an emission is swallowed (`{:error, :telemetry_invalid}`); a raise
inside the SIGNER propagates — only the emission is guarded, never the crypto.
(Consequence for counters: a crashing signer leaves an unpaired `:start` — no
`:stop` is emitted after a raise. Treat `start − stop` accumulation as a
crash-rate signal, not a bug; the classes cannot classify a call that never
returned.)

## If your handler raises

The `:telemetry` library (not the adapter) contains handler failures: `:telemetry.execute/3`
catches a raising handler, **permanently detaches it**, emits
`[:telemetry, :handler, :failure]`, logs, and returns — the exception does NOT
reach the adapter's emitters. Operational consequence: a handler that raises
once silently stops receiving ALL subsequent sign telemetry — including the
`:signing_failed` custody-misconfiguration alarm this doc calls the
highest-priority signal. Monitor `[:telemetry, :handler, :failure]` wherever
you consume this surface, and make handlers total (never let report/label
formatting raise).
