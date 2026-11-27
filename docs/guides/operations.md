# Operations runbook

The adapter has no supervisor, key store, network client, replay database or background
worker. Operate the host and its custody service. A signing success is not a receiver's
execution decision. See [host admission](framework-integration.md#11-complete-host-admission-before-any-effect).

## Deploy and preflight

1. Install the locked package and the toolchain your application supports. Select the
   contract major and profile explicitly. Validate canonical endpoint, audience, operation,
   bounds, clock skew and proof-age policy at startup.
2. Resolve immutable custody references. Run the doctor with the intended major and a
   nonproduction probe key first. A live probe signs synthetic bytes and may incur a real
   provider operation. Refuse deployment on fatal findings. The doctor reports a failed
   live signature check as an advisory with exit status zero. Resolve that failure and
   any missing callback needed by your signing entry points before enabling signing.
3. Exercise real signing and verification for each required object and a wrong-context
   refusal. The [preflight notebook](../notebooks/production-preflight.livemd) demonstrates
   this locally; it does not certify an external provider.
4. Configure host identity enrollment, issuer trust, policy, live revocation, durable replay
   uniqueness and execution recovery before enabling effects. Fail closed if a required
   service is unavailable. Rehearse restart and concurrent retry behavior in that host.
5. Attach total telemetry handlers once; verify they remain attached. Track custody latency,
   refusal classes, handler failures, host admission and recovery separately.

## Diagnose an incident

| Symptom | First check | Action |
|---|---|---|
| `:invalid_key_handle` | Callback availability, permissions, returned key suite and immutable id | Correct configuration; do not silently use another key. |
| `:signing_failed` | Provider health, raw/DER format and key identity/signature agreement | Stop affected signing; inspect custody status without logging inputs or keys. |
| `{:producer_error, :invalid}` | Canonical URI, identifiers, tagged arguments, bounds and windows | Correct the producer input; retries of identical input will not help. |
| Receiver refuses | Trusted issuer/context, identity binding, policy, revocation and replay record | Return uniform refusal; inspect value-free host signals and authorized records. |
| Missing stop metrics | Signing call/handle crash, handler failure or blocked custody call | Apply handle deadlines; restore failed telemetry attachment; investigate host health. |
| Admission outcome uncertain | Durable execution record and effect status | Reconcile through the host's recovery protocol before retrying an effect. |

## Rotate and recover

Provision a new immutable custody version, distribute trusted public key windows through
an authenticated channel, then issue/sign with the new version. Preserve historical keys
and transitions for evidence verification. Rotation and revocation are distinct: a signed
transition does not revoke a grant. Never destroy custody versions or replay/execution
records while an accepted request or required evidence still depends on them.

During an outage, refuse new effects when current revocation or admission cannot be
established. Retrying custody must not create extra grants or effects: retain invocation
identity, consult the host record, and use bounded retries. Roll back code only when the
wire/API and persisted state remain compatible; never downgrade to a permissive parser.
