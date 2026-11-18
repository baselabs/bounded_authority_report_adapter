# Anchors and rotation

Continue the [README quick start](../../README.md#quick-start). This is evidence signing; the host owns chain storage, trust enrollment and rotation policy.

## Recipe: rotating a key with `sign_key_transition/3`

Requires: nothing beyond this package.

A key transition is the retiring key's signed statement that names its successor. Sign it
with the retiring key's handle before you switch; a verifier that trusts the retiring key
then learns the next one from the transition, through
`BoundedAuthorityProtocol.V1.verify_key_transition/4`, instead of from a side channel.
Both key ids come from the handles' `key_identity/1`, so the statement names exactly the
keys in your key store.

```elixir
retiring = {MyApp.DevKey, {:holder, "audit-chain-key-1"}}
{:ok, {retiring_key_id, retiring_public_key}} = MyApp.DevKey.key_identity(elem(retiring, 1))

{:ok, {next_key_id, next_public_key}} =
  MyApp.DevKey.key_identity({:holder, "audit-chain-key-2"})

transition = %{
  transition_id: "urn:example:transition:audit-chain-2",
  chain_id: "urn:example:chain:audit",
  effective_at: now,
  next_key_id: next_key_id,
  next_public_key: next_public_key
}

{:ok, %{key_transition: transition_compact}} =
  BoundedAuthorityReportAdapter.sign_key_transition(transition, retiring)

# The verifier's view: both keys with their validity windows, and what it expects.
historical = fn key_id, public_key ->
  %V1.HistoricalPublicKey{
    key_id: key_id,
    public_key: public_key,
    valid_from: now - 3600,
    valid_before: :unbounded
  }
end

fingerprint = fn public_key ->
  {:ok, thumbprint} = BoundedAuthorityReportAdapter.public_key_thumbprint(public_key)
  thumbprint
end

{:ok, transition_facts} =
  V1.verify_key_transition(
    transition_compact,
    historical.(retiring_key_id, retiring_public_key),
    historical.(next_key_id, next_public_key),
    %V1.ExpectedKeyTransition{
      transition_id: transition.transition_id,
      chain_id: transition.chain_id,
      effective_at: now,
      current_key_id: retiring_key_id,
      current_key_fingerprint: fingerprint.(retiring_public_key),
      next_key_id: next_key_id,
      next_key_fingerprint: fingerprint.(next_public_key),
      bounds: V1.Bounds.maximum()
    }
  )

transition_facts.verification
#=> :authenticated_transition
```

After the switch, the retiring key signs nothing more: retire it in your key store, and keep
its public key and validity window where verifiers of older objects can find it. The
`V3` surface has the same `sign_key_transition/3` for P-256 keys.
