# Contributor agent instructions

Read [README](README.md), [Contributing](CONTRIBUTING.md), [Usage rules](usage-rules.md),
and the [integration guide](docs/guides/framework-integration.md) before changing this package.

This is a public, provider-neutral signer. The protocol dependency owns canonical signing
inputs and pure verification. The caller owns custody, issuer policy, trusted keys,
authorization, revocation, replay and execution. Never place private keys in handle terms.
Never infer authority from verification facts or the handle's self-declared issuer role.

The library and example app are separate projects. Keep transport dependencies in the
example. Use only documented protocol functions. Update examples and documentation with
contracts; discover and execute samples recursively and check rendered links.

Use the exact toolchains in `.tool-versions`. Validate through the repository CI contract.
Commit named paths. Do not push, publish, tag, deploy or dispatch workflows without a
maintainer's explicit instruction. Never read, print or commit secrets; never mock services.
