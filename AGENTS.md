# Repository guide

The public technical contract is described in:

- [README](README.md): installation and first signing/verification flow.
- [Charter](docs/charter.md): signing, verification and service-policy boundaries.
- [Strategy](docs/strategy.md): current stability and dependency graph.
- [Consumer integration](docs/consumer-integration.md): raw-body binding, identity and replay.
- [Contributing](CONTRIBUTING.md): project layout and validation commands.
- [Upgrading](docs/upgrading.md#stability-contract): the SemVer contract since 1.0.0.
- [Protocol specifications](https://github.com/baselabs/bounded_authority_protocol/tree/main/spec):
  canonical wire formats and independent conformance requirements.

The library and `examples/edge_agent` are separate Mix projects. The library has required
runtime dependencies on the public protocol package and telemetry, with optional Igniter
support for its installer. Transport dependencies belong to the example application.
`test/support` compiles only in the test environment and is excluded from the Hex archive.
