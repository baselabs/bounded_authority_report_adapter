# ROADMAP — Bounded Authority Report Adapter

Authored capability definitions only. **Status and evidence are DERIVED** from
`.forge/` machine state by `~/.claude/scripts/forge-roadmap.py --report` — never
hand-edited here. The board is machine-local (`.forge/` is gitignored), so a
fresh clone derives every row `DEFINED` until its machine state is rebuilt.

Rows seed from the charter (`docs/charter.md`) + the strategy (`docs/strategy.md`).
The **Why** column links the governing section; a per-slice ADR
(`docs/adr/…`) supersedes the link when that slice lands.

Deferred scope routes to a backlog, never to tracker prose. The ID rides each
slice slug (`b2-ra-…`) as the deterministic join key.

<!-- forge-roadmap-schema: 1 -->

| ID | What | Acceptance | Depends | Why |
|---|---|---|---|---|
| RA1 | **Envelope sign** — the core signing API: take a report + a holder key handle, produce a grant + proof envelope via BAP's signing-input producers + `assemble_compact`. slug:b2-ra-envelope-sign | A report signed through the adapter verifies cleanly via `BoundedAuthorityProtocol.V1.check_envelope/2`; the round-trip is byte-compatible with the grant-holder-proof conformance vector; the holder key never leaves the caller (the adapter takes a key handle, not a path to a key) | — | [charter §2](charter.md) · [strategy §5](strategy.md) |
| RA2 | **Conformance round-trip** — a test harness that signs each vector's input through the adapter and asserts the output verifies against the published vector. slug:b2-ra-conformance-roundtrip | Every grant-holder-proof case in BAP's `priv/conformance/v1/vectors/` round-trips green; a defect-injected bad signature or tampered body goes red (non-vacuous); the harness re-runs against BAP's corpus at the pinned ref | RA1 | [charter §6](charter.md) · [strategy §7](strategy.md) |
| RA3 | **Dependency-direction proof** — a structural test asserting the adapter depends only on the public protocol package (no private runtime dep, no transport lib). slug:b2-ra-dep-direction | A test proves `mix.exs` declares `bounded_authority_protocol` and no `bounded_authority` runtime / no `replicant` / no `capstan`; a fixture adding a forbidden dep trips the gate red | — | [charter §6](charter.md) · [strategy §3](strategy.md) |
| RA4 | **Checkpoint-ack boundary anchor (probe)** — the exploratory boundary-anchor ack: does the adapter also produce a signed `BoundaryAnchor` the edge agent verifies before advancing its checkpoint? slug:b2-ra-checkpoint-ack-probe | The design probes whether the protocol package's `BoundaryAnchor` + `boundary_anchor_signing_input` express the ack; if yes, a producer lands (signed ack round-trips via `verify_historical_anchor`); if no, the gap is documented as a named deferral to BAP (a proposed protocol ADR, never a consumer-side fork) | RA1 | [charter §5](charter.md) |
| RA5 | **verifier application consumer change** — verifier application's report-signature plug accepts the `ba_protocol_v1` envelope (alongside S1's `eddsa_boundary_s1` during transition). slug:companion-signer-consumer | verifier application's `report_signature.ex` verifies the BA envelope via BAP's `check_envelope`; the `signature_scheme` column carries `ba_protocol_v1`; both schemes verify until S1's is retired; the verifier application-side dependency-direction wall stays green (verifier application depends on BAP, NOT on this adapter) | RA1, RA2 | [verifier application ADR 0007 §6](https://hexdocs.pm/bounded_authority_protocol) |
| RA6 | **Closeout + own ADR** — the adapter ships its ADR (`docs/adr/0001-report-adapter-topology.md`) recording the envelope-sign mechanism, the edge-path constraint, and the checkpoint-ack probe resolution. slug:b2-ra-closeout | The ADR lands in this repo's `docs/adr/`; the verifier application ROADMAP B2 row derives SHIPPED; the full suite + conformance round-trip are green | RA1, RA2, RA3, RA4, RA5 | [charter](charter.md) · [strategy](strategy.md) |
