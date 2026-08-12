import Config

# Demo configuration for the edge-agent reference app. The agent + receiver SHARE
# this config so the request-field contract (consumer-integration.md §3) is
# byte-agreement-by-construction: `target_uri`, `operation`, `issuer`,
# `audience`, and the issuer/holder key seeds resolve IDENTICALLY on both sides.
# A real deployment keeps the edge↔verifier config in sync by operations policy
# (the single-environment round-trip cannot catch their drift).
#
# All keys here are DETERMINISTIC DEMO SEEDS — never production material. In
# production: the grant arrives issuer-signed out-of-band (the BA runtime); the
# holder key lives behind an HSM/KMS-backed handle; the trusted issuer + expected
# identity keys are published by the verifier.

config :edge_agent,
  # --- keys (DEMO seeds; prod = HSM/KMS + published issuer keys) ---------------
  holder_seed: <<2::256>>,
  issuer_seed: <<1::256>>,
  # --- the issuer / grant (the DemoIssuer mints from these; prod = out-of-band) -
  issuer_key_id: "demo-issuer",
  issuer: "https://demo-issuer.test",
  grant_id: "urn:demo:grant:1",
  audience: "https://demo-verifier.test",
  operation: "report_external_materialization",
  # --- the request-field contract (§3) — IDENTICAL on both sides ---------------
  target_uri: "https://receiver.local/report",
  report_body: ~s({"record":{"region":"us-east","signal":"ok"}}),
  # --- transport --------------------------------------------------------------
  receiver_url: "http://127.0.0.1:4001/report",
  receiver_ip: {127, 0, 0, 1},
  receiver_port: 4001,
  # --- verify windows (§4) -----------------------------------------------------
  clock_skew: 60,
  proof_max_age: 300
