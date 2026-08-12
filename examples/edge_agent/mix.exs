defmodule EdgeAgent.MixProject do
  use Mix.Project

  @version "0.1.0"

  # A minimal runnable edge-agent reference app (ROADMAP RA9) — the proof the
  # adapter works in a real deployment. TWO roles live here for a self-contained
  # loop (like the Livebook): the EDGE AGENT (calls `sign_report/3`, POSTs the
  # envelope via Req) and the RECEIVER (a Plug/Bandit consumer that verifies via
  # `check_envelope/2`, depending ONLY on BAP — never on the adapter). A demo
  # grant minter + an in-memory key-handle make the loop runnable with zero
  # external services; both are labeled DEMO-ONLY (a real deployment's issuer is
  # the BA runtime; real key custody is HSM/KMS).
  #
  # This is its OWN mix project: the adapter dep is `path: "../.."`, and the
  # transport deps (req/bandit/plug) live HERE — they never touch the library's
  # `mix.exs`, so the RA3 dependency-direction wall (which scans the library's
  # `mix.exs`/`lib`/`test/support`) stays green.
  def project do
    [
      app: :edge_agent,
      version: @version,
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # No `mod:` — the receiver is started explicitly via `EdgeAgent.Receiver.start/0`
  # (or `mix run --no-halt -e EdgeAgent.Receiver.start`) so a bare `mix test` /
  # `mix run` does not bind the demo port. The agent is a one-shot POST run via
  # `EdgeAgent.run/0`.
  def application do
    [
      extra_applications: [:crypto]
    ]
  end

  defp deps do
    [
      # The holder signing glue. Path-relative so the example tracks the working
      # tree of this repo; transitively resolves `bounded_authority_protocol`.
      {:bounded_authority_report_adapter, path: "../.."},
      # HTTP client (the agent POSTs the envelope + raw report body).
      {:req, "~> 0.5"},
      # HTTP server (the receiver is a Plug served by Bandit).
      {:plug, "~> 1.15"},
      {:bandit, "~> 1.0"},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false}
    ]
  end
end
