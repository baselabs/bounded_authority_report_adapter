defmodule BoundedAuthorityReportAdapter.MixProject do
  use Mix.Project

  @version "0.2.1"
  @source_url "https://github.com/baselabs/bounded_authority_report_adapter"

  def project do
    [
      app: :bounded_authority_report_adapter,
      version: @version,
      elixir: "~> 1.18",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      package: package(),
      docs: docs(),
      name: "Bounded Authority Report Adapter",
      description:
        "Holder-side companion signer for the Bounded Authority Protocol — signs protocol " <>
          "objects (holder proofs, boundary anchors, grants, key transitions) through a local " <>
          "key handle over the protocol's deterministic signing inputs. The private key never " <>
          "enters the library.",
      source_url: @source_url,
      homepage_url: @source_url,
      aliases: aliases()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:crypto]
    ]
  end

  # `mix ci` — local CI parity: reproduces .github/workflows/ci.yml step-for-
  # step (five library steps; edge dependency audit + five build steps) with zero
  # GitHub Actions spend.
  # The workflow exports MIX_ENV: test at the JOB level, so every step here
  # re-execs mix under MIX_ENV=test via env(1) — a bare local `mix ci` would
  # otherwise boot in :dev, and a :dev compile skips test/support (the
  # warnings trap). `mix cmd` aborts on the first non-zero step, like a failed
  # CI job. Not reproduced locally: checkout/setup-beam (asdf here).
  defp aliases do
    [
      ci: [
        # job: gate (the library)
        "cmd env MIX_ENV=test mix deps.get",
        "cmd env MIX_ENV=test mix format --check-formatted",
        "cmd env MIX_ENV=test mix compile --warnings-as-errors",
        "cmd env MIX_ENV=test mix credo --strict",
        "cmd env MIX_ENV=test mix test",
        # job: example (the workflow's working-directory: examples/edge_agent)
        "cmd --cd examples/edge_agent env MIX_ENV=test mix deps.get",
        "cmd --cd examples/edge_agent env MIX_ENV=test mix hex.audit",
        "cmd --cd examples/edge_agent env MIX_ENV=test mix format --check-formatted",
        "cmd --cd examples/edge_agent env MIX_ENV=test mix compile --warnings-as-errors",
        "cmd --cd examples/edge_agent env MIX_ENV=test mix credo --strict",
        "cmd --cd examples/edge_agent env MIX_ENV=test mix test"
      ]
    ]
  end

  # test/support/ holds the reference key-handle impl (Keys.RawKey) + test-only
  # keypair fixtures — compiled ONLY in :test so the {pub, priv} reference impl
  # does not ship in the artifact (design C5, ADR-0014: a key-in-process-memory
  # impl in lib/ would pave a road to the failure strategy §4 says the separate
  # repo exists to prevent).
  defp elixirc_paths(:test), do: ["lib/", "test/support/"]
  defp elixirc_paths(_env), do: ["lib/"]

  # The adapter depends ONLY on the public bounded_authority_protocol package on
  # the edge path — no private runtime dependency (the dependency-direction wall,
  # ADR 0003). BAP is consumed from its Hex release.
  defp deps do
    [
      {:bounded_authority_protocol, "~> 0.1.2"},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:ex_doc, "~> 0.34", only: [:dev, :test], runtime: false}
    ]
  end

  defp package do
    [
      maintainers: ["rjpalermo"],
      files: [
        "lib",
        ".formatter.exs",
        "mix.exs",
        "README.md",
        "CHANGELOG.md",
        "LICENSE",
        "NOTICE",
        "SECURITY.md",
        "docs/consumer-integration.md"
      ],
      licenses: ["Apache-2.0"],
      links: %{
        "GitHub" => @source_url,
        "Changelog" => "#{@source_url}/blob/master/CHANGELOG.md"
      }
    ]
  end

  defp docs do
    [
      main: "readme",
      source_ref: "v#{@version}",
      source_url: @source_url,
      extras: [
        "README.md",
        "CHANGELOG.md",
        "LICENSE",
        "NOTICE",
        "SECURITY.md",
        "docs/consumer-integration.md"
      ]
    ]
  end
end
