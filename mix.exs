defmodule BoundedAuthorityReportAdapter.MixProject do
  use Mix.Project

  @version "0.5.0"
  @source_url "https://github.com/baselabs/bounded_authority_report_adapter"

  def project do
    [
      app: :bounded_authority_report_adapter,
      version: @version,
      elixir: "~> 1.18",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      # The coverage floor is the MEASURED total, re-pinned at every slice
      # that moves it (never aspirational; pinned just under the measured
      # number — Mix compares the RAW ratio, whose hidden decimals round up
      # for display, so an exact display-value pin can flake).
      test_coverage: [summary: [threshold: 77.5]],
      # PLT lives under _build (gitignored, cache-friendly) — the BAP sibling's shape.
      dialyzer: [
        plt_core_path: "_build/plts",
        plt_local_path: "_build/plts",
        # :mix so the install task's Mix.Task behaviour callbacks resolve in the
        # PLT (the conditional-def pattern dialyzes clean with it — the
        # ash_onetime posture).
        plt_add_apps: [:mix]
      ],
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
        # The gate battery (parity with the sibling-standard batteries): coverage
        # floor, dialyzer (PLT + analysis under :test so test/support/ is in the
        # paths — the RA7 lesson), doc warnings, and the LIBRARY's own advisory
        # audits (the example job has always audited its own lock; the library's
        # lock is now audited too).
        "cmd env MIX_ENV=test mix test --cover",
        "cmd env MIX_ENV=test mix dialyzer",
        "cmd env MIX_ENV=test mix docs --warnings-as-errors",
        "cmd env MIX_ENV=test mix hex.audit",
        "cmd env MIX_ENV=test mix deps.audit",
        # The shipped-artifact gate: builds the exact Hex archive, proves its
        # census/metadata, and compiles + smoke-runs a consumer against the
        # UNPACKED package (scripts/check_package.exs; scratch-cleaned).
        "cmd env MIX_ENV=test mix run --no-start scripts/check_package.exs",
        # Two cache-isolated builds of the exact archive must agree byte for
        # byte (the release-candidate reproducibility gate).
        "cmd env MIX_ENV=test mix run --no-start scripts/check_reproducible.exs",
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
      # Runtime: the telemetry event surface (:telemetry.execute). Zero transitive
      # deps; the emitter is shape-validated and value-free
      # (lib/bounded_authority_report_adapter/telemetry.ex).
      {:telemetry, "~> 1.3"},
      {:bounded_authority_protocol, "== 0.3.0"},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      # The install task (lib/mix/tasks) uses Igniter when present; the file
      # compiles to a Mix.raise fallback without it.
      # No `only:` — the optional edge must order igniter BEFORE this package
      # in consumer builds, or lib/mix/tasks compiles its no-igniter fallback
      # (the ash_onetime posture, read first-hand).
      {:igniter, "~> 0.8", optional: true},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},
      {:ex_doc, "~> 0.34", only: [:dev, :test], runtime: false},
      {:mix_audit, "~> 2.1", only: [:dev, :test], runtime: false},
      # CycloneDX SBOM generation for the tag-push supply-chain workflow.
      {:sbom, "~> 0.10", only: [:dev, :test], runtime: false}
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
        "CODE_OF_CONDUCT.md",
        "CONTRIBUTING.md",
        "LICENSE",
        "NOTICE",
        "SECURITY.md",
        "usage-rules.md",
        "docs/consumer-integration.md",
        "docs/errors.md",
        "docs/getting-started.md",
        "docs/recipes.md",
        "docs/security.md",
        "docs/telemetry.md",
        "docs/upgrading.md"
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
        "usage-rules.md",
        "CHANGELOG.md",
        "CODE_OF_CONDUCT.md",
        "CONTRIBUTING.md",
        "LICENSE",
        "NOTICE",
        "SECURITY.md",
        "docs/consumer-integration.md",
        "docs/errors.md",
        "docs/getting-started.md",
        "docs/recipes.md",
        "docs/security.md",
        "docs/telemetry.md",
        "docs/upgrading.md"
      ]
    ]
  end
end
