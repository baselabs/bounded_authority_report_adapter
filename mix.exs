defmodule BoundedAuthorityReportAdapter.MixProject do
  use Mix.Project

  @version "0.11.0"
  @source_url "https://github.com/baselabs/bounded_authority_report_adapter"

  def project do
    [
      app: :bounded_authority_report_adapter,
      version: @version,
      # Supported Elixir line (ADR-0019): the range admits the supported
      # minors (1.18/1.19/1.20) and Mix refuses anything outside it at
      # compile. The supported OTP-major set ({27..29}) is enforced by
      # config/config.exs — 25/26 are excluded: the protocol package's
      # codecs decode through :json, which enters stdlib in OTP 27.
      # LOCKSTEP: this range, that set, .tool-versions, and the CI matrix
      # lanes move together in ONE commit.
      elixir: "~> 1.18",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      # The coverage floor is the MEASURED total, re-pinned at every change
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
        "Signer for the Bounded Authority Protocol: signs holder proofs, grants, boundary " <>
          "anchors, key transitions and content assertions (Ed25519 and ES256) through your " <>
          "key handle, over the protocol's deterministic signing inputs. The private key " <>
          "never enters the library.",
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
  # step on the pinned dev lane (every library-job step + the example job's
  # steps) with zero GitHub Actions spend.
  # NO env(1) re-exec — the FIRST step is an env guard that refuses any boot
  # other than MIX_ENV=test (a :dev compile skips test/support and its warnings)
  # with the invocation in its message; every later step is a plain task
  # name. The example job runs through scripts/ci_example.exs, preserving the
  # step-for-step order and abort-on-first-red semantics. Not reproduced
  # locally: checkout/setup-beam (asdf here), the OTP matrix dimension.
  defp aliases do
    [
      "sbom.generate": ["run --no-start scripts/generate_release_sbom.exs"],
      ci: [
        "run --no-start scripts/ci_env_guard.exs",
        # job: gate (the library)
        "deps.get",
        # Latest-first dependency currency (ADR-0020; the workflow's currency
        # step — caller-cwd .exs, runs against THIS project).
        "run --no-start scripts/check_deps_currency.exs",
        "format --check-formatted",
        "compile --warnings-as-errors",
        "credo --strict",
        # The gate battery (parity with the sibling-standard batteries): coverage
        # floor, dialyzer (PLT + analysis under :test so test/support/ is in the
        # paths, so their warnings are seen), doc warnings, and the LIBRARY's own advisory
        # audits (the example job has always audited its own lock; the library's
        # lock is now audited too). `test --cover` is the only test step: Mix runs a task once per
        # invocation, so a plain "test" before it made this step a silent no-op locally.
        "test --cover",
        "dialyzer",
        "docs --warnings-as-errors",
        "hex.audit",
        "deps.audit",
        # The shipped-artifact gate: builds the exact Hex archive, proves its
        # census/metadata, and compiles + smoke-runs a consumer against the
        # UNPACKED package (scripts/check_package.exs; scratch-cleaned).
        "run --no-start scripts/check_package.exs",
        # Two cache-isolated builds of the exact archive must agree byte for
        # byte (the release-candidate reproducibility gate).
        "run --no-start scripts/check_reproducible.exs",
        # job: example (the workflow's working-directory: examples/edge_agent)
        "run --no-start scripts/ci_example.exs"
      ]
    ]
  end

  # test/support/ holds the reference key-handle impl (Keys.RawKey) + test-only
  # keypair fixtures — compiled ONLY in :test so the {pub, priv} reference impl
  # does not ship in the artifact (ADR-0014: a key-in-process-memory
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
      # A RANGE with a security floor, not an exact pin (October 6, 2026;
      # ADR-0023 amendment): a library declares the range it is compatible with and only an
      # application locks an exact version. 0.8.0 is the floor: it carries the strict Ed25519
      # verification rule this adapter's key refusal and self-check call
      # (BoundedAuthorityProtocol.Ed25519), so 0.7.x must never resolve. The ceiling is the
      # next protocol minor, a deliberate, reviewed move. The dependency wall pins the
      # requirement shape and the locked version.
      {:bounded_authority_protocol, "~> 0.8.0"},
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
      # CycloneDX generation uses sbom.generate: mix run --no-start starts only
      # sbom's dependency applications except code-only hex_core, then its
      # supervisor and CLI. This avoids hex_core's :ssh application dependency.
      {:sbom, "~> 0.11.0", only: [:dev, :test], runtime: false},
      # EEF-CVE-2026-103502 (hex_core < 0.20.0: no TLS verification on OTP 24/25) is
      # fixed in hex_core 0.20.0, but sbom 0.11.0 still requires ~> 0.19.0. sbom calls
      # only hex_core.default_config/0, hex_api_package.get/2 and
      # hex_api_release.get/3, unchanged in 0.20.0. Drop this override once an sbom
      # release accepts hex_core 0.20.
      {:hex_core, "~> 0.20.0", only: [:dev, :test], runtime: false, override: true}
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
