defmodule BoundedAuthorityReportAdapter.MixProject do
  use Mix.Project

  @version "1.0.1"
  @source_url "https://github.com/baselabs/bounded_authority_report_adapter"

  def project do
    [
      app: :bounded_authority_report_adapter,
      version: @version,
      # Supported Elixir line: the range admits the supported
      # minors (1.18/1.19/1.20) and Mix refuses anything outside it at
      # compile. The supported OTP-major set ({27..29}) is enforced by
      # config/config.exs: 25/26 are excluded: the protocol package's
      # codecs decode through :json, which enters stdlib in OTP 27.
      # LOCKSTEP: this range, that set, .tool-versions, and the CI matrix
      # lanes move together in ONE commit.
      elixir: "~> 1.18",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      # The coverage floor is the MEASURED total, re-pinned at every change
      # that moves it (never aspirational; pinned just under the measured
      # number: Mix compares the RAW ratio, whose hidden decimals round up
      # for display, so an exact display-value pin can flake).
      test_coverage: [summary: [threshold: 77.5]],
      # PLT lives under _build (gitignored, cache-friendly): the BAP sibling's shape.
      dialyzer: [
        plt_core_path: "_build/plts",
        plt_local_path: "_build/plts",
        # :mix so the install task's Mix.Task behaviour callbacks resolve in the
        # PLT (the conditional-def pattern dialyzes clean with it); :earmark_parser
        # because the test-support documentation parser calls it at test time only.
        plt_add_apps: [:mix, :earmark_parser]
      ],
      deps: deps(),
      package: package(),
      docs: docs(),
      name: "Bounded Authority Report Adapter",
      description:
        "Signer for the Bounded Authority Protocol: signs holder proofs, grants, boundary " <>
          "anchors, key transitions and content assertions (Ed25519 and ES256) through your " <>
          "key handle, over the protocol's deterministic signing inputs. Keep private keys " <>
          "behind caller-owned key callbacks.",
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

  # `mix ci`: local CI parity: reproduces .github/workflows/ci.yml step-for-
  # step on the pinned dev lane (every library-job step + the example job's
  # steps) with zero GitHub Actions spend.
  # NO env(1) re-exec: the FIRST step is an env guard that refuses any boot
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
        "deps.get --check-locked",
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
        "cmd python3 scripts/check_doc_links.py doc",
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
        "run --no-start scripts/ci_example.exs",
        "cmd elixir scripts/check_livebooks.exs --local"
      ]
    ]
  end

  # test/support/ holds the reference key-handle impl (Keys.RawKey) + test-only
  # keypair fixtures: compiled ONLY in :test so the {pub, priv} reference impl
  # does not ship in the artifact: a key-in-process-memory handle in lib/ would
  # invite exactly the key custody this library exists to keep out of process.
  defp elixirc_paths(:test), do: ["lib/", "test/support/"]
  defp elixirc_paths(_env), do: ["lib/"]

  # Required runtime dependencies are the public protocol package and telemetry.
  # Igniter is optional installer support; authority-runtime and transport
  # dependencies are excluded by the dependency-direction test.
  defp deps do
    [
      # Runtime: the telemetry event surface (:telemetry.execute). Zero transitive
      # deps; the emitter is shape-validated and value-free
      # (lib/bounded_authority_report_adapter/telemetry.ex).
      {:telemetry, "~> 1.3"},
      # A RANGE with a security floor, not an exact pin: a library declares the range it is
      # compatible with and only an application locks an exact version.
      #   * The floor is the oldest protocol release this adapter supports. Every supported
      #     release carries the strict Ed25519 rule (BoundedAuthorityProtocol.Ed25519) that the
      #     key refusal and self-check call, the producer-canonicality checks, and the
      #     selector float-zero repair (erratum 6, 1.0.0 and later), so no 0.x release resolves.
      #   * The ceiling (exclusive) is the protocol's next compatibility boundary: the next
      #     minor while the protocol is 0.x, the next major from 1.0 on, where protocol minors
      #     are additive or soundness repairs. Crossing it is a deliberate, reviewed change.
      # The dependency wall test derives its probes from the floor and the ceiling, so a range
      # move edits only this requirement, the wall's three range attributes and the locks.
      {:bounded_authority_protocol, "~> 1.0"},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      # The install task (lib/mix/tasks) uses Igniter when present; the file
      # compiles to a Mix.raise fallback without it.
      # No `only:`: the optional edge must order igniter BEFORE this package
      # in consumer builds, or lib/mix/tasks compiles its no-igniter fallback.
      {:igniter, "~> 0.8", optional: true},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},
      {:ex_doc, "~> 0.34", only: [:dev, :test], runtime: false},
      {:earmark_parser, "~> 1.4", only: [:dev, :test], runtime: false},
      {:mix_audit, "~> 2.1", only: [:dev, :test], runtime: false},
      # CycloneDX generation uses sbom.generate: mix run --no-start starts only
      # sbom's dependency applications except code-only hex_core, then its
      # supervisor and CLI. This avoids hex_core's :ssh application dependency.
      {:sbom, "~> 0.12.1", only: [:dev, :test], runtime: false}
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
        "examples/files/signing-flow.svg",
        "docs/guides",
        "docs/notebooks"
      ],
      licenses: ["Apache-2.0"],
      links: %{
        "GitHub" => @source_url,
        "Changelog" => "#{@source_url}/blob/master/CHANGELOG.md"
      }
    ]
  end

  @doc false
  def documented_module?(module, _metadata) do
    source = module.module_info(:compile)[:source] |> to_string()
    String.starts_with?(source, Path.join(__DIR__, "lib") <> "/")
  end

  defp docs do
    [
      main: "readme",
      source_ref: "v#{@version}",
      source_url: @source_url,
      assets: %{"examples/files" => "files"},
      # CI builds the docs under MIX_ENV=test, which also compiles test/support/; only the
      # modules compiled from lib/ are documented.
      filter_modules: &documented_module?/2,
      groups_for_modules: [
        Signing: [BoundedAuthorityReportAdapter, BoundedAuthorityReportAdapter.V3],
        "Observe and preflight": [
          BoundedAuthorityReportAdapter.Telemetry,
          Mix.Tasks.BoundedAuthorityReportAdapter.Doctor
        ]
      ],
      groups_for_extras: [
        "Start here": ["README.md", "docs/guides/getting-started.md"],
        Concepts: [
          "docs/guides/holder-requests.md",
          "docs/guides/grants-and-roles.md",
          "docs/guides/key-custody.md",
          "docs/guides/anchors-and-rotation.md",
          "docs/guides/content-assertions.md",
          "docs/guides/local-loopback.md"
        ],
        "Integrate and operate": [
          "docs/guides/framework-integration.md",
          "docs/guides/security.md",
          "docs/guides/operations.md",
          "docs/guides/telemetry.md",
          "docs/guides/errors.md",
          "docs/guides/recipes.md",
          "docs/guides/testing.md",
          "docs/guides/upgrading.md"
        ],
        Notebooks: ~r/docs\/notebooks\//,
        Reference: ~r/docs\/guides\/(faq|glossary|cheatsheet)\.md|usage-rules\.md/,
        Project: ~r/CHANGELOG|CONTRIBUTING|SECURITY|CODE_OF_CONDUCT|LICENSE|NOTICE/
      ],
      extras: [
        {"README.md", title: "Overview"},
        "docs/guides/getting-started.md",
        "docs/guides/holder-requests.md",
        "docs/guides/grants-and-roles.md",
        "docs/guides/key-custody.md",
        "docs/guides/anchors-and-rotation.md",
        "docs/guides/content-assertions.md",
        "docs/guides/local-loopback.md",
        "docs/guides/framework-integration.md",
        "docs/guides/security.md",
        "docs/guides/operations.md",
        "docs/guides/telemetry.md",
        "docs/guides/errors.md",
        "docs/guides/recipes.md",
        "docs/guides/testing.md",
        "docs/guides/upgrading.md",
        {"docs/notebooks/holder-request.livemd", filename: "nb-holder-request"},
        {"docs/notebooks/issuer-grants.livemd", filename: "nb-issuer-grants"},
        {"docs/notebooks/es256-custody.livemd", filename: "nb-es256-custody"},
        {"docs/notebooks/anchors-and-rotation.livemd", filename: "nb-anchors-and-rotation"},
        {"docs/notebooks/content-assertions.livemd", filename: "nb-content-assertions"},
        {"docs/notebooks/local-loopback.livemd", filename: "nb-local-loopback"},
        {"docs/notebooks/production-preflight.livemd", filename: "nb-production-preflight"},
        "docs/guides/faq.md",
        "docs/guides/glossary.md",
        "docs/guides/cheatsheet.md",
        "usage-rules.md",
        "CHANGELOG.md",
        "CONTRIBUTING.md",
        "SECURITY.md",
        "CODE_OF_CONDUCT.md",
        "LICENSE",
        "NOTICE"
      ]
    ]
  end
end
