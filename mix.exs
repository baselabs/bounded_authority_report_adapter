defmodule BoundedAuthorityReportAdapter.MixProject do
  use Mix.Project

  @version "0.1.0"
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
        "Universal companion signer for the Bounded Authority protocol (ADR-0006) — " <>
          "signs BAP protocol objects (holder proofs, boundary anchors, grants, " <>
          "key transitions) via a local {module(), term()} key-handle and BAP's " <>
          "signing-input producers. Private BaseLabs library (not hex-published).",
      source_url: @source_url,
      homepage_url: @source_url
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:crypto]
    ]
  end

  # test/support/ holds the reference key-handle impl (Keys.RawKey) + test-only
  # keypair fixtures — compiled ONLY in :test so the {pub, priv} reference impl
  # does not ship in the artifact (design C5: a key-in-process-memory impl in
  # lib/ would pave a road to the failure strategy §4 says the separate repo
  # exists to prevent).
  defp elixirc_paths(:test), do: ["lib/", "test/support/"]
  defp elixirc_paths(_env), do: ["lib/"]

  # The adapter depends ONLY on the public bounded_authority_protocol package on
  # the edge path — no private runtime dependency (the dependency-direction wall,
  # ADR 0003). BAP is consumed as a PRIVATE git dep (not hex-published yet); the
  # same posture this adapter carries. See docs/strategy.md § Dependencies.
  defp deps do
    [
      {:bounded_authority_protocol,
       git: "https://github.com/baselabs/bounded_authority_protocol.git",
       ref: "c65d3bea37b08da631423bcfe2a12fa0f669933d"},
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
        "docs"
      ],
      licenses: ["Apache-2.0"],
      links: %{
        "GitHub" => @source_url
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
        "docs/charter.md",
        "docs/strategy.md",
        "docs/ROADMAP.md"
      ]
    ]
  end
end
