defmodule BoundedAuthorityReportAdapter.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/baselabs/bounded_authority_report_adapter"

  def project do
    [
      app: :bounded_authority_report_adapter,
      version: @version,
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      package: package(),
      docs: docs(),
      name: "Bounded Authority Report Adapter",
      description:
        "holder-side signing adapter for application reports — wraps the public " <>
          "bounded_authority_protocol package's grant/proof envelopes with " <>
          "local private-key signing. Private BaseLabs library (not hex-published).",
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

  # The adapter depends ONLY on the public bounded_authority_protocol package on
  # the edge path — no private runtime dependency (the dependency-direction wall,
  # ADR 0002). BAP is consumed as a PRIVATE git dep (not hex-published yet); the
  # same posture this adapter carries. See docs/strategy.md § Dependencies.
  defp deps do
    [
      {:bounded_authority_protocol,
       git: "https://github.com/baselabs/bounded_authority_protocol.git",
       ref: "4c64be36ada1c167214471847d4061ea5ff63c56"},
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
