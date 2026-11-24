defmodule Page.MixProject do
  use Mix.Project

  @version "0.1.1"
  @source_url "https://github.com/altenwald/page"

  def project do
    [
      app: :page,
      version: @version,
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: description(),
      package: package(),
      docs: docs(),
      test_coverage: [summary: [threshold: 95]]
    ]
  end

  def application do
    [extra_applications: [:logger, :crypto]]
  end

  defp deps do
    [
      {:ex_check, "~> 0.17", only: [:dev, :test], runtime: false},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:doctor, "~> 0.23", only: [:dev, :test], runtime: false},
      {:ex_doc, "~> 0.40", only: [:dev, :test], runtime: false},
      {:prisma, "~> 0.2", only: [:dev, :test], runtime: false}
    ]
  end

  defp description do
    "Files sealed with age, in pure Elixir: encrypt with a public key, " <>
      "open them only with the private one, interoperable with the age tool."
  end

  defp package do
    [
      licenses: ["MIT"],
      links: %{"GitHub" => @source_url},
      files: ~w(lib assets mix.exs README* CHANGELOG* LICENSE* .formatter.exs page_*.pplt)
    ]
  end

  defp docs do
    [
      main: "readme",
      source_ref: "v#{@version}",
      source_url: @source_url,
      extras: ["README.md", "CHANGELOG.md"]
    ]
  end
end
