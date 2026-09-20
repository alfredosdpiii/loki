defmodule LokiPhoenixFixture.MixProject do
  use Mix.Project

  def project do
    [
      app: :loki_phoenix_fixture,
      version: "0.1.0",
      elixir: "~> 1.17",
      deps: [
        {:sobelow, "0.14.1", only: :dev, runtime: false},
        {:credo, "1.7.12", only: :dev, runtime: false},
        {:phoenix_live_view, "1.2.12"}
      ]
    ]
  end

  def application, do: [extra_applications: [:logger]]
end
