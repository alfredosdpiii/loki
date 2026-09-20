defmodule LokiPhoenixFixtureWeb do
  @moduledoc false

  def controller do
    quote do
      use Phoenix.Controller, formats: [:html]
    end
  end

  def router do
    quote do
      use Phoenix.Router
    end
  end

  defmacro __using__(which) when is_atom(which) do
    apply(__MODULE__, which, [])
  end
end
