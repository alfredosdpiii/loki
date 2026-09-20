defmodule LokiPhoenixFixtureWeb.Components do
  @moduledoc false
  use Phoenix.Component

  attr :name, :string, required: true

  def greeting(assigns) do
    ~H"""
    <p>{@name}</p>
    """
  end

  def page(assigns) do
    ~H"""
    <.greeting name="World" />
    """
  end
end
