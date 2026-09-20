defmodule LokiPhoenixFixtureWeb.InputController do
  @moduledoc false
  use LokiPhoenixFixtureWeb, :controller

  def handle(_conn, %{"input" => input}), do: Jason.decode!(input)
end
