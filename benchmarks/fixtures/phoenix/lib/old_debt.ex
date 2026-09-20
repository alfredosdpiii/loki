defmodule OldDebt do
  def decode(input), do: :erlang.binary_to_term(input)
end
