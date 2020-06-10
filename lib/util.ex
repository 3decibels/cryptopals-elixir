defmodule Cryptopals.Util do

  @doc """
  Converts a hex encoded string into a charlist
  """
  def hex_to_charlist(hex) when is_binary(hex) do
    hex
    |> Base.decode16!(case: :lower)
    |> String.to_charlist
  end
end