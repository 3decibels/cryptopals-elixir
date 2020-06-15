defmodule Cryptopals.Util do

  @doc """
  Converts a hex encoded string into a charlist
  """
  def hex_to_charlist(hex) when is_binary(hex) do
    hex
    |> Base.decode16!(case: :lower)
    |> String.to_charlist
  end


  @doc """
  Computes the Hamming distance between two binaries

    ## Examples

      iex> Cryptopals.Util.hamming_distance("this is a test", "wokka wokka!!!")
      37

  """
  def hamming_distance(x, y) when is_binary(x) and is_binary(y) and byte_size(x) == byte_size(y) do
    compute_hamming(x, y, 0)
  end


  defp compute_hamming(<<x::1, x_tail::bitstring>>, <<y::1, y_tail::bitstring>>, acc) do
    cond do
      x == y ->
        compute_hamming(x_tail, y_tail, acc)
      true ->
        compute_hamming(x_tail, y_tail, acc + 1)
    end
  end


  defp compute_hamming(_, _, acc), do: acc

end