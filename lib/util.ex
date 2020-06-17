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
  def hamming_distance(x, y) when is_bitstring(x) and is_bitstring(y) and bit_size(x) == bit_size(y) do
    hamming_distance(x, y, 0)
  end


  defp hamming_distance(<<x::1, x_tail::bitstring>>, <<y::1, y_tail::bitstring>>, acc) do
    cond do
      x == y ->
        hamming_distance(x_tail, y_tail, acc)
      true ->
        hamming_distance(x_tail, y_tail, acc + 1)
    end
  end


  defp hamming_distance(_, _, acc), do: acc


  @doc """
  Finds the average Hamming distance on a ciphertext for a range of key sizes
  Computes 3 rounds of Hamming distance, comparing 4 keysize blocks
  Returns a list of tuples with each keysize and average Hamming distance

    ## Examples

      iex> Cryptopals.Util.find_average_hamming_distances("Test string", 2..5)
      [
        {2, 0.16666666666666666},
        {4, 0.3333333333333333},
        {5, 0.5333333333333333},
        {3, 0.7777777777777777}
      ]

  """
  def find_average_hamming_distances(data, %Range{} = range) when is_binary(data) do
    find_average_hamming_distances(data, range, 3)
  end


  @doc """
  Finds the average Hamming distance on a ciphertext for a range of key sizes
  Computes a selectable number rounds of Hamming distance, comparing (rounds + 1) keysize blocks
  Returns a list of tuples with each keysize and average Hamming distance

    ## Examples

      iex> Cryptopals.Util.find_average_hamming_distances("Test string", 2..5, 7)
      [
        {4, 0.32142857142857145},
        {2, 0.42857142857142855},
        {5, 0.5142857142857143},
        {3, 0.7142857142857143}
      ]

  """
  def find_average_hamming_distances(data, %Range{} = range, rounds) when is_binary(data) do
    Stream.map(range, fn keysize ->
      total_norm_distance = Enum.reduce(0..(rounds - 1), 0, fn iteration, acc ->
        offset = keysize * iteration
        <<_::bits-size(offset), x::bits-size(keysize), y::bits-size(keysize), _::bitstring>> = data
        acc + (Cryptopals.Util.hamming_distance(x, y) / keysize)
      end)
      avg_norm_distance = total_norm_distance / rounds
      {keysize, avg_norm_distance}
    end)
    |> Enum.sort(fn {_keysize_x, norm_distance_x}, {_keysize_y, norm_distance_y} -> norm_distance_x <= norm_distance_y end)
  end

end