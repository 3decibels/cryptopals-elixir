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


  defp hamming_distance(_x, _y, acc), do: acc


  @doc """
  Finds the average Hamming distance on a ciphertext for a range of key sizes
  Computes 3 rounds of Hamming distance, comparing 4 keysize blocks
  Returns a list of tuples with each keysize and average Hamming distance

    ## Examples

      iex> Cryptopals.Util.find_average_hamming_distances("String for testing Hamming distance", 2..5)
      [
        {4, 2.5833333333333335},
        {3, 2.777777777777778},
        {5, 2.8000000000000003},
        {2, 2.8333333333333335}
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

      iex> Cryptopals.Util.find_average_hamming_distances("String for testing Hamming distance", 2..5, 5)
      [
        {5, 2.6000000000000005},
        {4, 2.65},
        {3, 2.8},
        {2, 3.1}
      ]

  """
  def find_average_hamming_distances(data, %Range{} = range, rounds) when is_binary(data) do
    Stream.map(range, fn keysize ->
      total_norm_distance = Enum.reduce(0..(rounds - 1), 0, fn iteration, acc ->
        offset = keysize * iteration
        <<_::bytes-size(offset), x::bytes-size(keysize), y::bytes-size(keysize), _::binary>> = data
        acc + (Cryptopals.Util.hamming_distance(x, y) / keysize)
      end)
      avg_norm_distance = total_norm_distance / rounds
      {keysize, avg_norm_distance}
    end)
    |> Enum.sort(fn {_keysize_x, norm_distance_x}, {_keysize_y, norm_distance_y} -> norm_distance_x <= norm_distance_y end)
  end


  @doc """
  Returns a block of transposed data based on the requested keysize and block position
  """
  def create_block_from_data(data, keysize, block) when is_binary(data) and is_integer(keysize) and is_integer(block) and keysize >= block do
    offset = block - 1
    <<_::bytes-size(offset), block_data::8, tail::binary>> = data
    create_block_from_data(tail, keysize, block, <<block_data>>)
  end


  defp create_block_from_data(data, keysize, block, acc) when byte_size(data) >= keysize do
    offset = keysize - 1
    <<_::bytes-size(offset), block_data::8, tail::binary>> = data
    create_block_from_data(tail, keysize, block, acc <> <<block_data>>)
  end


  defp create_block_from_data(_data, _keysize, _block, acc), do: acc


  @doc """
  Performs an XOR on a binary using a repeating key
  """
  def repeating_key_xor(data, key) when is_binary(data) and is_binary(key) do
    repeating_key_xor(data, key, <<>>)
  end


  defp repeating_key_xor(data, key, acc) when is_binary(data) and is_binary(key) and byte_size(data) >= byte_size(key) do
    keysize = byte_size(key)
    <<segment::bytes-size(keysize), tail::binary>> = data
    repeating_key_xor(tail, key, acc <> :crypto.exor(segment, key))
  end


  defp repeating_key_xor(data, key, acc) when is_binary(data) and is_binary(key) and byte_size(data) < byte_size(key) do
    datasize = byte_size(data)
    <<keysegment::bytes-size(datasize), _::binary>> = key
    acc <> :crypto.exor(data, keysegment)
  end


  @doc """
  Searches the supplied binary for the number of duplicate byte sequences it contains.
  Takes the binary to search and the size of the byte chunks to search for duplicates of.

    ## Examples

      iex> Cryptopals.Util.count_duplicates("AAABBBCCCAAADDDAAABBB", 3)
      2
      iex> Cryptopals.Util.count_duplicates("AAABBBCCCAAADDDAAABBB", 2)
      3
      iex> Cryptopals.Util.count_duplicates("AAABBBCCCAAADDDAAABBB", 4)
      0
      iex> Cryptopals.Util.count_duplicates("AAABBBCCCAAADDDAAABBB", 1)
      16

  """
  def count_duplicates(data, chunk_size) when is_binary(data) and is_integer(chunk_size) and byte_size(data) > chunk_size * 2 do
    count_duplicates(data, chunk_size, 0)
  end


  defp count_duplicates(data, chunk_size, acc) when byte_size(data) > chunk_size * 2 do
    <<chunk::bytes-size(chunk_size), tail::binary>> = data
    cond do
      has_duplicate?(tail, chunk) ->
        count_duplicates(tail, chunk_size, acc + 1)
      true ->
        count_duplicates(tail, chunk_size, acc)
    end
  end


  defp count_duplicates(_data, _chunk_size, acc), do: acc


  @doc """
  Searches the supplied data for the supplied chunk.

  This function searches only on chunk boundaries, with the size of the chunk defining the boundary size.
  Ex: For a 4-byte chunk, each 4-byte segment of the data will be considered separately

    ## Examples

      iex> Cryptopals.Util.has_duplicate?("AAABBBCCCAAADDD", "AAA")
      true
      iex> Cryptopals.Util.has_duplicate?("AAABBBCCCAAADDD", "FFF")
      false
      iex> Cryptopals.Util.has_duplicate?("AAABBBCCCAAADDD", "AAAA")
      false
      iex> Cryptopals.Util.has_duplicate?("AAABBBCCCAAADDD", "AAAB")
      true
      iex> Cryptopals.Util.has_duplicate?("AAABBBCCCAAADDD", "BBBC")
      false
      iex> Cryptopals.Util.has_duplicate?("AAABBBCCCAAADDD", "BBCC")
      true

  """
  def has_duplicate?(data, chunk) when is_binary(data) and is_binary(chunk) and byte_size(data) > byte_size(chunk) do
    chunk_size = byte_size(chunk)
    <<comparison_chunk::bytes-size(chunk_size), tail::binary>> = data
    cond do
      comparison_chunk == chunk ->
        true
      true ->
        has_duplicate?(tail, chunk)
    end
  end


  def has_duplicate?(_data, _chunk), do: false

end