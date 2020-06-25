defmodule Cryptopals.Crypto do
  
  @doc """
  Pad supplied data to blocksize using PKCS#7 padding.

  If data is already greater than or equal to the blocksize, the data will be returned unaltered.

    ## Examples

    iex> Cryptopals.Crypto.pad_pkcs7("YELLOW SUBMARINE", 20)
    <<89, 69, 76, 76, 79, 87, 32, 83, 85, 66, 77, 65, 82, 73, 78, 69, 4, 4, 4, 4>>
    iex> Cryptopals.Crypto.pad_pkcs7("YELLOW SUBMARINE", 30) 
    <<89, 69, 76, 76, 79, 87, 32, 83, 85, 66, 77, 65, 82, 73, 78, 69, 14, 14, 14,
      14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14>>
    iex> Cryptopals.Crypto.pad_pkcs7("YELLOW SUBMARINE", 16)
    "YELLOW SUBMARINE"
    iex> Cryptopals.Crypto.pad_pkcs7("YELLOW SUBMARINE", 14)
    "YELLOW SUBMARINE"

  """
  def pad_pkcs7(data, blocksize) when is_binary(data) and is_integer(blocksize) and byte_size(data) < blocksize do
    padding = blocksize - byte_size(data)
    data <> :binary.copy(<<padding>>, padding)
  end


  def pad_pkcs7(data, blocksize) when is_binary(data) and is_integer(blocksize), do: data

end