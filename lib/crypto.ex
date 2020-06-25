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


  @doc """
  Encrypts or decrypts data using AES in CBC mode.

  Takes in data, the encryption key, the IV and an atom specifying if the function is encrypting or decrypting (:encrypt or :decrypt)
  """
  def aes_cbc(data, key, iv, direction) when is_binary(data) and is_binary(key) and is_binary(iv) and is_atom(direction) and byte_size(key) == byte_size(iv) do
    encrypt =
      cond do
        direction == :encrypt -> true
        direction == :decrypt -> false
        true -> raise ArgumentError, message: "Must pass either :encrypt or :decrypt as the direction"
      end
    aes_cbc(data, key, iv, encrypt, <<>>)
  end


  defp aes_cbc(data, key, previous, encrypt, acc) when byte_size(data) >= byte_size(key) do
    blocksize = byte_size(key)
    <<block::bytes-size(blocksize), tail::binary>> = data
    block = :crypto.exor(block, previous)
    acc <> :crypto.crypto_one_time(:aes_128_ecb, key, block, encrypt)
    aes_cbc(tail, key, block, encrypt, acc)
  end


  defp aes_cbc(_data, _key, _previous, _encrypt, acc), do: acc

end