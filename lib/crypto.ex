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
    with {:ok, key} <- check_key_size(key)
    do
      aes_cbc(data, key, iv, direction, <<>>)
    end
  end


  defp aes_cbc(data, key, previous, :encrypt, acc) when byte_size(data) >= byte_size(key) do
    blocksize = byte_size(key)
    <<block::bytes-size(blocksize), tail::binary>> = data
    block = :crypto.crypto_one_time(:aes_128_ecb, key, :crypto.exor(block, previous), true)
    acc = acc <> block
    aes_cbc(tail, key, block, :encrypt, acc)
  end


  defp aes_cbc(data, key, previous, :decrypt, acc) when byte_size(data) >= byte_size(key) do
    blocksize = byte_size(key)
    <<block::bytes-size(blocksize), tail::binary>> = data
    finished_block = :crypto.exor(:crypto.crypto_one_time(:aes_128_ecb, key, block, false), previous)
    acc = acc <> finished_block
    aes_cbc(tail, key, block, :decrypt, acc)
  end


  defp aes_cbc(_data, _key, _previous, _encrypt, acc), do: acc


  @doc """
  Checks that the byte size of a given key is a multiple of 16
  """
  def check_key_size(key) when is_binary(key) do
    cond do
      rem(byte_size(key), 16) == 0 -> {:ok, key}
      true -> {:error, "Bad keysize"}
    end
  end

end