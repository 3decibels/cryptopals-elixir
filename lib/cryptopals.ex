defmodule Cryptopals do
  @moduledoc """
  Documentation for `Cryptopals`.
  """

  @doc """
  Converts a hex string to base64
  Assumes input is lowercase

  ## Examples

      iex> Cryptopals.hex_to_base64("a8b419")
      "qLQZ"

  """
  def hex_to_base64(input) when is_binary(input) do
    input
    |> Base.decode16!(case: :lower)
    |> Base.encode64()
  end


  @doc """
  Performs an XOR on two hex strings of equal size
  Assumes input is lowercase

  ## Examples

      iex> Cryptopals.fixed_xor("1c0111001f01010006", "1a024b53535009181c")
      "6035a534c5108181a"

  """
  def fixed_xor(first, second) when is_binary(first) and is_binary(second) do
    Bitwise.bxor(String.to_integer(first, 16), String.to_integer(second, 16))
    |> Integer.to_string(16)
    |> String.downcase
  end


  @doc """
  Decodes a hex string that has been XORed against a single character and
  determines which character it was most likely XORed against
  Returns the decrypted plaintext and the associated language score
  """
  def decrypt_single_xored_hex(hex) when is_binary(hex) do
    Base.decode16!(hex, case: :lower)
    |> Cryptopals.decrypt_single_xored_ciphertext
  end


  @doc """
  Decodes a ciphertext string that has been XORed against a single character and
  determines which character it was most likely XORed against
  """
  def decrypt_single_xored_ciphertext(ciphertext) when is_binary(ciphertext) do
    plaintexts =
      for char <- 0..256 do
        plaintext = decrypt_single_char_xor(ciphertext, char)
        {_plaintext, score, _frequencies} = Cryptopals.Language.score_language(plaintext)
        {score, char, plaintext}
    end

    [{score, _char, decrypted_plaintext} | _tail] = Enum.sort plaintexts, fn({x, _, _}, {y, _, _}) -> x <= y end
    
    {decrypted_plaintext, score}
  end


  @doc """
  Decrypts a ciphertext using a single character XOR as the key
  Takes a ciphertext as a string and single character as an integer
  Returns plaintext as a string

    ## Examples

      iex(32)> Cryptopals.decrypt_single_char_xor(<<27, 55, 55, 51, 49, 54, 63>>, ?X)
      "Cooking"

  """
  def decrypt_single_char_xor(ciphertext, char) when is_binary(ciphertext) and is_integer(char) do
    :crypto.exor(ciphertext, :binary.copy(<<char>>, byte_size(ciphertext)))
  end


  @doc """
  Decrypts a file of ciphertexts (one text per line) using single character xor
  Returns the plaintext most likely to be valid
  """
  def detect_xor_from_file(path) when is_binary(path) do
    File.stream!(path)
    |> Stream.map(&String.trim/1)
    |> Stream.map(&(Base.decode16!(&1, case: :lower)))
    |> Stream.map(&Cryptopals.decrypt_single_xored_ciphertext/1)
    |> Enum.sort(fn({_, x}, {_, y}) -> x <= y end)
  end

end
