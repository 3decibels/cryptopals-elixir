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
  """
  def decrypt_single_xored_hex(hex) when is_binary(hex) do
    ciphertext = Cryptopals.Util.hex_to_charlist(hex)

    plaintexts =
      for char <- 0..256 do
        plaintext = decrypt_single_char_xor(ciphertext, char)
        {_plaintext, score, _frequencies} = Cryptopals.Language.score_language(plaintext)
        {score, char, plaintext}
    end

    [{_score, _char, decrypted_plaintext} | _tail] = Enum.sort plaintexts, fn({x, _, _}, {y, _, _}) -> x <= y end
    
    decrypted_plaintext
  end


  @doc """
  Decrypts a ciphertest using a single character XOR as the key
  Returns plaintext as a string
  """
  def decrypt_single_char_xor(ciphertext, char) when is_list(ciphertext) and is_integer(char) do
    ciphertext
    |> Enum.map(fn x -> Bitwise.bxor(x, char) end)
    |> List.to_string
  end

end
