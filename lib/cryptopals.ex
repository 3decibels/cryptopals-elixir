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
        {_plaintext, score} = Cryptopals.Language.score_language(plaintext)
        {score, char, plaintext}
    end

    [{score, char, decrypted_plaintext} | _tail] = Enum.sort plaintexts, fn({x, _, _}, {y, _, _}) -> x <= y end
    
    {decrypted_plaintext, char, score}
  end


  @doc """
  Decrypts a ciphertext using a single character XOR as the key
  Takes a ciphertext as a string and single character as an integer
  Returns plaintext as a string

    ## Examples

      iex> Cryptopals.decrypt_single_char_xor(<<27, 55, 55, 51, 49, 54, 63>>, ?X)
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
    |> Enum.reduce(fn({_, _, x_score} = x, {_, _, y_score} = y) ->
        cond do
          x_score <= y_score -> x
          true -> y
        end
      end)
  end


  @doc """
  Encrypts a plaintext with repeating key XOR
  Returns the hex encoded encrypted ciphertext

    ## Examples

      iex> Cryptopals.repeating_key_xor("I go crazy when I hear a cymbal", "ICE")
      "0063222663263b223f30633221262b690a652126243b632469203c24212425"

  """
  def repeating_key_xor(plaintext, key) when is_binary(plaintext) and is_binary(key) do
    Cryptopals.Util.repeating_key_xor(plaintext, key)
    |> Base.encode16(case: :lower)
  end


  @doc """
  Reads in data and breaks repeating key XOR (Vigenere) encryption.
  Returns the decrypted plaintext and the key
  """
  def break_repeating_key_xor(data, min_keysize, max_keysize) when is_binary(data) and is_integer(min_keysize) and is_integer(max_keysize) do
    {key, _score} = 
      for {keysize, _distance} <- Cryptopals.Util.find_average_hamming_distances(data, 2..40) do
        keysize
      end
      |> Stream.take(4)
      |> Stream.map(&Cryptopals.transpose_blocks(&1, data))
      |> Stream.map(&Cryptopals.find_xor_key_from_transposed_data/1)
      |> Stream.map(fn {keysize, bestchars} -> 
          {key, score} = Enum.reduce(bestchars, {"", 0}, fn {_plaintext, char, score}, {acc_key, acc_score} ->
            {acc_key <> <<char>>, acc_score + score}
          end)
          {key, score / keysize}
        end)
      |> Enum.reduce(fn({_x_key, x_score} = x, {_y_key, y_score} = y) ->
          cond do
            x_score <= y_score -> x
            true -> y
          end
        end)
    key
  end


  @doc """
  Reads in base64 encoded data from a file and breaks repeating key XOR (Vigenere) encryption.
  Returns the key used to encrypt the file.
  """
  def break_repeating_key_xor_from_file(path) when is_binary(path) do
    File.read!(path)
    |> Base.decode64!(ignore: :whitespace)
    |> break_repeating_key_xor(2, 40)
  end


  @doc """
  Reads in base64 encoded data from a file and breaks repeating key XOR (Vignere) encryption.
  Returns the decrypted plaintext.
  """
  def decrypt_repeating_key_xor_from_file(path) when is_binary(path) do
    key = Cryptopals.break_repeating_key_xor_from_file(path)
    File.read!(path)
    |> Base.decode64!(ignore: :whitespace)
    |> Cryptopals.Util.repeating_key_xor(key)
  end


  @doc """
  Takes a blob of data and transposes it into a number of blocks matching the keysize.
  Ex: For a keysize of 5, a block of data will be transposed into 5 blocks.
      Block 1 would have every 1st byte, block 2 every 2nd byte etc.
  """
  def transpose_blocks(keysize, data) when is_integer(keysize) and is_binary(data) do
    transposed = for block <- 1..keysize do
      Cryptopals.Util.create_block_from_data(data, keysize, block)
    end
    {keysize, transposed}
  end


  @doc """
  Takes data broken into blocks and determines the most likely character used as the key for each block
  """
  def find_xor_key_from_transposed_data({keysize, data}) when is_integer(keysize) and is_list(data) do
    result = Enum.map(data, &Cryptopals.decrypt_single_xored_ciphertext/1)
    {keysize, result}
  end

end
