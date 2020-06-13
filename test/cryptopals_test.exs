defmodule CryptopalsTest do
  use ExUnit.Case
  doctest Cryptopals

  @tag set: 1
  @tag challenge: 1
  test "Converting hex to base64" do
    assert Cryptopals.hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d") == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
  end

  @tag set: 1
  @tag challenge: 2
  test "Fixed XOR on hex" do
    assert Cryptopals.fixed_xor("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965") == "746865206b696420646f6e277420706c6179"
  end

  @tag set: 1
  @tag challenge: 3
  test "Single byte XOR cipher" do
  	{plaintext, _score} = Cryptopals.decrypt_single_xored_hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
  	assert plaintext == "Cooking MC's like a pound of bacon"
  end

end
