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
  test "Fixed XOR" do
    assert Cryptopals.fixed_xor("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965") == "746865206b696420646f6e277420706c6179"
  end

  @tag set: 1
  @tag challenge: 3
  test "Single-byte XOR cipher" do
    {plaintext, _score} = Cryptopals.decrypt_single_xored_hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
    assert plaintext == "Cooking MC's like a pound of bacon"
  end

  @tag set: 1
  @tag challenge: 4
  test "Detect single-character XOR" do
    {plaintext, _score} = Cryptopals.detect_xor_from_file("data/4.txt")
    assert plaintext == "Now that the party is jumping\n"
  end

  @tag set: 1
  @tag challenge: 5
  test "Implement repeating-key XOR"do
    ciphertext = Cryptopals.repeating_key_xor("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", "ICE")
    assert ciphertext == "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
  end

end
