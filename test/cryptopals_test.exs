defmodule CryptopalsTest do
  use ExUnit.Case, async: true
  doctest Cryptopals
  doctest Cryptopals.Crypto
  doctest Cryptopals.Util

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
    {plaintext, char, _score} = Cryptopals.decrypt_single_xored_hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
    assert plaintext == "Cooking MC's like a pound of bacon"
    assert char == 88
  end

  @tag set: 1
  @tag challenge: 4
  test "Detect single-character XOR" do
    {plaintext, char, _score} = Cryptopals.detect_xor_from_file("data/4.txt")
    assert plaintext == "Now that the party is jumping\n"
    assert char == 53
  end

  @tag set: 1
  @tag challenge: 5
  test "Implement repeating-key XOR" do
    ciphertext = Cryptopals.repeating_key_xor("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", "ICE")
    assert ciphertext == "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
  end

  @tag set: 1
  @tag challenge: 6
  test "Break repeating-key XOR" do
    assert Cryptopals.break_repeating_key_xor_from_file("data/6.txt") == "Terminator X: Bring the noise"
  end

  @tag set: 1
  @tag challenge: 7
  test "AES in ECB mode" do
    data = Cryptopals.decrypt_aes_ecb_from_file("data/7.txt", "YELLOW SUBMARINE")
    assert String.starts_with?(data, "I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \n")
  end

  @tag set: 1
  @tag challenge: 8
  test "Detect AES in ECB mode" do
    {_count, hex} = Cryptopals.detect_aes_ecb_from_file("data/8.txt")
    assert String.starts_with?(hex, "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb57086")
  end

  @tag set: 2
  @tag challenge: 9
  test "Implement PKCS#7 padding" do
    assert <<89, 69, 76, 76, 79, 87, 32, 83, 85, 66, 77, 65, 82, 73, 78, 69, 4, 4, 4, 4>> == Cryptopals.Crypto.pad_pkcs7("YELLOW SUBMARINE", 20)
  end

end
