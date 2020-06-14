defmodule Cryptopals.Language do

  @doc """
  Scores phrase based on the likelihood of it being an example of the selected language
  Defaults to English
  """
  def score_language(phrase) when is_binary(phrase), do: score_language(phrase, :english)


  @doc """
  Scores phrase based on the likelihood of it being an example of the selected language
  Lower scores are better
  """
  def score_language(phrase, :english) when is_binary(phrase) do
    # Second implementation of this fuction. First could clear challenge 3 but not 4.
    # Letter frequencies taken from http://pi.math.cornell.edu/~mec/2003-2004/cryptography/subs/frequencies.html
    # Great page on this topic: http://norvig.com/mayzner.html
    expectedfreq = %{"E" => 12.02, "T" => 9.10, "A" => 8.12, "O" => 7.68, "I" => 7.31, "N" => 6.95,
                     "S" => 6.28, "R" => 6.02, "H" => 5.92, "D" => 4.32, "L" => 3.98, "U" => 2.88,
                     "C" => 2.71, "M" => 2.61, "F" => 2.30, "Y" => 2.11, "W" => 2.09, "G" => 2.03,
                     "P" => 1.82, "B" => 1.49, "V" => 1.11, "K" => 0.69, "X" => 0.17, "Q" => 0.11,
                     "J" => 0.10, "Z" => 0.07, "0" => 0.10, "1" => 0.20, "2" => 0.10, "3" => 0.10,
                     "4" => 0.10, "5" => 0.10, "6" => 0.10, "7" => 0.10, "8" => 0.10, "9" => 0.10,
                     " " => 10.0, "'" => 0.10, "," => 0.10, "." => 0.10, "\n" => 0.1}

    phraselength = String.length(phrase)
    score =
      phrase
      |> String.upcase
      |> String.graphemes
      |> Enum.frequencies
      |> Enum.map(fn {char, freq} ->
        cond do
          Map.has_key?(expectedfreq, char) ->
            expected = (expectedfreq[char] / 100) * phraselength
            :math.pow(expected - freq, 2) / expected
          true ->
            :math.pow(0 - freq, 2) / 0.00001
        end
        end)
      |> Enum.sum
      |> :math.sqrt()

    {phrase, score}
  end

end