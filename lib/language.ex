defmodule Cryptopals.Language do

  @doc """
  Scores phrase based on the likelihood of it being an example of the selected language
  Defaults to English
  """
  def score_language(phrase) when is_binary(phrase), do: score_language(phrase, :english)


  @doc """
  Scores phrase based on the likelihood of it being an example of the selected language
  Lower scores are better
  Currently only English is supported
  """
  def score_language(phrase, :english) when is_binary(phrase) do
    # Letter frequencies taken from http://pi.math.cornell.edu/~mec/2003-2004/cryptography/subs/frequencies.html
    expectedfreq = %{'E' => 12.02, 'T' => 9.10, 'A' => 8.12, 'O' => 7.68, 'I' => 7.31, 'N' => 6.95,
                     'S' => 6.28, 'R' => 6.02, 'H' => 5.92, 'D' => 4.32, 'L' => 3.98, 'U' => 2.88}
    charlist =
      phrase
      |> String.upcase
      |> String.to_charlist

    charlist_length = Enum.count(charlist)
    frequencies =
      for char <- List.to_charlist(Map.keys(expectedfreq)) do
        instances = Enum.count(charlist, fn x -> x == char end)
        freq = instances / charlist_length * 100
        deviation = abs(expectedfreq[String.to_charlist(<<char>>)] - freq)
        {char, instances, freq, deviation}
      end

    score = 
      frequencies
      |> Enum.map(fn {_char, _instances, _freq, deviation} -> deviation end)
      |> Enum.reduce(fn x, acc -> x + acc end)
    score = score / Enum.count(frequencies)

    # Add average word length into the mix
    avg_word_length =
      phrase
      |> String.split
      |> Enum.map(fn x -> String.length(x) end)
      |> Enum.reduce(fn x, acc -> x + acc end)
      |> div(Enum.count(String.split(phrase)))
    score = (abs(avg_word_length - 7.0) * 0.5 + score) / 4

    {phrase, score, frequencies}
  end
end