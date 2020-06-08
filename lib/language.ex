defmodule Cryptopals.Language do

  @doc """
  Scores a list of phrases based on the likelihood of each phrase being an example of the selected language
  Currently only English is supported
  """
  def score_language(phrases, :english) when is_list(phrases) do
    for phrase <- phrases do
      charlist =
        phrase
        |> String.upcase
        |> String.to_charlist
      instances = Enum.count charlist, fn(char) ->
        Enum.member?('ETAOINSHRDLU', char)
      end
      {phrase, instances / String.length(phrase)}
    end
  end
end