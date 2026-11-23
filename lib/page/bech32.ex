defmodule Page.Bech32 do
  @moduledoc false
  # Bech32 (BIP 173) as age uses it for its keys: no length limit.

  import Bitwise

  @charset ~c"qpzry9x8gf2tvdw0s3jn54khce6mua7l"
  @generator [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]

  @doc false
  @spec encode(String.t(), binary()) :: String.t()
  def encode(hrp, data) do
    hrp = String.downcase(hrp)
    groups = to_groups(data)
    checksum = checksum(hrp, groups)
    hrp <> "1" <> to_string(for g <- groups ++ checksum, do: Enum.at(@charset, g))
  end

  @doc false
  @spec decode(String.t()) :: {:ok, String.t(), binary()} | :error
  def decode(string) do
    with true <- string == String.downcase(string) or string == String.upcase(string),
         string = String.downcase(string),
         [hrp, rest] when hrp != "" and byte_size(rest) >= 6 <- split_last(string),
         {:ok, groups} <- to_values(rest),
         1 <- polymod(hrp_expand(hrp) ++ groups),
         {:ok, data} <- from_groups(Enum.drop(groups, -6)) do
      {:ok, hrp, data}
    else
      _other -> :error
    end
  end

  defp split_last(string) do
    case :binary.matches(string, "1") do
      [] ->
        :error

      matches ->
        {pos, 1} = List.last(matches)
        [binary_part(string, 0, pos), binary_part(string, pos + 1, byte_size(string) - pos - 1)]
    end
  end

  defp to_values(rest) do
    values = for <<c <- rest>>, do: Enum.find_index(@charset, &(&1 == c))
    if Enum.any?(values, &is_nil/1), do: :error, else: {:ok, values}
  end

  defp to_groups(data) do
    pad = rem(5 - rem(bit_size(data), 5), 5)
    bits = <<data::bitstring, 0::size(pad)>>
    for <<g::5 <- bits>>, do: g
  end

  defp from_groups(groups) do
    bits = for g <- groups, into: <<>>, do: <<g::5>>
    bytes = div(bit_size(bits), 8)
    <<data::binary-size(^bytes), rest::bitstring>> = bits
    if bit_size(rest) < 5 and rest == <<0::size(bit_size(rest))>>, do: {:ok, data}, else: :error
  end

  defp checksum(hrp, groups) do
    pm = bxor(polymod(hrp_expand(hrp) ++ groups ++ [0, 0, 0, 0, 0, 0]), 1)
    for i <- 0..5, do: pm |> bsr(5 * (5 - i)) |> band(31)
  end

  defp hrp_expand(hrp) do
    chars = String.to_charlist(hrp)
    Enum.map(chars, &bsr(&1, 5)) ++ [0] ++ Enum.map(chars, &band(&1, 31))
  end

  defp polymod(values) do
    Enum.reduce(values, 1, fn value, chk ->
      top = bsr(chk, 25)
      chk |> band(0x1FFFFFF) |> bsl(5) |> bxor(value) |> mix_generators(top)
    end)
  end

  defp mix_generators(chk, top) do
    @generator
    |> Enum.with_index()
    |> Enum.reduce(chk, &mix_generator(&1, &2, top))
  end

  defp mix_generator({gen, i}, acc, top) do
    if band(bsr(top, i), 1) == 1, do: bxor(acc, gen), else: acc
  end
end
