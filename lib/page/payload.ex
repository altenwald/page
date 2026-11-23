defmodule Page.Payload do
  @moduledoc false
  # The age payload: 64 KiB chunks of ChaCha20-Poly1305 (STREAM), the last one flagged.

  @chunk 65_536
  @tag 16

  @doc false
  @spec encrypt(binary(), binary()) :: binary()
  def encrypt(file_key, plaintext) do
    nonce = :crypto.strong_rand_bytes(16)
    key = Page.Format.hkdf(file_key, nonce, "payload")
    chunks = chunks(plaintext)
    last = length(chunks) - 1

    body =
      chunks
      |> Enum.with_index()
      |> Enum.map(fn {chunk, index} -> seal_chunk(key, index, index == last, chunk) end)

    IO.iodata_to_binary([nonce | body])
  end

  @doc false
  @spec decrypt(binary(), binary()) :: {:ok, binary()} | {:error, :corrupt}
  def decrypt(file_key, <<nonce::binary-size(16), body::binary>>) when byte_size(body) >= @tag do
    key = Page.Format.hkdf(file_key, nonce, "payload")
    open_chunks(key, body, 0, [])
  end

  def decrypt(_file_key, _payload), do: {:error, :corrupt}

  defp chunks(<<>>), do: [<<>>]
  defp chunks(plaintext), do: split(plaintext, [])

  defp split(<<chunk::binary-size(@chunk), rest::binary>>, acc) when rest != <<>>,
    do: split(rest, [chunk | acc])

  defp split(last, acc), do: Enum.reverse([last | acc])

  defp seal_chunk(key, index, last?, chunk) do
    {ciphertext, tag} =
      :crypto.crypto_one_time_aead(
        :chacha20_poly1305,
        key,
        nonce(index, last?),
        chunk,
        <<>>,
        true
      )

    ciphertext <> tag
  end

  defp open_chunks(key, body, index, acc) do
    size = @chunk + @tag

    case body do
      <<chunk::binary-size(^size), rest::binary>> when rest != <<>> ->
        with {:ok, plain} <- open_chunk(key, index, false, chunk) do
          open_chunks(key, rest, index + 1, [plain | acc])
        end

      last when byte_size(last) >= @tag ->
        open_last(key, last, index, acc)

      _short ->
        {:error, :corrupt}
    end
  end

  # The last chunk may only be empty when it is the only one.
  defp open_last(key, last, index, acc) do
    case open_chunk(key, index, true, last) do
      {:ok, <<>>} when index > 0 -> {:error, :corrupt}
      {:ok, plain} -> {:ok, IO.iodata_to_binary(Enum.reverse([plain | acc]))}
      {:error, reason} -> {:error, reason}
    end
  end

  defp open_chunk(key, index, last?, chunk) do
    size = byte_size(chunk) - @tag
    <<ciphertext::binary-size(^size), tag::binary-size(@tag)>> = chunk

    case :crypto.crypto_one_time_aead(
           :chacha20_poly1305,
           key,
           nonce(index, last?),
           ciphertext,
           <<>>,
           tag,
           false
         ) do
      :error -> {:error, :corrupt}
      plain -> {:ok, plain}
    end
  end

  defp nonce(index, last?), do: <<index::88, if(last?, do: 1, else: 0)::8>>
end
