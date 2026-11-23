defmodule Page.Format do
  @moduledoc false
  # The age v1 header: version line, X25519 stanzas and the header MAC.

  @version "age-encryption.org/v1"
  @zero_nonce <<0::96>>

  @doc false
  @spec hkdf(binary(), binary(), binary()) :: binary()
  def hkdf(ikm, salt, info) do
    prk = :crypto.mac(:hmac, :sha256, salt, ikm)
    :crypto.mac(:hmac, :sha256, prk, info <> <<1>>)
  end

  @doc false
  @spec encode(binary(), [binary()]) :: binary()
  def encode(file_key, recipients) do
    stanzas = Enum.map(recipients, &wrap(file_key, &1))
    unsigned = IO.iodata_to_binary([@version, "\n", stanzas, "---"])
    unsigned <> " " <> b64(header_mac(file_key, unsigned)) <> "\n"
  end

  @doc false
  @spec decode(binary()) ::
          {:ok, %{unsigned: binary(), mac: binary(), stanzas: list(), rest: binary()}} | :error
  def decode(data) do
    with {:ok, @version, rest} <- line(data),
         {:ok, stanzas, mac, tail} <- stanzas(rest, []) do
      header_size = byte_size(data) - byte_size(tail)
      mac_line = byte_size(" ") + byte_size(b64(mac)) + 1
      unsigned = binary_part(data, 0, header_size - mac_line)
      {:ok, %{unsigned: unsigned, mac: mac, stanzas: stanzas, rest: tail}}
    else
      _other -> :error
    end
  end

  @doc false
  @spec unwrap([{binary(), binary()}], binary()) :: {:ok, binary()} | :error
  def unwrap(stanzas, secret) do
    public = Page.Key.public_key(secret)

    Enum.find_value(stanzas, :error, fn
      {["X25519", share], body} -> unwrap_stanza(share, body, secret, public)
      _other -> nil
    end)
  end

  @doc false
  @spec valid_mac?(binary(), binary(), binary()) :: boolean()
  def valid_mac?(file_key, unsigned, mac) do
    :crypto.hash_equals(header_mac(file_key, unsigned), mac)
  end

  defp wrap(file_key, public) do
    {share, ephemeral} = :crypto.generate_key(:ecdh, :x25519)
    shared = :crypto.compute_key(:ecdh, public, ephemeral, :x25519)
    key = hkdf(shared, share <> public, "age-encryption.org/v1/X25519")

    {wrapped, tag} =
      :crypto.crypto_one_time_aead(:chacha20_poly1305, key, @zero_nonce, file_key, <<>>, true)

    ["-> X25519 ", b64(share), "\n", b64(wrapped <> tag), "\n"]
  end

  defp unwrap_stanza(share_b64, body, secret, public) do
    with {:ok, <<_::binary-size(32)>> = share} <- Base.decode64(share_b64, padding: false),
         {:ok, <<wrapped::binary-size(16), tag::binary-size(16)>>} <-
           Base.decode64(body, padding: false),
         shared = :crypto.compute_key(:ecdh, share, secret, :x25519),
         false <- shared == <<0::256>>,
         key = hkdf(shared, share <> public, "age-encryption.org/v1/X25519"),
         file_key when is_binary(file_key) <-
           :crypto.crypto_one_time_aead(
             :chacha20_poly1305,
             key,
             @zero_nonce,
             wrapped,
             <<>>,
             tag,
             false
           ) do
      {:ok, file_key}
    else
      _other -> nil
    end
  end

  defp header_mac(file_key, unsigned) do
    :crypto.mac(:hmac, :sha256, hkdf(file_key, <<>>, "header"), unsigned)
  end

  defp stanzas(data, acc) do
    case line(data) do
      {:ok, "-> " <> args, rest} ->
        {body, rest} = body(rest, [])
        stanzas(rest, [{String.split(args, " "), body} | acc])

      {:ok, "--- " <> mac, rest} ->
        with {:ok, mac} <- Base.decode64(mac, padding: false),
             do: {:ok, Enum.reverse(acc), mac, rest}

      _other ->
        :error
    end
  end

  defp body(data, acc) do
    case line(data) do
      {:ok, text, rest} when byte_size(text) == 64 -> body(rest, [text | acc])
      {:ok, text, rest} -> {IO.iodata_to_binary(Enum.reverse([text | acc])), rest}
      :error -> {IO.iodata_to_binary(Enum.reverse(acc)), data}
    end
  end

  defp line(data) do
    case :binary.split(data, "\n") do
      [text, rest] -> {:ok, text, rest}
      _other -> :error
    end
  end

  defp b64(binary), do: Base.encode64(binary, padding: false)
end
