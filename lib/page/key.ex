defmodule Page.Key do
  @moduledoc false
  # age X25519 keys: `age1...` recipients and `AGE-SECRET-KEY-1...` identities.

  alias Page.Bech32

  @doc false
  @spec generate() :: %{identity: String.t(), recipient: String.t()}
  def generate do
    {public, secret} = :crypto.generate_key(:ecdh, :x25519)
    %{identity: encode_identity(secret), recipient: encode_recipient(public)}
  end

  @doc false
  @spec parse_recipient(term()) :: {:ok, binary()} | :error
  def parse_recipient(string) when is_binary(string) do
    case Bech32.decode(string) do
      {:ok, "age", <<_key::binary-size(32)>> = key} -> {:ok, key}
      _other -> :error
    end
  end

  def parse_recipient(_other), do: :error

  @doc false
  @spec parse_identity(term()) :: {:ok, binary()} | :error
  def parse_identity(string) when is_binary(string) do
    case Bech32.decode(string) do
      {:ok, "age-secret-key-", <<_key::binary-size(32)>> = key} -> {:ok, key}
      _other -> :error
    end
  end

  def parse_identity(_other), do: :error

  @doc false
  @spec public_key(binary()) :: binary()
  def public_key(secret) do
    {public, ^secret} = :crypto.generate_key(:ecdh, :x25519, secret)
    public
  end

  @doc false
  @spec encode_recipient(binary()) :: String.t()
  def encode_recipient(public), do: Bech32.encode("age", public)

  @doc false
  @spec encode_identity(binary()) :: String.t()
  def encode_identity(secret), do: "age-secret-key-" |> Bech32.encode(secret) |> String.upcase()
end
