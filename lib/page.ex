defmodule Page do
  @moduledoc """
  Files sealed with [age](https://age-encryption.org), in pure Elixir.

  A page is sealed with one or more public keys (recipients) and can only be
  opened with a matching private key (identity). The server that seals needs
  only the public key, so it can write archives it cannot read. The format is
  the one of the `age` tool (X25519 recipients), so a sealed page can be opened
  with `age -d -i key.txt` and a file sealed by `age -r age1...` can be opened
  here. Passphrases and plugins are not supported.

  ## Example

      %{identity: identity, recipient: recipient} = Page.generate_identity()
      {:ok, sealed} = Page.seal("secret", recipient)
      {:ok, "secret"} = Page.open(sealed, identity)
  """

  alias Page.{Format, Key, Payload}

  @typedoc "A public key: `age1...`."
  @type recipient :: String.t()

  @typedoc "A private key: `AGE-SECRET-KEY-1...`."
  @type identity :: String.t()

  @typedoc "Why a page could not be sealed or opened."
  @type error ::
          :invalid_recipient
          | :invalid_identity
          | :no_recipients
          | :not_a_page
          | :no_matching_identity
          | :bad_header
          | :corrupt
          | File.posix()

  @doc "Generates a new key pair."
  @spec generate_identity() :: %{identity: identity(), recipient: recipient()}
  def generate_identity, do: Key.generate()

  @doc "The public key of an identity."
  @spec recipient(identity()) :: {:ok, recipient()} | {:error, :invalid_identity}
  def recipient(identity) do
    case Key.parse_identity(identity) do
      {:ok, secret} -> {:ok, secret |> Key.public_key() |> Key.encode_recipient()}
      :error -> {:error, :invalid_identity}
    end
  end

  @doc "Whether the string is a valid public key."
  @spec valid_recipient?(term()) :: boolean()
  def valid_recipient?(recipient), do: match?({:ok, _key}, Key.parse_recipient(recipient))

  @doc "Seals `data` for one recipient or a list of them."
  @spec seal(iodata(), recipient() | [recipient()]) :: {:ok, binary()} | {:error, error()}
  def seal(data, recipients) do
    with {:ok, keys} <- parse_recipients(List.wrap(recipients)) do
      file_key = :crypto.strong_rand_bytes(16)
      {:ok, Format.encode(file_key, keys) <> Payload.encrypt(file_key, IO.iodata_to_binary(data))}
    end
  end

  @doc "Opens a sealed page with one identity or a list of them."
  @spec open(binary(), identity() | [identity()]) :: {:ok, binary()} | {:error, error()}
  def open(sealed, identities) do
    with {:ok, secrets} <- parse_identities(List.wrap(identities)),
         {:ok, header} <- decode_header(sealed),
         {:ok, file_key} <- find_file_key(header.stanzas, secrets),
         :ok <- check_mac(file_key, header) do
      Payload.decrypt(file_key, header.rest)
    end
  end

  @doc """
  Seals the file at `source` into `destination`, writing it whole (a partial
  file is never left behind) and readable only by its owner.
  """
  @spec seal_file(Path.t(), Path.t(), recipient() | [recipient()]) :: :ok | {:error, error()}
  def seal_file(source, destination, recipients) do
    with {:ok, data} <- File.read(source),
         {:ok, sealed} <- seal(data, recipients) do
      write(destination, sealed)
    end
  end

  @doc "Opens the sealed file at `source` into `destination`."
  @spec open_file(Path.t(), Path.t(), identity() | [identity()]) :: :ok | {:error, error()}
  def open_file(source, destination, identities) do
    with {:ok, sealed} <- File.read(source),
         {:ok, data} <- open(sealed, identities) do
      write(destination, data)
    end
  end

  defp write(destination, data) do
    part = destination <> ".part"

    with :ok <- File.write(part, data, [:binary]),
         :ok <- File.chmod(part, 0o600) do
      File.rename(part, destination)
    end
  end

  defp parse_recipients([]), do: {:error, :no_recipients}
  defp parse_recipients(list), do: collect(list, &Key.parse_recipient/1, :invalid_recipient)

  defp parse_identities([]), do: {:error, :invalid_identity}
  defp parse_identities(list), do: collect(list, &Key.parse_identity/1, :invalid_identity)

  defp collect(list, parse, reason) do
    Enum.reduce_while(list, {:ok, []}, fn item, {:ok, acc} ->
      case parse.(item) do
        {:ok, key} -> {:cont, {:ok, acc ++ [key]}}
        :error -> {:halt, {:error, reason}}
      end
    end)
  end

  defp decode_header("age-encryption.org/v1\n" <> _rest = sealed) do
    case Format.decode(sealed) do
      {:ok, header} -> {:ok, header}
      :error -> {:error, :bad_header}
    end
  end

  defp decode_header(_other), do: {:error, :not_a_page}

  defp find_file_key(stanzas, secrets) do
    Enum.find_value(secrets, {:error, :no_matching_identity}, fn secret ->
      case Format.unwrap(stanzas, secret) do
        {:ok, file_key} -> {:ok, file_key}
        :error -> nil
      end
    end)
  end

  defp check_mac(file_key, %{unsigned: unsigned, mac: mac}) do
    if Format.valid_mac?(file_key, unsigned, mac), do: :ok, else: {:error, :bad_header}
  end
end
