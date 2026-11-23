defmodule PageTest do
  use ExUnit.Case, async: true

  @sizes [0, 1, 15, 16, 65_535, 65_536, 65_537, 131_072, 200_000]

  setup do
    %{keys: Page.generate_identity()}
  end

  describe "keys" do
    test "a generated pair is valid and the recipient derives from the identity", %{keys: keys} do
      assert "age1" <> _ = keys.recipient
      assert "AGE-SECRET-KEY-1" <> _ = keys.identity
      assert Page.valid_recipient?(keys.recipient)
      assert {:ok, recipient} = Page.recipient(keys.identity)
      assert recipient == keys.recipient
    end

    test "rejects malformed keys", %{keys: keys} do
      refute Page.valid_recipient?("age1nope")
      refute Page.valid_recipient?(keys.identity)
      refute Page.valid_recipient?(nil)
      refute Page.valid_recipient?(String.replace(keys.recipient, ~r/.$/, "q"))
      assert {:error, :invalid_identity} = Page.recipient("AGE-SECRET-KEY-1nope")
      assert {:error, :invalid_identity} = Page.recipient(keys.recipient)
      assert {:error, :invalid_identity} = Page.recipient(42)
    end

    test "a mixed-case key is not accepted", %{keys: keys} do
      mixed =
        String.upcase(String.slice(keys.recipient, 0, 10)) <>
          String.slice(keys.recipient, 10..-1//1)

      refute Page.valid_recipient?(mixed)
    end

    test "an identity may be written in lowercase", %{keys: keys} do
      assert {:ok, _recipient} = Page.recipient(String.downcase(keys.identity))
    end
  end

  describe "seal and open" do
    test "round trips every size around the chunk boundaries", %{keys: keys} do
      for size <- @sizes do
        data = :crypto.strong_rand_bytes(size)
        assert {:ok, sealed} = Page.seal(data, keys.recipient)
        assert {:ok, ^data} = Page.open(sealed, keys.identity)
      end
    end

    test "accepts iodata", %{keys: keys} do
      assert {:ok, sealed} = Page.seal(["a", ["b", ?c]], keys.recipient)
      assert {:ok, "abc"} = Page.open(sealed, keys.identity)
    end

    test "the sealed page starts with the age header and hides the data", %{keys: keys} do
      assert {:ok, sealed} = Page.seal("very secret text", keys.recipient)
      assert String.starts_with?(sealed, "age-encryption.org/v1\n-> X25519 ")
      refute sealed =~ "very secret"
    end

    test "sealing twice never gives the same bytes", %{keys: keys} do
      assert {:ok, one} = Page.seal("same", keys.recipient)
      assert {:ok, two} = Page.seal("same", keys.recipient)
      refute one == two
    end

    test "any of several recipients can open it", %{keys: keys} do
      other = Page.generate_identity()
      assert {:ok, sealed} = Page.seal("both", [keys.recipient, other.recipient])
      assert {:ok, "both"} = Page.open(sealed, keys.identity)
      assert {:ok, "both"} = Page.open(sealed, other.identity)
      assert {:ok, "both"} = Page.open(sealed, [other.identity, keys.identity])
    end

    test "a different identity cannot open it", %{keys: keys} do
      stranger = Page.generate_identity()
      assert {:ok, sealed} = Page.seal("mine", keys.recipient)
      assert {:error, :no_matching_identity} = Page.open(sealed, stranger.identity)
    end

    test "rejects bad recipients and identities", %{keys: keys} do
      assert {:error, :no_recipients} = Page.seal("x", [])
      assert {:error, :invalid_recipient} = Page.seal("x", "age1nope")
      assert {:error, :invalid_recipient} = Page.seal("x", [keys.recipient, "nope"])
      assert {:ok, sealed} = Page.seal("x", keys.recipient)
      assert {:error, :invalid_identity} = Page.open(sealed, [])
      assert {:error, :invalid_identity} = Page.open(sealed, "nope")
    end
  end

  describe "tampering" do
    setup %{keys: keys} do
      {:ok, sealed} = Page.seal(:crypto.strong_rand_bytes(70_000), keys.recipient)
      %{sealed: sealed}
    end

    test "something that is not a page", %{keys: keys} do
      assert {:error, :not_a_page} = Page.open("hello", keys.identity)
      assert {:error, :not_a_page} = Page.open(<<>>, keys.identity)
    end

    test "a header cut short", %{keys: keys, sealed: sealed} do
      assert {:error, :bad_header} = Page.open(binary_part(sealed, 0, 60), keys.identity)
    end

    test "a flipped byte in the header MAC", %{keys: keys, sealed: sealed} do
      [head, rest] = :binary.split(sealed, "--- ")
      <<first, tail::binary>> = rest
      flipped = head <> "--- " <> <<Bitwise.bxor(first, 1), tail::binary>>
      assert {:error, :bad_header} = Page.open(flipped, keys.identity)
    end

    test "a changed stanza", %{keys: keys, sealed: sealed} do
      changed = String.replace(sealed, "-> X25519 ", "-> X25519 A", global: false)
      assert {:error, reason} = Page.open(changed, keys.identity)
      assert reason in [:bad_header, :no_matching_identity]
    end

    test "a flipped byte in the payload", %{keys: keys, sealed: sealed} do
      at = byte_size(sealed) - 40
      <<before::binary-size(^at), byte, rest::binary>> = sealed
      flipped = <<before::binary, Bitwise.bxor(byte, 1), rest::binary>>
      assert {:error, :corrupt} = Page.open(flipped, keys.identity)
    end

    test "a payload cut at a chunk boundary", %{keys: keys, sealed: sealed} do
      [head, _rest] = :binary.split(sealed, "---")
      mac_end = byte_size(head) + byte_size("---") + 1 + 43 + 1
      cut = binary_part(sealed, 0, mac_end + 16 + 65_536 + 16)
      assert {:error, :corrupt} = Page.open(cut, keys.identity)
    end

    test "a payload with nothing after the header", %{keys: keys, sealed: sealed} do
      [head, mac_and_rest] = :binary.split(sealed, "--- ")
      [mac, _payload] = :binary.split(mac_and_rest, "\n")
      assert {:error, :corrupt} = Page.open(head <> "--- " <> mac <> "\n", keys.identity)
    end
  end

  describe "files" do
    @describetag :tmp_dir

    test "seals and opens a file without leaving a partial one", %{keys: keys, tmp_dir: dir} do
      source = Path.join(dir, "data.tsv")
      sealed = Path.join(dir, "data.tsv.age")
      opened = Path.join(dir, "back.tsv")
      File.write!(source, "a\tb\n1\t2\n")

      assert :ok = Page.seal_file(source, sealed, keys.recipient)
      assert :ok = Page.open_file(sealed, opened, keys.identity)

      assert File.read!(opened) == "a\tb\n1\t2\n"
      refute File.exists?(sealed <> ".part")
      assert File.stat!(sealed).mode |> Bitwise.band(0o777) == 0o600
    end

    test "reports a missing file", %{keys: keys, tmp_dir: dir} do
      assert {:error, :enoent} =
               Page.seal_file(Path.join(dir, "nope"), Path.join(dir, "out"), keys.recipient)

      assert {:error, :enoent} =
               Page.open_file(Path.join(dir, "nope"), Path.join(dir, "out"), keys.identity)

      refute File.exists?(Path.join(dir, "out"))
    end

    test "does not write anything when sealing fails", %{keys: keys, tmp_dir: dir} do
      source = Path.join(dir, "data")
      File.write!(source, "x")
      assert {:error, :invalid_recipient} = Page.seal_file(source, Path.join(dir, "out"), "nope")
      refute File.exists?(Path.join(dir, "out"))
      refute File.exists?(Path.join(dir, "out.part"))
      assert keys
    end

    test "reports a destination that cannot be written", %{keys: keys, tmp_dir: dir} do
      source = Path.join(dir, "data")
      File.write!(source, "x")

      assert {:error, :enoent} =
               Page.seal_file(source, Path.join([dir, "missing", "out"]), keys.recipient)
    end
  end
end
