defmodule Page.InteropTest do
  use ExUnit.Case, async: true

  @moduletag :interop
  @moduletag :tmp_dir

  @sizes [0, 1, 65_535, 65_536, 65_537, 200_000]

  defp age(args) do
    {out, status} = System.cmd("age", args, stderr_to_stdout: true)
    {status, out}
  end

  defp keygen(dir) do
    path = Path.join(dir, "key.txt")
    {_out, 0} = System.cmd("age-keygen", ["-o", path], stderr_to_stdout: true)
    {recipient, 0} = System.cmd("age-keygen", ["-y", path])

    identity =
      path
      |> File.read!()
      |> String.split("\n")
      |> Enum.find(&String.starts_with?(&1, "AGE-SECRET-KEY-"))

    %{path: path, recipient: String.trim(recipient), identity: identity}
  end

  test "reads the public key of an age identity", %{tmp_dir: dir} do
    key = keygen(dir)
    assert {:ok, recipient} = Page.recipient(key.identity)
    assert recipient == key.recipient
    assert Page.valid_recipient?(key.recipient)
  end

  test "the age tool opens what Page seals", %{tmp_dir: dir} do
    key = keygen(dir)

    for size <- @sizes do
      data = :crypto.strong_rand_bytes(size)
      sealed = Path.join(dir, "sealed-#{size}")
      File.write!(sealed, elem(Page.seal(data, key.recipient), 1))

      {out, 0} = System.cmd("age", ["-d", "-i", key.path, sealed])
      assert out == data
    end
  end

  test "Page opens what the age tool seals", %{tmp_dir: dir} do
    key = keygen(dir)

    for size <- @sizes do
      data = :crypto.strong_rand_bytes(size)
      plain = Path.join(dir, "plain-#{size}")
      sealed = Path.join(dir, "age-#{size}")
      File.write!(plain, data)

      assert {0, ""} = age(["-r", key.recipient, "-o", sealed, plain])
      assert {:ok, ^data} = Page.open(File.read!(sealed), key.identity)
    end
  end

  test "Page opens a page the age tool sealed for several recipients", %{tmp_dir: dir} do
    one = keygen(Path.join(dir, "")) |> Map.put(:dir, dir)
    plain = Path.join(dir, "plain")
    sealed = Path.join(dir, "multi")
    other = Page.generate_identity()
    File.write!(plain, "shared")

    assert {0, ""} = age(["-r", one.recipient, "-r", other.recipient, "-o", sealed, plain])
    assert {:ok, "shared"} = Page.open(File.read!(sealed), other.identity)
    assert {:ok, "shared"} = Page.open(File.read!(sealed), one.identity)
  end
end
