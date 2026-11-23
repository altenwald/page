<p align="center">
  <img src="assets/logo.svg" alt="Page Logo" width="160">
</p>

# Page

[![Hex Package](https://img.shields.io/hexpm/v/page.svg)](https://hex.pm/packages/page)
[![Hex Docs](https://img.shields.io/badge/hex-docs-purple.svg)](https://hexdocs.pm/page)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/altenwald/page/blob/main/LICENSE)

> A *page* sealed with [age](https://age-encryption.org): the server that seals
> needs only the public key, so it can write archives it cannot read.

Pure Elixir, no external commands: it uses only Erlang's `:crypto`. The format
is the one of the `age` tool (X25519 recipients), so a sealed page can be opened
with `age -d -i key.txt` and a file sealed by `age -r age1...` can be opened
with Page. Passphrases and plugins are not supported.

## Installation

```elixir
def deps do
  [{:page, "~> 0.1"}]
end
```

## Usage

```elixir
%{identity: identity, recipient: recipient} = Page.generate_identity()

{:ok, sealed} = Page.seal("secret", recipient)
{:ok, "secret"} = Page.open(sealed, identity)

:ok = Page.seal_file("archive.tsv", "archive.tsv.age", recipient)
:ok = Page.open_file("archive.tsv.age", "archive.tsv", identity)
```

Keep the identity (`AGE-SECRET-KEY-1...`) away from the server that seals: it
only needs the recipient (`age1...`).

Data is sealed in memory, so it is meant for files that fit comfortably in it.

## License

MIT.
