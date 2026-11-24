# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.1.1 - 2026-11-24

### Changed

- Simplified `assets/logo.svg` (removed decorative dots and arc).
- Added Prisma static analysis (`mix prisma`) to `ex_check` and ship `page_0.1.1.pplt` in the Hex package.

## 0.1.0 - 2026-11-23

### Added

- Seal and open data and files with the age v1 format, in pure Elixir (X25519
  recipients, ChaCha20-Poly1305 STREAM payload): `Page.seal/2`, `Page.open/2`,
  `Page.seal_file/3`, `Page.open_file/3`.
- Key generation and checks: `Page.generate_identity/0`, `Page.recipient/1`,
  `Page.valid_recipient?/1`.
- Interoperability with the `age` tool in both directions, checked by tests that
  run only when `age` is installed.
