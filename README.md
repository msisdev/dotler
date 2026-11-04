# dotler

**Official Documentation & Manual**: **[https://msisdev.github.io/dotler/](https://msisdev.github.io/dotler/)**

`dotler` is a privacy-first, deterministic dotfile synchronization engine with selective envelope encryption (`XChaCha20-Poly1305` + `Argon2id` + 12-word BIP-39 recovery), remote Git sharing, and built-in AI/MCP tooling.

## Documentation

Read **[The Dotler Book (https://msisdev.github.io/dotler/)](https://msisdev.github.io/dotler/)** for the complete user guide, configuration reference, and command manual.

## Quick Overview

```sh
dotler init
dotler check
dotler status
dotler import
dotler export
dotler tidy [--purge]
dotler vault <init | passwd | recover>
dotler key <set | del>
dotler git <ls | clone | install | uninstall>
dotler ai
dotler mcp
```
