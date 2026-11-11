<h1 align="center">dotler</h1>

> **Warning: Experimental / Pre-Release**
> `dotler` is currently under active experimentation and has **not** been officially released yet. Commands, configuration formats, and behavior may change without notice.

`dotler` is a dotfile manager with...
- selective encryption
- git sharing
- built-in AI/MCP tooling

Official documentation & manual: [https://msisdev.github.io/dotler/](https://msisdev.github.io/dotler/)

## Installation

### With Script
Linux / macOS

```sh
curl -fsSL https://msisdev.github.io/dotler/install.sh | sh
```

Windows (PowerShell)

```powershell
irm https://msisdev.github.io/dotler/install.ps1 | iex
```

### With Cargo
```sh
# Build latest version
cargo install dotler

# Or build latest main branch from GitHub
cargo install --git https://github.com/msisdev/dotler --locked
```

## Quick Overview

```sh
dotler init
dotler check
dotler status
dotler import
dotler export
dotler tidy [--purge]
dotler vault init [--git <url> | --url <url> | --from <repo_or_path>]
dotler vault <passwd | recover>
dotler key <set | del>
dotler git <ls | clone | install | uninstall>
dotler ai
dotler mcp
dotler update [--check] [--version <tag>] [--force] [-y]
```

---

*This project was generated with AI.*
