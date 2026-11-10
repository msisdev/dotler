# dotler

> **Warning: Experimental / Pre-Release**
> `dotler` is currently under active experimentation and has **not** been officially released yet. Commands, configuration formats, and behavior may change without notice.

**Official Documentation & Manual**: **[https://msisdev.github.io/dotler/](https://msisdev.github.io/dotler/)**

`dotler` is a dotfile manager with selective encryption, Git sharing, and built-in AI/MCP tooling.

## Documentation

Read **[The Dotler Book (https://msisdev.github.io/dotler/)](https://msisdev.github.io/dotler/)** for the user guide, configuration reference, and command manual.

## Installation

**Linux / macOS**:

```sh
curl -fsSL https://msisdev.github.io/dotler/install.sh | sh
```

**Windows (PowerShell)**:

```powershell
irm https://msisdev.github.io/dotler/install.ps1 | iex
```

**Cargo (from source)**:

```sh
cargo install dotler
```

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

---

*This project was generated with AI.*
