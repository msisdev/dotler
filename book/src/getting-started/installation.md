# Installation

## Install with Cargo

Install `dotler` from GitHub using Cargo (Rust 1.85+):

```sh
cargo install --git https://github.com/msisdev/dotler
```

Verify the installation:

```sh
dotler --version
```

## Supported Platforms

- **Linux**: Secret Service (`D-Bus`) for OS keyring integration.
- **macOS**: Keychain Services for OS keyring integration.
- **Windows**: Credential Manager for OS keyring integration.
- **BSD**: Secret Service (`D-Bus`) for OS keyring integration.

## Local Files (`~/.config/dotler/`)

Every file under `~/.config/dotler/` is created only when a write operation requires it:

- `config.toml`: Created when `dotler init` or `dotler git clone` registers a repository.
- `state.db`: Created when `dotler import`, `dotler export`, `dotler tidy`, or `dotler git install` writes file state.
- `backups/`: Created when `dotler git install` backs up existing local files before replacing them.
- `dotler.lock`: Created when a command acquires the process lock.
