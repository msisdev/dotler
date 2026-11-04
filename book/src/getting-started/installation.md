# Installation

## Install with Cargo

Requires Rust `1.89+` and `git`:

```sh
cargo install dotler
```

Check the installed version:

```sh
dotler --version
```

## Supported Platforms

- **Linux** (`x86_64`, `aarch64`)
- **macOS** (`x86_64`, `aarch64`)
- **Windows** (`x86_64`, `aarch64`)
- **BSD** (`FreeBSD`, `OpenBSD`, `NetBSD`)

## Local Files (`~/.config/dotler/`)

**dotler** stores machine-local state under `~/.config/dotler/`. Each file is created only when a write operation requires it:

- `config.toml`: Registered repository paths and default device names (created on `dotler init` or `dotler git clone`).
- `state.db`: SQLite database tracking synced and installed files (created on `import`, `export`, `tidy`, or `git install`).
- `backups/`: Original file backups before `dotler git install` overwrites local files.
- `dotler.lock`: Process lock file used during command execution.
