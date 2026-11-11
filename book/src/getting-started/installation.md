# Installation

## Quick Install (One-Liner)

Automatically detects your OS and CPU architecture, downloads the latest prebuilt release binary from GitHub Releases, verifies its SHA-256 checksum, and installs `dotler` to `~/.local/bin`:

**Linux / macOS**:

```sh
curl -fsSL https://msisdev.github.io/dotler/install.sh | sh
```

**Windows (PowerShell)**:

```powershell
irm https://msisdev.github.io/dotler/install.ps1 | iex
```

Optional environment variables for `install.sh` / `install.ps1`:

- `DOTLER_INSTALL_DIR`: Custom installation directory (default: `~/.local/bin`)
- `DOTLER_VERSION`: Specific release tag to install, e.g., `v0.2.0` (default: `latest`)
- `DOTLER_LIBC`: Linux C library variant, `musl` (default, static) or `gnu`

## Install with Package Managers

### Homebrew (macOS & Linux)

```sh
brew install msisdev/tap/dotler
```

### Scoop (Windows)

```powershell
scoop bucket add msisdev https://github.com/msisdev/scoop-bucket
scoop install dotler
```

### WinGet (Windows)

```powershell
winget install msisdev.dotler
```

### Arch Linux (AUR)

```sh
yay -S dotler-bin
# or
paru -S dotler-bin
```

### Nix (`flake.nix`)

```sh
nix profile install github:msisdev/dotler
```

### Debian / Ubuntu (`.deb`), Fedora / RHEL (`.rpm`), Alpine (`.apk`)

Prebuilt `.deb`, `.rpm`, and `.apk` packages are attached to every [GitHub Release](https://github.com/msisdev/dotler/releases/latest):

```sh
# Debian / Ubuntu (x86_64 / amd64)
curl -fsSLO https://github.com/msisdev/dotler/releases/latest/download/dotler_0.2.0_amd64.deb
sudo apt install ./dotler_0.2.0_amd64.deb

# Fedora / RHEL (x86_64)
sudo dnf install https://github.com/msisdev/dotler/releases/latest/download/dotler-0.2.0-1.x86_64.rpm

# Alpine Linux (x86_64)
curl -fsSLO https://github.com/msisdev/dotler/releases/latest/download/dotler_0.2.0_x86_64.apk
sudo apk add --allow-untrusted ./dotler_0.2.0_x86_64.apk
```

## Install with Cargo

Requires Rust `1.89+` and `git`:

```sh
# Install from crates.io
cargo install dotler

# Or install prebuilt binary via cargo-binstall
cargo binstall dotler

# Or build latest main branch directly from GitHub
cargo install --git https://github.com/msisdev/dotler --locked
```

Check the installed version:

```sh
dotler --version
```

## Updating `dotler` (`dotler update`)

`dotler` includes a built-in self-updater that automatically detects how it was installed:

```sh
# Check for newer releases without modifying the binary
dotler update --check

# Update standalone binary to the latest release (or show package manager upgrade hint)
dotler update

# Update non-interactively or target a specific release tag
dotler update -y --version v0.2.0
```

- **Standalone installations (`~/.local/bin/dotler`)**: Downloads the platform release archive, verifies its `SHA-256` checksum, and atomically replaces the executable in place.
- **Package manager installations (`Homebrew`, `Scoop`, `WinGet`, `Nix`, `Cargo`, system packages)**: Preserves package manager integrity and prints the exact upgrade command for your package manager (pass `--force` to override and replace the binary directly).

## Prebuilt Release Binaries

Download the archive or system package matching your operating system and CPU architecture from [GitHub Releases](https://github.com/msisdev/dotler/releases):

| OS | Architecture | Format / Linkage | Release Asset |
| :--- | :--- | :--- | :--- |
| **Linux** | `x86_64` (Intel / AMD 64-bit) | `musl` (Static, Portable) | `dotler-x86_64-unknown-linux-musl.tar.gz` |
| **Linux** | `x86_64` (Intel / AMD 64-bit) | `glibc` (`2.39+`, Dynamic) | `dotler-x86_64-unknown-linux-gnu.tar.gz` |
| **Linux** | `x86_64` (Intel / AMD 64-bit) | Debian / Ubuntu Package | `dotler_<version>_amd64.deb` |
| **Linux** | `x86_64` (Intel / AMD 64-bit) | Fedora / RHEL Package | `dotler-<version>-1.x86_64.rpm` |
| **Linux** | `x86_64` (Intel / AMD 64-bit) | Alpine Linux Package | `dotler_<version>_x86_64.apk` |
| **Linux** | `aarch64` (`ARM64`) | `musl` (Static, Portable) | `dotler-aarch64-unknown-linux-musl.tar.gz` |
| **Linux** | `aarch64` (`ARM64`) | `glibc` (`2.39+`, Dynamic) | `dotler-aarch64-unknown-linux-gnu.tar.gz` |
| **Linux** | `aarch64` (`ARM64`) | Debian / Ubuntu Package | `dotler_<version>_arm64.deb` |
| **Linux** | `aarch64` (`ARM64`) | Fedora / RHEL Package | `dotler-<version>-1.aarch64.rpm` |
| **Linux** | `aarch64` (`ARM64`) | Alpine Linux Package | `dotler_<version>_aarch64.apk` |
| **macOS** | `aarch64` (Apple Silicon M1–M4) | System | `dotler-aarch64-apple-darwin.tar.gz` |
| **macOS** | `x86_64` (Intel Mac) | System | `dotler-x86_64-apple-darwin.tar.gz` |
| **Windows** | `x86_64` (Intel / AMD 64-bit) | MSVC | `dotler-x86_64-pc-windows-msvc.zip` |
| **Windows** | `aarch64` (`ARM64`) | MSVC | `dotler-aarch64-pc-windows-msvc.zip` |

> **BSD (`FreeBSD`, `OpenBSD`, `NetBSD`)**: Install from source using `cargo install dotler`.

### Linux: `glibc` (`-linux-gnu`) vs. `musl` (`-linux-musl`)

- **`-linux-musl` (Recommended for compatibility)**: Statically linked with `musl` libc and has **zero runtime dependency on host `glibc`**. Choose this archive on Alpine Linux, older distributions (Ubuntu 22.04, Debian 12, RHEL 9, etc.), or if you see a `weak version 'GLIBC_2.39' not found` warning.
- **`-linux-gnu`**: Dynamically linked against the system's GNU C Library (`glibc 2.39+`, built on Ubuntu 24.04). Choose this on recent `glibc`-based distributions (Ubuntu 24.04+, Arch Linux, Fedora 40+, Debian Trixie/Sid).

## Local Files (`~/.config/dotler/`)

**dotler** stores machine-local state under `~/.config/dotler/`. Each file is created only when a write operation requires it:

- `config.toml`: Registered repository paths and default device names (created on `dotler init` or `dotler git clone`).
- `state.db`: SQLite database tracking synced and installed files (created on `import`, `export`, `tidy`, or `git install`).
- `backups/`: Original file backups before `dotler git install` overwrites local files.
- `dotler.lock`: Process lock file used during command execution.
