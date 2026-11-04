# Migrating from Symlink

## Why dotler didn't adopt symlink

- **Broken links on atomic save**: Many editors and tools save files by writing a temporary file and renaming it, replacing your symlink with a regular file.
- **Unwanted runtime files in Git**: Symlinking an entire config directory exposes cache, lock, and log files directly inside your Git repository.
- **No per-file encryption**: A symlink must point to a plaintext file on disk, so encrypted `.enc` files cannot be stored directly in the repository without a separate build step.
- **Windows permission issues**: Creating symlinks on Windows requires Administrator privileges or Developer Mode.

## How to Migrate

You do not need to remove your existing symlinks manually before switching to `dotler`:

1. Add your dotfile paths to `dotler.toml`.
2. Run `dotler import`: Dotler follows symlinks pointing inside your home directory (`~`) and saves their contents as regular files in your repository.
3. Run `dotler export`: Dotler replaces the old symlinks on your system with standalone regular files.
