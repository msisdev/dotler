# Quick Start

## 1. Initialize a Repository

Create a directory for your dotfiles and initialize it:

```sh
mkdir ~/dotfiles && cd ~/dotfiles
dotler init
```

`dotler init` creates `dotler.toml` and `SKILL.md` (existing files are never overwritten) and registers the repository in `~/.config/dotler/config.toml`.

## 2. Configure `dotler.toml`

Select the dotfiles to track in `dotler.toml`:

```toml
[shell]
os-linux = "~"
os-macos = "~"
files = """
.zshrc
.gitconfig
"""
```

## 3. Import from Your System

Copy the selected dotfiles from your system into the repository:

```sh
dotler import
```

## 4. Export to Your System

Deploy the repository dotfiles back to your system paths:

```sh
dotler export
```

Use `--dry-run` with `import` or `export` to preview changes without modifying files.
