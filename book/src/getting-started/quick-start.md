# Quick Start

## 1. Initialize a Repository

Create a directory for your dotfiles and initialize it:

```sh
mkdir ~/dotfiles && cd ~/dotfiles
dotler init
```

`dotler init` creates `dotler.toml` (existing files are never overwritten), registers the repository in `~/.config/dotler/config.toml`, and prints an onboarding hint for `dotler ai`.

## 2. Configure `dotler.toml`

Select the dotfiles to track in `dotler.toml`:

```toml
[shell]
os-nux = "~"
os-mac = "~"
files = """
.zshrc
.gitconfig tmpl
.netrc enc
"""
```

Group target paths can start with `~` / `~/...` (home directory) or `.` / `./...` (current working directory, useful for project-local `.env` or secret files kept inside a project repository without escaping the current directory):

```toml
[secrets]
os-nux = "."
os-mac = "."
os-win = "."
files = """
.env enc
"""
```

- `<pattern>`: Include matching file or directory as plaintext.
- `<pattern> enc` (or `<pattern> enc=cont`): Include matching file or directory with content-only encryption (`<rel_path>.dotler.enc`).
- `<pattern> enc=full`: Include matching file or directory with full path + content encryption (`<group>/<32-hex>.dotler.fenc`), hiding subdirectory and file names in the repository.
- `<pattern> tmpl`: Include matching UTF-8 text file or directory with reversible `{{ $HOME }}` <-> OS home directory substitution (`import` replaces your home path with `{{ $HOME }}`; `export` and `git install` render `{{ $HOME }}` to the target machine's home path).
- `<pattern> enc tmpl` / `<pattern> enc=full tmpl`: Combine `.dotler.enc` or `.dotler.fenc` encryption with `{{ $HOME }}` template substitution.
- `!<pattern>`: Exclude matching file or directory.
- `[<group>.<sub...>]` (Dotted sub-groups): Organize subdirectories into `<group>/<sub...>/` inside the repository. Define `os-*` / device paths only on the top-level `[<group>]` section (`<root_path>/<sub...>` is derived automatically, and running `dotler import <group>` targets the entire `<group>.*` subtree).

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
