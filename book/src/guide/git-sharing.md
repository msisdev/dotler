# Git & Remote Sharing

Dotler includes a pure-Rust remote Git and HTTP engine (`gix` + `ureq`). You can inspect, clone, and install dotfiles from remote Git repositories **even on machines where the `git` CLI is not installed**.

## 1. Supported URL Formats & Provider Prefixes

Both `dotler git <ls|clone|install>` and `dotler vault init --git <url>` share the same URL parser. You can pass full URLs or provider prefixes (both shorthand and full names are supported):

| Provider | Shorthand Prefix | Full Name Prefix | Example | Expands To |
| :--- | :--- | :--- | :--- | :--- |
| **GitHub** | `gh:` | `github:` | `gh:user/dots` or `github:user/dots` | `https://github.com/user/dots.git` |
| **GitLab** | `gl:` | `gitlab:` | `gl:user/dots` or `gitlab:user/dots` | `https://gitlab.com/user/dots.git` |
| **Codeberg** | `cb:` | `codeberg:` | `cb:user/dots` or `codeberg:user/dots` | `https://codeberg.org/user/dots.git` |
| **SourceHut** | `srht:` | `sourcehut:` | `srht:~user/dots` or `sourcehut:~user/dots` | `https://git.sr.ht/~user/dots` |
| **Bitbucket** | `bb:` | `bitbucket:` | `bb:user/dots` or `bitbucket:user/dots` | `https://bitbucket.org/user/dots.git` |

### Subdirectory Targeting

If a repository contains multiple `dotler.toml` manifests in subdirectories, append `/<subpath>` to the repository URL:

```sh
dotler git ls github:user/dots/profiles/work
```

## 2. Inspect a Remote Repository (`git ls`)

Preview the `dotler.toml` manifests, group names, target paths, and vault status of a remote repository without modifying your system:

```sh
dotler git ls gh:user/dotfiles
```

## 3. Clone into Your Dotler Repository (`git clone`)

Copy selected groups (or an entire remote dotler repository) into your local dotler repository and merge their group definitions into your local `dotler.toml`:

```sh
# Clone all groups into a new or existing local repository
dotler git clone gh:user/dotfiles

# Clone only specific groups
dotler git clone gh:user/dotfiles nvim zsh
```

- **Cross-Vault Re-Keying**: If the remote repository contains encrypted `.enc` files encrypted under a different vault, `dotler git clone` decrypts them in memory using the source vault passphrase and re-encrypts them under your local repository's vault key without writing intermediate plaintext to disk.

## 4. Install Directly to Your System (`git install` & `git uninstall`)

Deploy specific dotfile groups from a remote repository directly to your OS paths without setting up a local dotler repository:

```sh
# Install specific groups from a remote repository
dotler git install gh:user/dotfiles nvim ghostty

# Override the destination path for a single group
dotler git install gh:user/dotfiles nvim --path ~/.config/nvim-test
```

Before overwriting any existing file on your system, `dotler git install` snapshots the original file into `~/.config/dotler/backups/` and records the installation in `~/.config/dotler/state.db`.

To remove installed remote files and restore your original backups:

```sh
# Roll back specific installed groups (or all installed groups if omitted)
dotler git uninstall nvim
dotler git uninstall
```
