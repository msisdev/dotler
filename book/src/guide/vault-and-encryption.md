# Vault & Encryption

Dotler provides built-in end-to-end file encryption (`XChaCha20-Poly1305` + `Argon2id`) so you can safely commit sensitive configuration files alongside public dotfiles in the same Git repository.

## 1. Initialize a New Vault

Inside your dotler repository, run:

```sh
dotler vault init
```

- Prompts for a master passphrase (or offers to reuse the passphrase already stored in your OS keyring).
- Generates a random 256-bit Data Encryption Key (`DEK`) and a **12-word recovery mnemonic**.
- Writes `vault_id`, `password_slot`, `recovery_slot`, and an optional `vault_hint` (`--hint "..."`) to the top of `dotler.toml`.

> **Important**: Store your 12-word recovery mnemonic in a safe place. If you forget your passphrase, `dotler vault recover` is the only way to unlock the vault.

## 2. Share or Align a Vault Across Repositories & Devices (`vault from`)

If you maintain multiple dotler repositories (for example, a public repository and a private work repository, or repositories on separate machines) and want them to share the exact same vault (`vault_id`, `password_slot`, and `recovery_slot`), import the existing vault configuration into the target repository:

### From a Remote Git Repository (`vault from git`)

Fetches `dotler.toml` from a remote Git repository without requiring `git` to be installed on your system:

```sh
# Using shorthand or full provider prefix
dotler vault from git gh:username/dotfiles
dotler vault from git github:username/dotfiles

# Or a full HTTPS URL (with optional subdirectory path)
dotler vault from git https://github.com/username/dotfiles/work
```

### From an HTTP / Self-Hosted Endpoint (`vault from url`)

Fetches vault metadata via `HTTP GET`. Parses as **TOML first** (such as a raw `dotler.toml` URL) and **automatically falls back to JSON**:

```sh
# Raw dotler.toml over HTTPS
dotler vault from url https://raw.githubusercontent.com/username/dotfiles/main/dotler.toml

# Or a minimal self-hosted JSON endpoint
dotler vault from url https://vault.example.com/dotler-vault.json
```

Minimal TOML or JSON payloads only need `password_slot` and `recovery_slot` (`vault_id` is verified if present, or derived automatically from the unwrapped key once your passphrase is verified):

```json
{
  "password_slot": "<base64>",
  "recovery_slot": "<base64>",
  "vault_hint": "optional hint"
}
```

### From a Local Repository Label or File Path (`vault from file`)

Reads vault metadata from another repository registered in `~/.config/dotler/config.toml` or from a local TOML/JSON file or directory path:

```sh
# Registered repository label
dotler vault from file main

# Local directory or file path (TOML or JSON)
dotler vault from file ~/other-dotfiles
dotler vault from file ./vault.json
```

In all three subcommands (`file`, `git`, `url`), any `[<group>]` sections in the source file are ignored. If the imported `vault_id` is already registered in your OS keyring, `dotler vault from` unlocks `password_slot` without prompting; otherwise it prompts for the passphrase, verifies `password_slot`, and stores the `vault_id` entry in your OS keyring before writing the vault configuration to the target `dotler.toml`. If the target repository already has `.dotler.enc` or `.dotler.fenc` files encrypted under a different vault, `dotler vault from` automatically decrypts them with the previous vault key and re-encrypts them in memory under the newly imported vault before atomically updating `dotler.toml`.

## 3. Encrypting & Decrypting Files (`enc` / `enc=cont` & `enc=full`)

Add `enc` (`enc=cont` for content-only encryption) or `enc=full` (to encrypt both file/subdirectory names and file contents) to selection rules in `dotler.toml` (combinable with `tpl` for `{{ $HOME }}` substitution):

```toml
[ssh]
os-nux = "~/.ssh"
os-mac = "~/.ssh"
files = """
* enc=full
id_ed25519 enc=cont
config tpl
*.pub
!known_hosts*
"""
```

- `enc` / `enc=cont` (Content Encryption): Stores `<group>/<rel_path>.dotler.enc` in the repository while keeping relative paths readable.
- `enc=full` (Full Path + Content Encryption): Stores `<group>/<32-hex>.dotler.fenc` flattened at the group root with the original relative path encrypted inside the archive (use wildcard or directory rules such as `* enc=full` or `*.pem enc=full` so literal filenames do not appear in `dotler.toml`; `dotler check` emits a hint if a literal filename is written directly with `enc=full`).
- `dotler import` & `dotler export`: Automatically encrypt and decrypt `.dotler.enc` and `.dotler.fenc` files (restoring original nested subdirectories on `export`).
- `dotler tidy`: Converts existing repository files in place across plaintext, `.dotler.enc`, and `.dotler.fenc` whenever selection rules change (and automatically migrates legacy `.enc` / `.fenc` archives whose header matches `vault_id`), pruning empty subdirectories automatically.

### Project-Local File Encryption (`.` / `./...`)

You can also anchor a group path to the current working directory using `.` or `./...` (for example, to encrypt `.env` files inside a project repository while leaving the rest of the project untouched):

```toml
[secrets]
os-nux = "."
os-mac = "."
os-win = "."
files = """
.env enc
config/*.secret enc=full
"""
```

- Paths and symlinks for `.` / `./...` groups are strictly confined within the current working directory (any escape outside `pwd`, into `.git`, or into `<repo>/<group>/` storage is blocked).
- `dotler tidy` only evaluates orphan history within the current working directory so files synced in other projects remain untouched.

### Organizing Encrypted Subfolders (`[vault.<domain>]`)

When tracking a large workspace with `enc=full`, you can split specific domains into dedicated encrypted subdirectories (`vault/problems/`, `vault/sleep/`) using dotted sub-group headers while keeping a top-level `[vault]` fallback for everything else:

```toml
[vault]
os-nux = "./notes"
os-mac = "./notes"
os-win = "./notes"
files = "* enc=full"

[vault.problems]
files = "* enc=full"

[vault.sleep]
files = "* enc=full"
```

- **Root-only paths**: Define `os-*` and device paths **only** on the top-level `[vault]` group. Each `[vault.<sub...>]` sub-group automatically targets `<root_path>/<sub...>` and stores its archives under `<repo>/vault/<sub...>/` (omit `files` on `[vault]` if you only want declared sub-groups synced).
- **Most-specific sub-group wins**: Files under `./notes/sleep` are delegated to `[vault.sleep]` (`vault/sleep/<32-hex>.dotler.fenc`), while root files and unlisted folders fall back to `[vault]` (`vault/<32-hex>.dotler.fenc`).
- **Subtree commands & in-place relocation**: Running `dotler import vault` or `dotler status vault` targets `[vault]` and all `vault.*` sub-groups together, and running `dotler tidy` after adding or removing a sub-group relocates existing archives across `vault/` and `vault/<sub...>/` without losing data.

## 4. OS Keyring Integration

Dotler automatically provisions your master passphrase in your operating system's native credential manager (macOS Keychain, Linux Secret Service / Keyutils, Windows Credential Manager) at vault and repository lifecycle boundaries (`dotler init`, `dotler vault init`, `dotler vault from`, `dotler vault rotate <password|recovery|key>`, `dotler vault recover`) so `import`, `export`, and `tidy` run without prompting every time. Keys are isolated per `vault_id` (so multiple independent repositories with distinct passphrases coexist without conflict), with automatic fallback to the global `default` slot:

```sh
# Inspect vault_id and OS keyring readiness across registered repositories
dotler vault ls

# Register an already-initialized repository's vault passphrase in your OS keyring
dotler vault init
```

## 5. Vault Rotation & Mnemonic Recovery

### Rotate Passphrase (`vault rotate password`)

Re-wraps `password_slot` using your new passphrase without re-encrypting any `.dotler.enc` / `.dotler.fenc` files in the repository. By default, `dotler vault rotate password` updates all locally registered repositories that share the current passphrase and updates the OS keyring in one step:

```sh
dotler vault rotate password
```

### Reissue Recovery Mnemonic (`vault rotate recovery`)

If you lost your 12-word recovery mnemonic (or suspect it was exposed) while you still know your passphrase, reissue `recovery_slot` with a brand-new 12-word mnemonic without changing your passphrase or re-encrypting any files. By default, all locally registered repositories sharing the active `vault_id` are synchronized together (use `-r <repo>` to target a single repository):

```sh
dotler vault rotate recovery
```

### Rotate Master Vault Key (`vault rotate key`)

If you suspect the master vault key itself may have been compromised, generate a brand-new 256-bit master key (`vault_id`), passphrase slot, and 12-word recovery mnemonic, and automatically re-encrypt all `.dotler.enc` and `.dotler.fenc` files in memory across all locally registered repositories sharing the old `vault_id` before committing atomically to disk and updating the OS keyring:

```sh
dotler vault rotate key
```

### Recover Vault (`vault recover`)

If you lose your passphrase, unlock the vault with your 12-word recovery mnemonic and set a new passphrase. Recovery automatically rotates `recovery_slot` and issues a brand-new 12-word recovery mnemonic (single-use mnemonic rotation):

```sh
dotler vault recover
```
