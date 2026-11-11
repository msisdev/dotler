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

## 2. Share the Same Vault Across Repositories & Devices

If you maintain multiple dotler repositories (for example, a public repository and a private work repository, or repositories on separate machines) and want them to share the exact same vault (`vault_id`, `password_slot`, and `recovery_slot`), initialize the new repository's vault from an existing source:

### From a Remote Git Repository (`--git`)

Fetches `dotler.toml` from a remote Git repository without requiring `git` to be installed on your system:

```sh
# Using shorthand or full provider prefix
dotler vault init --git gh:username/dotfiles
dotler vault init --git github:username/dotfiles

# Or a full HTTPS URL (with optional subdirectory path)
dotler vault init --git https://github.com/username/dotfiles/work
```

### From an HTTP / Self-Hosted Endpoint (`--url`)

Fetches vault metadata via `HTTP GET`. Parses as **TOML first** (such as a raw `dotler.toml` URL) and **automatically falls back to JSON**:

```sh
# Raw dotler.toml over HTTPS
dotler vault init --url https://raw.githubusercontent.com/username/dotfiles/main/dotler.toml

# Or a minimal self-hosted JSON endpoint
dotler vault init --url https://vault.example.com/dotler-vault.json
```

Minimal TOML or JSON payloads only need `password_slot` and `recovery_slot` (`vault_id` is verified if present, or derived automatically from the unwrapped key once your passphrase is verified):

```json
{
  "password_slot": "<base64>",
  "recovery_slot": "<base64>",
  "vault_hint": "optional hint"
}
```

### From a Local Repository Label or File Path (`--from`)

Reads vault metadata from another repository registered in `~/.config/dotler/config.toml` or from a local TOML/JSON file or directory path:

```sh
# Registered repository label
dotler vault init --from main

# Local directory or file path (TOML or JSON)
dotler vault init --from ~/other-dotfiles
dotler vault init --from ./vault.json
```

In all three modes (`--git`, `--url`, `--from`), any `[<group>]` sections in the source file are ignored, and your passphrase is verified against `password_slot` before writing the vault configuration to the target `dotler.toml`.

## 3. Encrypting & Decrypting Files

Add the `encrypt` attribute to selection rules in `dotler.toml`:

```toml
[gh]
os-nux = "~/.config/gh"
os-mac = "~/.config/gh"
files = """
config.yml
hosts.yml encrypt
"""
```

- `dotler import`: Encrypts `hosts.yml` from your system and stores it as `gh/hosts.yml.enc` in the repository.
- `dotler export`: Decrypts `gh/hosts.yml.enc` from the repository and writes plaintext `hosts.yml` to `~/.config/gh/hosts.yml`.
- `dotler tidy`: If you add or remove the `encrypt` attribute on a file that is already in the repository, run `dotler tidy` to convert existing repository files between plaintext and `.enc` in place.

## 4. OS Keyring Integration

Store your master passphrase in your operating system's native credential manager (macOS Keychain, Linux Secret Service / Keyutils, Windows Credential Manager) so `import`, `export`, and `tidy` run without prompting every time:

```sh
# Save passphrase to OS keyring
dotler key set

# Remove passphrase from OS keyring
dotler key del
```

## 5. Passphrase Rotation & Mnemonic Recovery

### Change Passphrase (`vault passwd`)

Re-wraps `password_slot` using your new passphrase without re-encrypting any `.enc` files in the repository. By default, `dotler vault passwd` updates all locally registered repositories that share the current passphrase and updates the OS keyring in one step:

```sh
dotler vault passwd
```

### Recover Vault (`vault recover`)

If you lose your passphrase, unlock the vault with your 12-word recovery mnemonic and set a new passphrase. Recovery automatically rotates `recovery_slot` and issues a brand-new 12-word recovery mnemonic (single-use mnemonic rotation):

```sh
dotler vault recover
```
