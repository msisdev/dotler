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

In all three subcommands (`file`, `git`, `url`), any `[<group>]` sections in the source file are ignored. If the imported `vault_id` is already registered in your OS keyring, `dotler vault from` unlocks `password_slot` without prompting; otherwise it prompts for the passphrase, verifies `password_slot`, and stores the `vault_id` entry in your OS keyring before writing the vault configuration to the target `dotler.toml`. If the target repository already has `.enc` files encrypted under a different vault, `dotler vault from` automatically decrypts them with the previous vault key and re-encrypts them in memory under the newly imported vault before atomically updating `dotler.toml`.

## 3. Encrypting & Decrypting Files

Add the `enc` attribute (or `enc tmpl` when combining with `{{ $HOME }}` template substitution) to selection rules in `dotler.toml`:

```toml
[gh]
os-nux = "~/.config/gh"
os-mac = "~/.config/gh"
files = """
config.yml
hosts.yml enc
"""
```

- `dotler import`: Encrypts `hosts.yml` from your system and stores it as `gh/hosts.yml.enc` in the repository.
- `dotler export`: Decrypts `gh/hosts.yml.enc` from the repository and writes plaintext `hosts.yml` to `~/.config/gh/hosts.yml`.
- `dotler tidy`: If you add or remove the `enc` attribute on a file that is already in the repository, run `dotler tidy` to convert existing repository files between plaintext and `.enc` in place.

## 4. OS Keyring Integration

Dotler automatically provisions your master passphrase in your operating system's native credential manager (macOS Keychain, Linux Secret Service / Keyutils, Windows Credential Manager) at vault and repository lifecycle boundaries (`dotler init`, `dotler vault init`, `dotler vault from`, `dotler vault passwd`, `dotler vault recover`) so `import`, `export`, and `tidy` run without prompting every time. Keys are isolated per `vault_id` (so multiple independent repositories with distinct passphrases coexist without conflict), with automatic fallback to the global `default` slot:

```sh
# Inspect vault_id and OS keyring readiness across registered repositories
dotler vault ls

# Register an already-initialized repository's vault passphrase in your OS keyring
dotler vault init
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
