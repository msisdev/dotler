# Introduction

> **Warning: Experimental / Pre-Release**
> `dotler` is currently under active experimentation and has **not** been officially released yet. Commands, configuration formats, and behavior may change without notice.

**dotler** is a dotfile manager.

A dotfile manager collects configuration files (= dotfiles) scattered across your file system into a single Git repository so you can deploy them across your machines.

## Features

**Configuration**
```toml
# dotler.toml

[ghostty]
os-nux = "~/.config/ghostty"
os-mac = "~/.config/ghostty"
os-win = "~/.config/ghostty"
files = """
*
"""
```
- Select dotfiles in `./dotler.toml`.
- `dotler import` to import dotfiles from file system to dotler directory.
- `dotler export` to export dotfiles from dotler directory to file system.


**Encryption**
```toml
# dotler.toml

vault_id = "26ef..."
password_slot = "L0OX..."
recovery_slot = "1UKW..."

[gh]
os-nux = "~/.config/gh"
os-mac = "~/.config/gh"
os-win = "~/AppData/Roaming/GitHub CLI"
files = """
!*
hosts.yml encrypt
"""
```
- Protect your files with passphrase.
- Mark files with `encrypt` attribute in `./dotler.toml`.
- `dotler import`/`dotler export` will encrypt/decrypt them automatically.


**Git Sharing**
- Publish your dotler repository to Git.
- `dotler git clone` will copy dotfiles from remote to current dotler directory.
- `dotler git install` will copy dotfiles from remote to your OS dotfile.
- dotler recognizes `dotler.toml` in any depth of the repository.


**AI-Ready**
- AI hint (`dotler ai`)
- Built-in AI onboarding hints in `dotler.toml` and `dotler init`.
- AI-friendly terminal output (`--json`).
- Built-in MCP server (`dotler mcp`).



---
*This project was generated with AI.*
