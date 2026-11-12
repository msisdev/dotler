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


**Encryption & Home Path Templates**
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
config.yml tmpl
hosts.yml enc
"""
```
- Protect your files with a passphrase (`dotler vault init`).
- Share the same vault across multiple repositories or devices via `dotler vault init --git`, `--url` (TOML or JSON), or `--from`.
- Mark files with the `enc` attribute in `./dotler.toml` so `dotler import` and `dotler export` encrypt and decrypt them automatically.
- Mark UTF-8 text files with the `tmpl` attribute (or `enc tmpl`) for reversible `{{ $HOME }}` <-> OS home directory substitution across machines.


**Git Sharing (No `git` Binary Required)**
- Publish your dotler repository to Git (`gh:`/`github:`, `gl:`/`gitlab:`, `cb:`/`codeberg:`, `srht:`/`sourcehut:`, `bb:`/`bitbucket:`, or full HTTPS URLs).
- `dotler git clone` copies dotfiles from a remote repository into your local dotler directory.
- `dotler git install` deploys dotfiles from a remote repository directly to your OS paths (with automatic backup & `dotler git uninstall` rollback).
- Built-in pure-Rust Git & HTTP engine works even when `git` is not installed on your system.
- Recognizes `dotler.toml` at any depth of the repository.


**AI-Ready**
- AI hint (`dotler ai`)
- Built-in AI onboarding hints in `dotler.toml` and `dotler init`.
- AI-friendly terminal output (`--json`).
- Built-in MCP server (`dotler mcp`).



---
*This project was generated with AI.*
