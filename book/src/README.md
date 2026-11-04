# Introduction

**Dotler** is a dotfile manager.

A dotfile manager collects configuration files scattered across your system into a single Git repository and deploys them across your machines.

## Core Features

- **Configuration**: Select dotfiles in `dotler.toml` and sync them with `dotler import` and `dotler export`.
- **Encryption**: Store your passphrase in the OS keyring and mark files with `encrypt` in `dotler.toml` to encrypt and decrypt them automatically.
- **Git Sharing**: Publish your repository to Git and clone or install your dotfiles onto any machine with a single command.
- **AI-Ready**: AI-friendly terminal output (`--json`, `dotler ai`), automatic `SKILL.md` generation, and a built-in MCP server (`dotler mcp`).
