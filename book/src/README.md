# Introduction

**dotler** is a dotfile manager.

A dotfile manager collects configuration files (= dotfiles) scattered across your file system into a single Git repository so you can deploy them across your machines.

## Features

**Configuration**
- Select dotfiles in `./dotler.toml` file.
- `dotler import` to import dotfiles from file system to dotler directory.
- `dotler export` to export dotfiles from dotler directory to file system.


**Encryption**
- Protect your files with passphrase.
- Mark files with `encrypt` attribute in `./dotler.toml`.
- `dotler import`/`dotler export` will encrypt/decrypt them automatically.


**Git Sharing**
- Publish your dotler repository to Git.
- `dotler git clone` will copy dotfiles from remote to current dotler directory.
- `dotler git install` will copy dotfiles from remote to your OS dotfile.


**AI-Ready**
- AI-friendly terminal output (`--json`, `dotler ai`).
- Automatic `SKILL.md` generation.
- Built-in MCP server (`dotler mcp`).
