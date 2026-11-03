//! Dynamic agent briefing and repository skill document generation.
//!
//! Renders structured operational manuals for AI coding agents and scaffolds
//! `<repo>/SKILL.md` during repository initialization.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::agent::AgentError;
use crate::config::local::LocalConfig;
use crate::config::repo::OsInfo;
use crate::config::state::atomic_write_file;

/// Snapshot of the local system configuration and OS environment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentSnapshot {
    pub os_family: String,
    pub os_distro: Option<String>,
    pub default_devices: Vec<String>,
    pub registered_repos: BTreeMap<String, String>,
    pub keyring_ready: bool,
}

impl EnvironmentSnapshot {
    pub fn capture(local_config: &LocalConfig, os_info: &OsInfo, keyring_ready: bool) -> Self {
        Self {
            os_family: os_info.family.clone(),
            os_distro: if os_info.distro.is_empty() || os_info.distro == "unknown" {
                None
            } else {
                Some(os_info.distro.clone())
            },
            default_devices: local_config.default_devices.clone(),
            registered_repos: local_config.repos.clone(),
            keyring_ready,
        }
    }
}

/// Generates the one-shot markdown briefing for AI agents (`dotler ai`).
pub fn render_briefing(
    local_config: &LocalConfig,
    os_info: &OsInfo,
    keyring_ready: bool,
) -> String {
    let snapshot = EnvironmentSnapshot::capture(local_config, os_info, keyring_ready);
    let mut out = String::new();

    out.push_str("# Dotler Agent Briefing\n\n");

    // Section 1: System Overview & Active Device Profile
    out.push_str("## 1. System Overview & Active Device Profile\n");
    out.push_str(&format!("- OS Family: `{}`\n", snapshot.os_family));
    if let Some(ref distro) = snapshot.os_distro {
        out.push_str(&format!("- OS Distro: `{}`\n", distro));
        out.push_str(&format!(
            "- Matching OS Keys: `os-{}`, `os-{}`\n",
            distro, snapshot.os_family
        ));
    } else {
        out.push_str(&format!(
            "- Matching OS Keys: `os-{}`\n",
            snapshot.os_family
        ));
    }
    out.push_str(&format!(
        "- Default Devices Priority: {:?}\n",
        snapshot.default_devices
    ));
    out.push_str("- Registered Repositories:\n");
    if snapshot.registered_repos.is_empty() {
        out.push_str("  - (None configured in ~/.config/dotler/config.toml)\n");
    } else {
        for (label, path) in &snapshot.registered_repos {
            out.push_str(&format!("  - `{}`: `{}`\n", label, path));
        }
    }
    out.push_str(&format!(
        "- OS Keyring Master Password Status: `keyring_ready: {}`\n\n",
        snapshot.keyring_ready
    ));

    // Section 2: Group Layout & Selection Rules
    out.push_str("## 2. Group Layout & Selection Rules (dotler.toml)\n");
    out.push_str("- Single Home Path Rule: All dotfile target paths MUST start with `~/` (e.g. `~/.bashrc`, `~/.config/nvim`). Directory traversal (`..`), backslashes, and shell variables (`$HOME`, `%VAR%`) are strictly prohibited.\n");
    out.push_str("- 3-State Selection Rules (Last-Match-Wins):\n");
    out.push_str("  - `<pattern>`: Include matching files as plaintext.\n");
    out.push_str(
        "  - `<pattern> encrypt`: Include matching files and encrypt using XChaCha20-Poly1305.\n",
    );
    out.push_str("  - `!<pattern>`: Exclude matching files.\n");
    out.push_str("  - Sequential line-by-line evaluation: rules appearing later override earlier declarations.\n");
    out.push_str("- Manifest Example:\n\n");
    out.push_str("```text\n");
    out.push_str("[shell]\n");
    out.push_str("files = \"\"\"\n");
    out.push_str("*\n");
    out.push_str("*.key encrypt\n");
    out.push_str("!*.log\n");
    out.push_str("\"\"\"\n");
    out.push_str("path = \"~\"\n");
    out.push_str("os-linux = \"~\"\n");
    out.push_str("os-macos = \"~\"\n");
    out.push_str("```\n\n");

    // Section 3: Standard Operational Guidelines & Command Cheatsheet
    out.push_str("## 3. Standard Operational Guidelines & Command Cheatsheet\n");
    out.push_str("Always follow the deterministic 5-step agent execution loop:\n");
    out.push_str("1. Inspect or edit `dotler.toml` and dotfiles.\n");
    out.push_str("2. Statically validate configuration: `dotler check --json`\n");
    out.push_str("3. Reconcile formats and clean orphans: `dotler tidy --keep --json`\n");
    out.push_str("4. Pre-simulate operations without disk modification:\n");
    out.push_str("   - For collection: `dotler import --dry-run --json`\n");
    out.push_str("   - For deployment: `dotler export --dry-run --json`\n");
    out.push_str("5. Perform atomic synchronized operations:\n");
    out.push_str("   - `dotler import --json`\n");
    out.push_str("   - `dotler export --json`\n\n");
    out.push_str("MCP Equivalent Tools:\n");
    out.push_str("- `dotler_briefing`: Fetch this briefing and environment status.\n");
    out.push_str("- `dotler_check`: Perform static manifest and path safety checks.\n");
    out.push_str("- `dotler_status`: Reconcile 3-way synchronization state.\n");
    out.push_str("- `dotler_import`: Ingest OS files into repository with atomic staging.\n");
    out.push_str("- `dotler_export`: Deploy repository files with conflict protection.\n");
    out.push_str("- `dotler_tidy`: Reconcile file formats and clean untracked orphans.\n");
    out.push_str("- `dotler_git_ls`: Inspect remote Git repositories before cloning.\n\n");

    // Section 4: Security Guardrails & Prohibitions
    out.push_str("## 4. Security Guardrails & Prohibitions (Zero Secret Leakage)\n");
    out.push_str(
        "- NEVER prompt the user in chat for master passphrases or 12-word recovery mnemonics!\n",
    );
    out.push_str("- If `keyring_ready` is false and an encrypted group needs synchronization, instruct the user to run `dotler key set` once in their local terminal.\n");
    out.push_str("- Plaintext passwords and mnemonics are never accepted via CLI flags or MCP tool arguments.\n");
    out.push_str("- Directory traversal (`..`) and environment variable expansions are blocked by path safety invariants.\n");
    out.push_str(
        "- Never overwrite locally modified files without explicit `--force` user authorization.\n",
    );

    out
}

/// Scaffolds the default `<repo>/SKILL.md` file in the target repository directory.
pub fn scaffold_skill_md(repo_dir: &Path) -> Result<PathBuf, AgentError> {
    let skill_path = repo_dir.join("SKILL.md");

    let content = r#"# Dotler Repository Operational Manual for AI Coding Agents

## Repository Architecture & Standards
This repository is managed by `dotler`, a privacy-first, zero-trace dotfile synchronization engine.
Dotfiles are organized in top-level group directories defined within `dotler.toml`.

## Selection Syntax & Rules (`dotler.toml`)
- Target Path Rule: All deployment targets MUST begin with `~/`.
- 3-State Selection (Last-Match-Wins):
  - `<pattern>`: Plaintext inclusion.
  - `<pattern> encrypt`: Authenticated symmetric encryption (XChaCha20-Poly1305).
  - `!<pattern>`: Exclusion.
  - Later rules override earlier rules.

## Recommended Agent Execution Loop
1. Edit manifests or files.
2. Validate syntax: `dotler check --json`
3. Reconcile encryption formats: `dotler tidy --keep --json`
4. Pre-simulate: `dotler import --dry-run --json` or `dotler export --dry-run --json`
5. Apply atomically: `dotler import --json` or `dotler export --json`

## Security Guardrails
- ZERO SECRET LEAKAGE: Never ask the user for master passwords or recovery phrases in conversation.
- If encryption fails due to a locked vault, direct the user to run `dotler key set` in their terminal.
"#;

    atomic_write_file(&skill_path, content.as_bytes())?;

    Ok(skill_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_init_scaffolds_skill_md() {
        let temp = tempfile::tempdir().unwrap();
        let path = scaffold_skill_md(temp.path()).unwrap();
        assert!(path.is_file());

        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("~/"));
        assert!(content.contains("<pattern> encrypt"));
        assert!(content.contains("ZERO SECRET LEAKAGE"));
    }

    #[test]
    fn test_render_briefing_sections() {
        let cfg = LocalConfig::default();
        let os_info = OsInfo::new("ubuntu", "linux");
        let briefing = render_briefing(&cfg, &os_info, true);

        assert!(briefing.contains("## 1. System Overview & Active Device Profile"));
        assert!(briefing.contains("## 2. Group Layout & Selection Rules"));
        assert!(briefing.contains("## 3. Standard Operational Guidelines & Command Cheatsheet"));
        assert!(briefing.contains("## 4. Security Guardrails & Prohibitions"));
        assert!(briefing.contains("keyring_ready: true"));
    }

    #[test]
    fn test_render_briefing_zero_secret_leakage() {
        let _guard = crate::crypto::keyring::MOCK_KEYRING_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let cfg = LocalConfig::default();
        let os_info = OsInfo::new("debian", "linux");
        let secret = "my_super_secret_password_never_leak_me";

        crate::crypto::keyring::OsKeyring::enable_mock();
        crate::crypto::keyring::OsKeyring::set(&secrecy::SecretString::new(secret.to_string()))
            .unwrap();

        let briefing = render_briefing(&cfg, &os_info, true);

        assert!(!briefing.contains(secret));
        assert!(briefing.contains("keyring_ready: true"));

        crate::crypto::keyring::OsKeyring::disable_mock();
    }

    #[test]
    fn test_environment_snapshot_capture() {
        let mut cfg = LocalConfig {
            default_devices: vec!["workstation".to_string()],
            ..Default::default()
        };
        cfg.repos
            .insert("dotfiles".to_string(), "/home/user/dotfiles".to_string());

        let os_info = OsInfo::new("darwin", "macos");
        let snap = EnvironmentSnapshot::capture(&cfg, &os_info, false);

        assert_eq!(snap.os_family, "macos");
        assert_eq!(snap.default_devices, vec!["workstation"]);
        assert_eq!(snap.registered_repos.len(), 1);
        assert!(!snap.keyring_ready);
    }
}
