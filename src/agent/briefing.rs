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

/// Official online documentation URL for Dotler.
pub const OFFICIAL_MANUAL_URL: &str = "https://msisdev.github.io/dotler/";

/// Shared static operational guide embedded in both `dotler ai` (`render_briefing`)
/// and `<repo>/SKILL.md` (`scaffold_skill_md`).
pub const SHARED_OPERATIONAL_GUIDE: &str = r#"## 2. Group Layout & Selection Rules (dotler.toml)
- Official Documentation: https://msisdev.github.io/dotler/
- Single Home Path Rule: All dotfile target paths MUST start with `~` or `~/` (e.g. `~/.bashrc`, `~/.config/nvim`). Directory traversal (`..`), backslashes, and shell variables (`$HOME`, `%VAR%`) are strictly prohibited.
- 3-State Selection Rules (Last-Match-Wins):
  - `<pattern>` (or `+<pattern>`): Include matching files as plaintext.
  - `<pattern> encrypt` (or `@<pattern>`): Include matching files and encrypt using XChaCha20-Poly1305 (`.enc`).
  - `!<pattern>`: Exclude matching files.
  - Sequential line-by-line evaluation: rules appearing later override earlier declarations.
- Manifest Example:

```text
[shell]
files = """
*
*.key encrypt
!*.log
"""
os-linux = "~"
os-macos = "~"
```

## 3. Standard Operational Guidelines & Command Cheatsheet
Always follow the deterministic 5-step agent execution loop:
1. Inspect or edit `dotler.toml` and dotfiles.
2. Statically validate configuration: `dotler check --json`
3. Reconcile formats and clean orphans: `dotler tidy --json` (use `dotler tidy --purge --json` to permanently delete orphaned OS files)
4. Pre-simulate operations without disk modification:
   - For collection: `dotler import --dry-run --json`
   - For deployment: `dotler export --dry-run --json`
5. Perform atomic synchronized operations:
   - `dotler import --json`
   - `dotler export --json`

MCP Equivalent Tools:
- `dotler_briefing`: Fetch this briefing and environment status.
- `dotler_check`: Perform static manifest and path safety checks.
- `dotler_status`: Reconcile 3-way synchronization state.
- `dotler_import`: Ingest OS files into repository with atomic staging.
- `dotler_export`: Deploy repository files with conflict protection.
- `dotler_tidy`: Reconcile file formats and clean untracked orphans (`purge: false` by default).
- `dotler_git_ls`: Inspect remote Git repositories before cloning.

## 4. Security Guardrails & Prohibitions (Zero Secret Leakage)
- ZERO SECRET LEAKAGE: NEVER prompt the user in chat for master passphrases or 12-word recovery mnemonics!
- If `keyring_ready` is false and an encrypted group needs synchronization, instruct the user to run `dotler key set` once in their local terminal.
- `dotler vault passwd` rotates the passphrase across all matching locally registered repositories and updates the OS keyring in one shot.
- Symbolic links are strictly prohibited inside the repository (exit code 3). On the OS side, symlinks pointing to regular files inside `~` are dereferenced on `import` and materialized into standalone regular files on `export`.
- Directory traversal (`..`), symlinks escaping `~`, and environment variable expansions are blocked by path safety invariants (exit code 3).
- Never overwrite locally modified files without explicit `--force` user authorization.
"#;

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

    out.push_str(SHARED_OPERATIONAL_GUIDE);
    out
}

/// Scaffolds the default `<repo>/SKILL.md` file in the target repository directory.
pub fn scaffold_skill_md(repo_dir: &Path) -> Result<PathBuf, AgentError> {
    let skill_path = repo_dir.join("SKILL.md");

    let mut content = String::from(
        "# Dotler Repository Operational Manual for AI Coding Agents\n\n\
         ## 1. Repository Architecture & Standards\n\
         - This repository is managed by `dotler`, a privacy-first, deterministic dotfile synchronization engine.\n\
         - Dotfiles are organized in top-level group directories defined within `dotler.toml`.\n\
         - Run `dotler ai` (or MCP `dotler_briefing`) to inspect live device/OS keys and keyring status on the current machine.\n\n",
    );
    content.push_str(SHARED_OPERATIONAL_GUIDE);

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
