//! Terminal inline formatting and ANSI report rendering for CLI commands.

use crossterm::style::{Attribute, Color, ResetColor, SetAttribute, SetForegroundColor};
use serde::{Deserialize, Serialize};

pub use crate::core::vault_loader::VaultPasswdReport;

/// Formats the `Error:` label using ANSI 16-color index 9 (Negative Red) and Bold.
pub fn styled_error_label() -> String {
    format!(
        "{}{}Error:{}{}",
        SetForegroundColor(Color::AnsiValue(9)),
        SetAttribute(Attribute::Bold),
        SetAttribute(Attribute::Reset),
        ResetColor,
    )
}

/// Formats the `Hint:` label using ANSI 16-color index 12 (Info Blue) and Bold.
pub fn styled_hint_label() -> String {
    format!(
        "{}{}Hint:{}{}",
        SetForegroundColor(Color::AnsiValue(12)),
        SetAttribute(Attribute::Bold),
        SetAttribute(Attribute::Reset),
        ResetColor,
    )
}

/// Summary report returned by `vault init`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultInitReport {
    pub vault_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mnemonic: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

/// Summary report returned by `vault recover`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultRecoverReport {
    pub vault_id: String,
    pub status: String,
    pub new_mnemonic: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

/// Summary report returned by `key set` and `key del`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyReport {
    pub status: String,
}

/// Summary report returned by `update`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateReport {
    pub status: String,
    pub check_only: bool,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub install_method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upgrade_command: Option<String>,
}

/// Wrapper around [`crate::engine::sync::SyncReport`] for `export` inline formatting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ExportReport(pub crate::engine::sync::SyncReport);

/// Plain-text formatting contract for terminal output.
pub trait InlineRender {
    fn render_inline(&self) -> String;
}

impl InlineRender for () {
    fn render_inline(&self) -> String {
        String::new()
    }
}

impl InlineRender for String {
    fn render_inline(&self) -> String {
        self.clone()
    }
}

impl InlineRender for &str {
    fn render_inline(&self) -> String {
        self.to_string()
    }
}

impl InlineRender for serde_json::Value {
    fn render_inline(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }
}

impl<T: InlineRender> InlineRender for Option<T> {
    fn render_inline(&self) -> String {
        match self {
            Some(v) => v.render_inline(),
            None => String::new(),
        }
    }
}

impl<T: InlineRender> InlineRender for Vec<T> {
    fn render_inline(&self) -> String {
        let lines: Vec<String> = self.iter().map(|item| item.render_inline()).collect();
        lines.join("\n")
    }
}

impl InlineRender for crate::engine::check::InitReport {
    fn render_inline(&self) -> String {
        format!(
            "Init done. ('{}' at '{}', device: {})\n{} {}",
            self.label,
            self.repo_path.display(),
            self.device,
            styled_hint_label(),
            self.hint
        )
    }
}

impl InlineRender for crate::engine::check::CheckReport {
    fn render_inline(&self) -> String {
        format!("☀️ Config is ok. ({} groups)", self.groups_checked)
    }
}

impl InlineRender for crate::engine::sync::FileActionPlan {
    fn render_inline(&self) -> String {
        let mode_label = match (self.is_encrypted, self.is_template) {
            (true, true) => "encrypted+template",
            (true, false) => "encrypted",
            (false, true) => "template",
            (false, false) => "plain",
        };
        format!(
            "[{}] {} -> {:?} ({})",
            self.group_name, self.relative_path, self.status, mode_label
        )
    }
}

impl InlineRender for crate::engine::sync::SyncReport {
    fn render_inline(&self) -> String {
        format!(
            "☀️ Import done. ({} imported, {} skipped)",
            self.processed, self.skipped
        )
    }
}

impl InlineRender for ExportReport {
    fn render_inline(&self) -> String {
        format!(
            "☀️ Export done. ({} exported, {} skipped)",
            self.0.processed, self.0.skipped
        )
    }
}

impl InlineRender for crate::engine::sync::TidyReport {
    fn render_inline(&self) -> String {
        format!(
            "☀️ Tidy done. ({} encrypted, {} decrypted, {} removed, {} purged, {} untracked)",
            self.encrypted_in_repo,
            self.decrypted_in_repo,
            self.removed_from_repo,
            self.removed_os_orphans.len(),
            self.untracked_kept_orphans.len()
        )
    }
}

impl InlineRender for crate::engine::remote::RemoteRepoSummary {
    fn render_inline(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("Remote Repository: {}\n", self.url));
        if self.manifests.is_empty() {
            out.push_str(&format!("Vault Configured: {}\n", self.has_vault));
            out.push_str("Groups:\n");
            for g in &self.groups {
                out.push_str(&format!("  - {} (targets: {:?})\n", g.name, g.target_paths));
            }
        } else {
            for m in &self.manifests {
                out.push_str(&format!("Manifest: {}\n", m.path));
                out.push_str(&format!("  Vault Configured: {}\n", m.has_vault));
                out.push_str("  Groups:\n");
                for g in &m.groups {
                    out.push_str(&format!(
                        "    - {} (targets: {:?})\n",
                        g.name, g.target_paths
                    ));
                }
            }
        }
        out
    }
}

impl InlineRender for crate::engine::remote::CloneReport {
    fn render_inline(&self) -> String {
        format!(
            "☀️ Clone done. ({} groups, '{}')",
            self.cloned_groups.len(),
            self.destination.display()
        )
    }
}

impl InlineRender for crate::engine::remote::InstallReport {
    fn render_inline(&self) -> String {
        format!(
            "☀️ Install done. ({} installed, {} backed up)",
            self.installed_files.len(),
            self.backed_up_files.len()
        )
    }
}

impl InlineRender for crate::engine::remote::UninstallReport {
    fn render_inline(&self) -> String {
        format!(
            "☀️ Uninstall done. ({} removed, {} restored)",
            self.removed_files.len(),
            self.restored_backups.len()
        )
    }
}

impl InlineRender for VaultInitReport {
    fn render_inline(&self) -> String {
        match &self.mnemonic {
            Some(m) => format!(
                "Vault init done. (id: {})\n🔑 Recovery mnemonic: {}",
                self.vault_id, m
            ),
            None => format!("Vault init done. (id: {})", self.vault_id),
        }
    }
}

impl InlineRender for VaultPasswdReport {
    fn render_inline(&self) -> String {
        format!(
            "☀️ Passphrase rotation done. ({} rotated, {} skipped)",
            self.rotated_repos.len(),
            self.skipped_repos.len()
        )
    }
}

impl InlineRender for VaultRecoverReport {
    fn render_inline(&self) -> String {
        format!(
            "☀️ Vault recovery done. (id: {})\n🔑 New recovery mnemonic: {}",
            self.vault_id, self.new_mnemonic
        )
    }
}

impl InlineRender for KeyReport {
    fn render_inline(&self) -> String {
        match self.status.as_str() {
            "keyring_deleted" => "Key delete done.".to_string(),
            _ => "Key set done.".to_string(),
        }
    }
}

impl InlineRender for UpdateReport {
    fn render_inline(&self) -> String {
        let target = self
            .target_version
            .as_deref()
            .unwrap_or(self.version.as_str());
        match self.status.as_str() {
            "updated" => format!("☀️ Update done. (v{} -> v{})", self.version, target),
            "managed_by_package_manager" => {
                let method = self.install_method.as_deref().unwrap_or("package-manager");
                let cmd = self
                    .upgrade_command
                    .as_deref()
                    .unwrap_or("your package manager upgrade command");
                if method == "homebrew-tap" && cmd.contains("brew untap msisdev/tap") {
                    format!(
                        "Update delegated to {method}. (v{} -> v{})\n{} 'dotler' is now in official homebrew-core! Migrate with '{cmd}', or run 'dotler update --force' to replace the binary directly.",
                        self.version,
                        target,
                        styled_hint_label()
                    )
                } else {
                    format!(
                        "Update delegated to {method}. (v{} -> v{})\n{} Run '{cmd}' to update, or 'dotler update --force' to replace the binary directly.",
                        self.version,
                        target,
                        styled_hint_label()
                    )
                }
            }
            "update_available" => match &self.upgrade_command {
                Some(cmd) if cmd.contains("brew untap msisdev/tap") => format!(
                    "Update check done. (v{} -> v{} available)\n{} 'dotler' is now in official homebrew-core! Migrate with '{cmd}'.",
                    self.version,
                    target,
                    styled_hint_label()
                ),
                Some(cmd) => format!(
                    "Update check done. (v{} -> v{} available)\n{} Run '{cmd}' to update.",
                    self.version,
                    target,
                    styled_hint_label()
                ),
                None => format!(
                    "Update check done. (v{} -> v{} available)",
                    self.version, target
                ),
            },
            "cancelled" => String::new(),
            _ => format!("Update check done. (v{}, up to date)", self.version),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::path::PathBuf;

    pub(crate) fn strip_ansi(s: &str) -> String {
        let mut out = String::new();
        let mut chars = s.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\x1b' {
                if chars.peek() == Some(&'[') {
                    chars.next();
                    for ch in chars.by_ref() {
                        if ch.is_ascii_alphabetic() {
                            break;
                        }
                    }
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    fn mk_update(
        status: &str,
        check_only: bool,
        ver: &str,
        target: &str,
        cmd: Option<&str>,
    ) -> UpdateReport {
        UpdateReport {
            status: status.to_string(),
            check_only,
            version: ver.to_string(),
            target_version: Some(target.to_string()),
            install_method: Some(
                if cmd.is_some() {
                    "homebrew-tap"
                } else {
                    "standalone"
                }
                .to_string(),
            ),
            upgrade_command: cmd.map(str::to_string),
        }
    }

    #[test]
    fn test_inline_render_formats_and_emoji_rules() {
        let init_rep = crate::engine::check::InitReport {
            label: "main".into(),
            device: "default".into(),
            repo_path: PathBuf::from("/home/user/dotfiles"),
            hint: "Run 'dotler ai'".into(),
        };
        let init_raw = init_rep.render_inline();
        assert!(init_raw.contains("\x1b[38;5;12m") && !init_raw.contains("☀️"));
        assert_eq!(
            strip_ansi(&init_raw),
            "Init done. ('main' at '/home/user/dotfiles', device: default)\nHint: Run 'dotler ai'"
        );

        let check_rep = crate::engine::check::CheckReport {
            status: "valid".into(),
            groups_checked: 3,
        };
        assert_eq!(check_rep.render_inline(), "☀️ Config is ok. (3 groups)");

        let sync_rep = crate::engine::sync::SyncReport {
            processed: 12,
            skipped: 3,
            conflicts: vec![],
        };
        assert_eq!(
            sync_rep.render_inline(),
            "☀️ Import done. (12 imported, 3 skipped)"
        );
        assert_eq!(
            ExportReport(sync_rep).render_inline(),
            "☀️ Export done. (12 exported, 3 skipped)"
        );

        let tidy_rep = crate::engine::sync::TidyReport {
            encrypted_in_repo: 2,
            decrypted_in_repo: 1,
            removed_from_repo: 3,
            removed_os_orphans: vec![PathBuf::from("a")],
            untracked_kept_orphans: vec![PathBuf::from("b"), PathBuf::from("c")],
        };
        assert_eq!(
            tidy_rep.render_inline(),
            "☀️ Tidy done. (2 encrypted, 1 decrypted, 3 removed, 1 purged, 2 untracked)"
        );

        let clone_rep = crate::engine::remote::CloneReport {
            repo_url: "gh:u/r".into(),
            destination: PathBuf::from("/tmp/dots"),
            cloned_groups: vec!["nvim".into(), "zsh".into()],
        };
        assert_eq!(
            clone_rep.render_inline(),
            "☀️ Clone done. (2 groups, '/tmp/dots')"
        );

        let install_rep = crate::engine::remote::InstallReport {
            installed_files: vec![PathBuf::from("a"), PathBuf::from("b")],
            backed_up_files: vec![PathBuf::from("c")],
        };
        assert_eq!(
            install_rep.render_inline(),
            "☀️ Install done. (2 installed, 1 backed up)"
        );

        let uninstall_rep = crate::engine::remote::UninstallReport {
            removed_files: vec![PathBuf::from("a")],
            restored_backups: vec![PathBuf::from("b"), PathBuf::from("c")],
        };
        assert_eq!(
            uninstall_rep.render_inline(),
            "☀️ Uninstall done. (1 removed, 2 restored)"
        );

        let vinit = VaultInitReport {
            vault_id: "vid-123".into(),
            mnemonic: Some("word1 word2".into()),
            hint: None,
        };
        assert_eq!(
            vinit.render_inline(),
            "Vault init done. (id: vid-123)\n🔑 Recovery mnemonic: word1 word2"
        );
        let vinit_imp = VaultInitReport {
            vault_id: "vid-123".into(),
            mnemonic: None,
            hint: None,
        };
        assert_eq!(vinit_imp.render_inline(), "Vault init done. (id: vid-123)");

        let vpasswd = VaultPasswdReport {
            status: "password_rotated".into(),
            rotated_repos: vec!["a".into(), "b".into()],
            skipped_repos: vec!["c".into()],
            keyring_updated: true,
            already_synced_repos: vec![],
            vault_id: Some("vid-123".into()),
        };
        assert_eq!(
            vpasswd.render_inline(),
            "☀️ Passphrase rotation done. (2 rotated, 1 skipped)"
        );

        let vrec = VaultRecoverReport {
            vault_id: "vid-999".into(),
            status: "recovered".into(),
            new_mnemonic: "new1 new2".into(),
            hint: None,
        };
        assert_eq!(
            vrec.render_inline(),
            "☀️ Vault recovery done. (id: vid-999)\n🔑 New recovery mnemonic: new1 new2"
        );
        assert_eq!(
            KeyReport {
                status: "keyring_updated".into()
            }
            .render_inline(),
            "Key set done."
        );
        assert_eq!(
            KeyReport {
                status: "keyring_deleted".into()
            }
            .render_inline(),
            "Key delete done."
        );

        assert_eq!(
            mk_update("up_to_date", true, "0.1.0", "0.1.0", None).render_inline(),
            "Update check done. (v0.1.0, up to date)"
        );
        assert_eq!(
            mk_update("updated", false, "0.1.0", "0.2.0", None).render_inline(),
            "☀️ Update done. (v0.1.0 -> v0.2.0)"
        );
        assert_eq!(
            strip_ansi(
                &mk_update(
                    "managed_by_package_manager",
                    false,
                    "0.1.0",
                    "0.2.0",
                    Some("brew upgrade msisdev/tap/dotler")
                )
                .render_inline()
            ),
            "Update delegated to homebrew-tap. (v0.1.0 -> v0.2.0)\nHint: Run 'brew upgrade msisdev/tap/dotler' to update, or 'dotler update --force' to replace the binary directly."
        );
        let migrate_cmd =
            "brew uninstall msisdev/tap/dotler && brew untap msisdev/tap && brew install dotler";
        assert_eq!(
            strip_ansi(
                &mk_update(
                    "managed_by_package_manager",
                    false,
                    "0.2.0",
                    "1.0.0",
                    Some(migrate_cmd)
                )
                .render_inline()
            ),
            "Update delegated to homebrew-tap. (v0.2.0 -> v1.0.0)\nHint: 'dotler' is now in official homebrew-core! Migrate with 'brew uninstall msisdev/tap/dotler && brew untap msisdev/tap && brew install dotler', or run 'dotler update --force' to replace the binary directly."
        );
    }
}
