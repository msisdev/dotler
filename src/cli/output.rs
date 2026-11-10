//! Formatting, structured JSON envelopes, and deterministic process exit codes.

use crossterm::style::{Attribute, Color, ResetColor, SetAttribute, SetForegroundColor};
use serde::{Deserialize, Serialize};
use std::io::Write;

pub use crate::core::vault_loader::VaultPasswdReport;

pub const EXIT_SUCCESS: i32 = 0;
pub const EXIT_SYNC_CONFLICT: i32 = 1;
pub const EXIT_CONFIG_OR_ARGS_ERROR: i32 = 2;
pub const EXIT_SECURITY_BLOCKED: i32 = 3;
pub const EXIT_AUTH_OR_LOCK_ERROR: i32 = 4;

/// Common top-level structured JSON success envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonEnvelope<T> {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    pub data: Option<T>,
}

impl<T: Serialize> JsonEnvelope<T> {
    pub fn success(command: impl Into<String>, data: T) -> Self {
        Self {
            ok: true,
            command: Some(command.into()),
            data: Some(data),
        }
    }
}

/// Actionable, structured error payload for AI agents and scripts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonErrorPayload {
    pub ok: bool,
    pub error_code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    pub hint: String,
}

impl JsonErrorPayload {
    pub fn new(
        error_code: impl Into<String>,
        message: impl Into<String>,
        location: Option<String>,
        hint: impl Into<String>,
    ) -> Self {
        Self {
            ok: false,
            error_code: error_code.into(),
            message: message.into(),
            location,
            hint: hint.into(),
        }
    }
}

/// Unified error enum for the CLI boundary layer.
#[derive(Debug)]
pub enum CliError {
    Config(crate::config::ConfigError),
    State(crate::config::StateError),
    Lock(crate::config::LockError),
    Crypto(crate::crypto::CryptoError),
    Vault(crate::crypto::vault::VaultError),
    Keyring(crate::crypto::keyring::KeyringError),
    Engine(crate::engine::EngineError),
    Args(String),
    Io(std::io::Error),
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config(e) => write!(f, "Configuration error: {e}"),
            Self::State(e) => write!(f, "State ledger error: {e}"),
            Self::Lock(e) => write!(f, "Lock error: {e}"),
            Self::Crypto(e) => write!(f, "Cryptographic error: {e}"),
            Self::Vault(e) => write!(f, "Vault error: {e}"),
            Self::Keyring(e) => write!(f, "Keyring error: {e}"),
            Self::Engine(e) => write!(f, "Engine error: {e}"),
            Self::Args(m) => write!(f, "CLI argument error: {m}"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for CliError {}

impl From<crate::config::ConfigError> for CliError {
    fn from(e: crate::config::ConfigError) -> Self {
        Self::Config(e)
    }
}

impl From<crate::config::StateError> for CliError {
    fn from(e: crate::config::StateError) -> Self {
        Self::State(e)
    }
}

impl From<crate::config::LockError> for CliError {
    fn from(e: crate::config::LockError) -> Self {
        Self::Lock(e)
    }
}

impl From<crate::crypto::CryptoError> for CliError {
    fn from(e: crate::crypto::CryptoError) -> Self {
        Self::Crypto(e)
    }
}

impl From<crate::crypto::vault::VaultError> for CliError {
    fn from(e: crate::crypto::vault::VaultError) -> Self {
        Self::Vault(e)
    }
}

impl From<crate::crypto::keyring::KeyringError> for CliError {
    fn from(e: crate::crypto::keyring::KeyringError) -> Self {
        Self::Keyring(e)
    }
}

impl From<crate::engine::EngineError> for CliError {
    fn from(e: crate::engine::EngineError) -> Self {
        Self::Engine(e)
    }
}

impl From<std::io::Error> for CliError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl CliError {
    pub fn exit_code(&self) -> i32 {
        match self {
            CliError::Config(e) => e.exit_code(),
            CliError::State(e) => e.exit_code(),
            CliError::Lock(e) => e.exit_code(),
            CliError::Crypto(e) => e.exit_code(),
            CliError::Vault(e) => e.exit_code(),
            CliError::Keyring(e) => e.exit_code(),
            CliError::Engine(e) => e.exit_code(),
            CliError::Args(_) => EXIT_CONFIG_OR_ARGS_ERROR,
            CliError::Io(_) => EXIT_CONFIG_OR_ARGS_ERROR,
        }
    }

    pub fn error_code(&self) -> String {
        match self {
            CliError::Engine(e) => e.error_code().to_string(),
            CliError::Config(crate::config::ConfigError::HardBlockedPath { .. }) => {
                "SECURITY_BLOCKED".to_string()
            }
            CliError::Config(crate::config::ConfigError::InvalidSelectionAttribute { .. }) => {
                "INVALID_ATTRIBUTE".to_string()
            }
            CliError::Config(crate::config::ConfigError::CrossGroupFileCollision { .. }) => {
                "GROUP_COLLISION".to_string()
            }
            CliError::Config(crate::config::ConfigError::UnknownField { .. }) => {
                "UNKNOWN_FIELD".to_string()
            }
            CliError::Config(crate::config::ConfigError::UnknownOsKey { .. }) => {
                "UNKNOWN_OS_KEY".to_string()
            }
            CliError::Config(crate::config::ConfigError::TomlSyntaxError(_)) => {
                "SYNTAX_ERROR".to_string()
            }
            CliError::Config(_) => "CONFIG_ERROR".to_string(),
            CliError::State(_) => "STATE_ERROR".to_string(),
            CliError::Lock(crate::config::LockError::Timeout { .. }) => "LOCK_TIMEOUT".to_string(),
            CliError::Lock(_) => "LOCK_ERROR".to_string(),
            CliError::Vault(crate::crypto::vault::VaultError::InvalidSecret) => {
                "INVALID_SECRET".to_string()
            }
            CliError::Vault(crate::crypto::vault::VaultError::VaultIdMismatch { .. }) => {
                "VAULT_ID_MISMATCH".to_string()
            }
            CliError::Vault(crate::crypto::vault::VaultError::DecryptionFailed(_)) => {
                "DECRYPTION_FAILED".to_string()
            }
            CliError::Vault(_) => "VAULT_ERROR".to_string(),
            CliError::Keyring(
                crate::crypto::keyring::KeyringError::PassphraseRequiredInNonInteractiveMode,
            ) => "PASSPHRASE_REQUIRED".to_string(),
            CliError::Keyring(crate::crypto::keyring::KeyringError::PromptCancelled) => {
                "PROMPT_CANCELLED".to_string()
            }
            CliError::Keyring(_) => "KEYRING_ERROR".to_string(),
            CliError::Crypto(_) => "CRYPTO_ERROR".to_string(),
            CliError::Args(_) => "CLI_ARGS_ERROR".to_string(),
            CliError::Io(_) => "IO_ERROR".to_string(),
        }
    }

    pub fn location(&self) -> Option<String> {
        match self {
            CliError::Config(crate::config::ConfigError::InvalidSelectionAttribute {
                line_no,
                ..
            }) => Some(format!("dotler.toml:{line_no}")),
            CliError::Config(crate::config::ConfigError::CrossGroupFileCollision {
                path, ..
            }) => Some(path.clone()),
            CliError::Config(crate::config::ConfigError::HardBlockedPath { path, .. }) => {
                Some(path.clone())
            }
            CliError::Engine(crate::engine::EngineError::SyncConflict { path, .. }) => {
                Some(path.display().to_string())
            }
            CliError::Engine(crate::engine::EngineError::EncryptionMismatch { path, .. }) => {
                Some(path.display().to_string())
            }
            CliError::Engine(crate::engine::EngineError::HardBlockedPath { path, .. }) => {
                Some(path.display().to_string())
            }
            CliError::Engine(crate::engine::EngineError::FileNotFound { path }) => {
                Some(path.display().to_string())
            }
            CliError::Lock(crate::config::LockError::Timeout { .. }) => {
                Some("~/.config/dotler/dotler.lock".to_string())
            }
            _ => None,
        }
    }

    pub fn hint(&self) -> String {
        match self {
            CliError::Engine(e) => e.hint(),
            CliError::Config(crate::config::ConfigError::InvalidSelectionAttribute {
                hint,
                ..
            }) => hint.clone(),
            CliError::Config(crate::config::ConfigError::UnknownField { hint, .. }) => hint.clone(),
            CliError::Config(crate::config::ConfigError::UnknownOsKey { hint, .. }) => hint.clone(),
            CliError::Config(crate::config::ConfigError::HardBlockedPath { path, .. }) => {
                format!(
                    "Path '{path}' violates path security rules. Ensure targets remain within home directory and contain no '..' components."
                )
            }
            CliError::Config(crate::config::ConfigError::CrossGroupFileCollision {
                path,
                group1,
                group2,
            }) => {
                format!(
                    "Target '{path}' is claimed by both '{group1}' and '{group2}'. Disambiguate with explicit pattern negation (!{path})."
                )
            }
            CliError::Config(crate::config::ConfigError::MissingVaultConfig) => {
                "Run 'dotler vault init' to initialize vault encryption before syncing encrypted files.".to_string()
            }
            CliError::Config(e) => format!("Fix configuration error: {e}"),
            CliError::Lock(crate::config::LockError::Timeout { .. }) => {
                "Another dotler process holds ~/.config/dotler/dotler.lock. Wait for it to complete or terminate stale processes.".to_string()
            }
            CliError::Vault(crate::crypto::vault::VaultError::InvalidSecret) => {
                "Passphrase authentication failed. Verify passphrase or use 'dotler vault recover'.".to_string()
            }
            CliError::Keyring(
                crate::crypto::keyring::KeyringError::PassphraseRequiredInNonInteractiveMode,
            ) => {
                "Passphrase required. Run 'dotler key set' to register in keyring or export DOTLER_PASSPHRASE.".to_string()
            }
            CliError::Args(msg) => format!("Correct argument usage: {msg}"),
            _ => "Review command syntax and local configuration.".to_string(),
        }
    }

    pub fn to_json_payload(&self) -> JsonErrorPayload {
        JsonErrorPayload::new(
            self.error_code(),
            self.to_string(),
            self.location(),
            self.hint(),
        )
    }
}

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
        format!(
            "[{}] {} -> {:?} ({})",
            self.group_name,
            self.relative_path,
            self.status,
            if self.is_encrypted {
                "encrypted"
            } else {
                "plain"
            }
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
        format!("Update check done. (v{}, up to date)", self.version)
    }
}

/// Success output renderer writing to custom writer.
pub fn render_success_to<W: Write, T>(
    writer: &mut W,
    command_name: &str,
    data: &T,
    json_mode: bool,
) -> i32
where
    T: Serialize + InlineRender,
{
    if json_mode {
        let envelope = JsonEnvelope::success(command_name, data);
        let s = serde_json::to_string(&envelope).expect("JSON serialization cannot fail");
        let _ = writeln!(writer, "{s}");
    } else {
        let text = data.render_inline();
        if !text.is_empty() {
            let _ = writeln!(writer, "{text}");
        }
    }
    EXIT_SUCCESS
}

/// Success output renderer writing to stdout.
pub fn render_success<T>(command_name: &str, data: &T, json_mode: bool) -> i32
where
    T: Serialize + InlineRender,
{
    let mut stdout = std::io::stdout();
    render_success_to(&mut stdout, command_name, data, json_mode)
}

/// Error output renderer writing to custom stdout and stderr writers.
pub fn render_error_to<W1: Write, W2: Write>(
    stdout: &mut W1,
    stderr: &mut W2,
    error: &CliError,
    json_mode: bool,
) -> i32 {
    let code = error.exit_code();
    let payload = error.to_json_payload();

    if json_mode {
        let s = serde_json::to_string(&payload).expect("JSON serialization cannot fail");
        let _ = writeln!(stdout, "{s}");
    } else {
        let _ = writeln!(stderr, "{} {}", styled_error_label(), payload.message);
        if let Some(ref loc) = payload.location {
            let _ = writeln!(stderr, "Location: {loc}");
        }
        let _ = writeln!(stderr, "{} {}", styled_hint_label(), payload.hint);
    }

    code
}

/// Renders EngineError directly to custom stdout and stderr writers.
pub fn render_engine_error<W1: Write, W2: Write>(
    stdout: &mut W1,
    stderr: &mut W2,
    err: &crate::engine::EngineError,
    json_mode: bool,
) -> i32 {
    let location = match err {
        crate::engine::EngineError::SyncConflict { path, .. }
        | crate::engine::EngineError::EncryptionMismatch { path, .. }
        | crate::engine::EngineError::HardBlockedPath { path, .. }
        | crate::engine::EngineError::FileNotFound { path } => Some(path.display().to_string()),
        crate::engine::EngineError::LockTimeout { .. } => {
            Some("~/.config/dotler/dotler.lock".to_string())
        }
        _ => None,
    };

    let payload = JsonErrorPayload::new(err.error_code(), err.to_string(), location, err.hint());

    if json_mode {
        let s = serde_json::to_string(&payload).expect("JSON serialization cannot fail");
        let _ = writeln!(stdout, "{s}");
    } else {
        let _ = writeln!(stderr, "{} {}", styled_error_label(), payload.message);
        if let Some(ref loc) = payload.location {
            let _ = writeln!(stderr, "Location: {loc}");
        }
        let _ = writeln!(stderr, "{} {}", styled_hint_label(), payload.hint);
    }

    err.exit_code()
}

/// Error output renderer writing to standard stdout and stderr.
pub fn render_error(error: &CliError, json_mode: bool) -> i32 {
    let mut stdout = std::io::stdout();
    let mut stderr = std::io::stderr();
    render_error_to(&mut stdout, &mut stderr, error, json_mode)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    use std::path::PathBuf;

    fn strip_ansi(s: &str) -> String {
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

    #[test]
    fn test_json_envelope_zero_ansi() {
        let mut buf = Vec::new();
        let payload = json!({ "status": "ok", "count": 42 });
        let code = render_success_to(&mut buf, "test_cmd", &payload, true);
        assert_eq!(code, EXIT_SUCCESS);

        let out = String::from_utf8(buf).unwrap();
        assert!(!out.contains("\x1b["), "Must not contain ANSI escape codes");

        let env: JsonEnvelope<Value> = serde_json::from_str(&out).unwrap();
        assert!(env.ok);
        assert_eq!(env.command, Some("test_cmd".to_string()));
        assert_eq!(env.data.unwrap()["count"], 42);
    }

    #[test]
    fn test_json_error_payload_zero_ansi() {
        let mut stdout_buf = Vec::new();
        let mut stderr_buf = Vec::new();

        let err = CliError::Args("Unknown flag --foo".to_string());
        let code = render_error_to(&mut stdout_buf, &mut stderr_buf, &err, true);
        assert_eq!(code, EXIT_CONFIG_OR_ARGS_ERROR);

        let out = String::from_utf8(stdout_buf).unwrap();
        assert!(
            !out.contains("\x1b["),
            "Error JSON must not contain ANSI codes"
        );

        let payload: JsonErrorPayload = serde_json::from_str(&out).unwrap();
        assert!(!payload.ok);
        assert_eq!(payload.error_code, "CLI_ARGS_ERROR");
        assert!(payload.hint.contains("Correct argument usage"));
    }

    #[test]
    fn test_exit_codes_mapping() {
        assert_eq!(EXIT_SUCCESS, 0);
        assert_eq!(EXIT_SYNC_CONFLICT, 1);
        assert_eq!(EXIT_CONFIG_OR_ARGS_ERROR, 2);
        assert_eq!(EXIT_SECURITY_BLOCKED, 3);
        assert_eq!(EXIT_AUTH_OR_LOCK_ERROR, 4);

        let lock_err = CliError::Lock(crate::config::LockError::Timeout { timeout_ms: 5000 });
        assert_eq!(lock_err.exit_code(), 4);

        let sec_err = CliError::Config(crate::config::ConfigError::HardBlockedPath {
            path: "/etc/passwd".to_string(),
            reason: "outside home".to_string(),
        });
        assert_eq!(sec_err.exit_code(), 3);
    }

    #[test]
    fn test_inline_render_formats_and_emoji_rules() {
        let init_rep = crate::engine::check::InitReport {
            label: "main".to_string(),
            device: "default".to_string(),
            repo_path: PathBuf::from("/home/user/dotfiles"),
            hint: "Run 'dotler ai'".to_string(),
        };
        let init_raw = init_rep.render_inline();
        assert!(init_raw.contains("\x1b[38;5;12m"));
        assert!(!init_raw.contains("☀️"));
        assert_eq!(
            strip_ansi(&init_raw),
            "Init done. ('main' at '/home/user/dotfiles', device: default)\nHint: Run 'dotler ai'"
        );

        let check_rep = crate::engine::check::CheckReport {
            status: "valid".to_string(),
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
            ExportReport(sync_rep.clone()).render_inline(),
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
            repo_url: "gh:u/r".to_string(),
            destination: PathBuf::from("/tmp/dots"),
            cloned_groups: vec!["nvim".to_string(), "zsh".to_string()],
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

        let vinit_rep = VaultInitReport {
            vault_id: "vid-123".to_string(),
            mnemonic: Some("word1 word2".to_string()),
            hint: None,
        };
        assert_eq!(
            vinit_rep.render_inline(),
            "Vault init done. (id: vid-123)\n🔑 Recovery mnemonic: word1 word2"
        );

        let vinit_import_rep = VaultInitReport {
            vault_id: "vid-123".to_string(),
            mnemonic: None,
            hint: None,
        };
        assert_eq!(
            vinit_import_rep.render_inline(),
            "Vault init done. (id: vid-123)"
        );

        let vpasswd_rep = VaultPasswdReport {
            status: "password_rotated".to_string(),
            rotated_repos: vec!["a".to_string(), "b".to_string()],
            skipped_repos: vec!["c".to_string()],
            keyring_updated: true,
            already_synced_repos: vec![],
            vault_id: Some("vid-123".to_string()),
        };
        assert_eq!(
            vpasswd_rep.render_inline(),
            "☀️ Passphrase rotation done. (2 rotated, 1 skipped)"
        );

        let vrec_rep = VaultRecoverReport {
            vault_id: "vid-999".to_string(),
            status: "recovered".to_string(),
            new_mnemonic: "new1 new2".to_string(),
            hint: None,
        };
        assert_eq!(
            vrec_rep.render_inline(),
            "☀️ Vault recovery done. (id: vid-999)\n🔑 New recovery mnemonic: new1 new2"
        );

        let key_set_rep = KeyReport {
            status: "keyring_updated".to_string(),
        };
        assert_eq!(key_set_rep.render_inline(), "Key set done.");

        let key_del_rep = KeyReport {
            status: "keyring_deleted".to_string(),
        };
        assert_eq!(key_del_rep.render_inline(), "Key delete done.");

        let update_rep = UpdateReport {
            status: "up_to_date".to_string(),
            check_only: true,
            version: "0.1.0".to_string(),
        };
        assert_eq!(
            update_rep.render_inline(),
            "Update check done. (v0.1.0, up to date)"
        );
    }

    #[test]
    fn test_non_json_error_colors_error_and_hint_labels() {
        let mut stdout_buf = Vec::new();
        let mut stderr_buf = Vec::new();
        let err = CliError::Args("Bad flag".to_string());
        let code = render_error_to(&mut stdout_buf, &mut stderr_buf, &err, false);
        assert_eq!(code, EXIT_CONFIG_OR_ARGS_ERROR);
        assert!(stdout_buf.is_empty());

        let raw_stderr = String::from_utf8(stderr_buf).unwrap();
        assert!(raw_stderr.contains("\x1b[38;5;9m"));
        assert!(raw_stderr.contains("\x1b[38;5;12m"));
        assert!(raw_stderr.contains("Error:"));
        assert!(raw_stderr.contains("Hint:"));
        let plain = strip_ansi(&raw_stderr);
        assert!(plain.starts_with("Error: CLI argument error: Bad flag\nHint: "));
    }
}
