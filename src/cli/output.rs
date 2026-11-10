//! Formatting, structured JSON envelopes, and deterministic process exit codes.

use serde::{Deserialize, Serialize};
use std::io::Write;

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
            "Initialized repository '{}' at '{}' (device: {})\nHint: {}",
            self.label,
            self.repo_path.display(),
            self.device,
            self.hint
        )
    }
}

impl InlineRender for crate::engine::check::CheckReport {
    fn render_inline(&self) -> String {
        format!("Configuration valid ({} groups checked)", self.groups_checked)
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
            "Synchronized: {} processed, {} skipped, {} conflicts",
            self.processed,
            self.skipped,
            self.conflicts.len()
        )
    }
}

impl InlineRender for crate::engine::sync::TidyReport {
    fn render_inline(&self) -> String {
        format!(
            "Tidy completed: {} encrypted in repo, {} decrypted in repo, {} removed from repo, {} os orphans removed, {} orphans kept",
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
            "Successfully cloned repository into '{}' ({} groups)",
            self.destination.display(),
            self.cloned_groups.len()
        )
    }
}

impl InlineRender for crate::engine::remote::InstallReport {
    fn render_inline(&self) -> String {
        format!(
            "Installed {} dotfiles; backed up {} files",
            self.installed_files.len(),
            self.backed_up_files.len()
        )
    }
}

impl InlineRender for crate::engine::remote::UninstallReport {
    fn render_inline(&self) -> String {
        format!(
            "Uninstalled {} dotfiles; restored {} backups",
            self.removed_files.len(),
            self.restored_backups.len()
        )
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
        let _ = writeln!(stderr, "Error: {}", payload.message);
        if let Some(ref loc) = payload.location {
            let _ = writeln!(stderr, "Location: {loc}");
        }
        let _ = writeln!(stderr, "Hint: {}", payload.hint);
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
        let _ = writeln!(stderr, "Error: {}", payload.message);
        if let Some(ref loc) = payload.location {
            let _ = writeln!(stderr, "Location: {loc}");
        }
        let _ = writeln!(stderr, "Hint: {}", payload.hint);
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
}
