//! Conditional vault master key loader and multi-repository passphrase rotation.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::local::{LocalConfig, WalkDir, expand_tilde, find_ancestor_repo_dir};
use crate::config::repo::{
    RepoConfig, VaultConfig, parse_selection_rules, rules_have_effective_encryption,
    update_vault_manifest_section,
};
use crate::config::state::write_file_safe;
use crate::crypto::SecretString;
use crate::crypto::keyring::{OsKeyring, PASSPHRASE_ENV_VAR};
use crate::crypto::vault::{VaultKey, VaultSlot, change_password};
use crate::engine::EngineError;

/// Policy governing whether a command requires unlocking the repository vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultUnlockPolicy {
    Optional,
    RequiredIfEncrypted,
    RequiredAlways,
}

/// Summary report returned by [`rotate_vault_passphrases`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultPasswdReport {
    pub status: String,
    pub rotated_repos: Vec<String>,
    pub skipped_repos: Vec<String>,
    pub keyring_updated: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub already_synced_repos: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault_id: Option<String>,
}

/// Returns `true` if any group in `repo_cfg` has an effective `enc` selection rule.
pub fn has_encrypted_rules(repo_cfg: &RepoConfig) -> bool {
    for g in repo_cfg.groups.values() {
        if let Ok(rules) = parse_selection_rules(&g.files)
            && rules_have_effective_encryption(&rules)
        {
            return true;
        }
    }
    false
}

/// Returns `true` if any group directory in `repo_path` contains a `.enc` file.
pub fn has_encrypted_repo_files(repo_path: &Path, repo_cfg: &RepoConfig) -> bool {
    for g_name in repo_cfg.groups.keys() {
        let group_dir = repo_path.join(g_name);
        if !group_dir.is_dir() {
            continue;
        }
        for entry in WalkDir::new(&group_dir).into_iter().filter_map(|e| e.ok()) {
            if entry.file_type().is_file()
                && entry.path().extension().and_then(|s| s.to_str()) == Some("enc")
            {
                return true;
            }
        }
    }
    false
}

/// Conditionally unlocks the repository [`VaultKey`] using environment variables, OS keyring,
/// or interactive terminal prompt.
pub fn unlock_vault_if_needed(
    repo_cfg: &RepoConfig,
    use_keyring: bool,
    is_interactive: bool,
    required: bool,
) -> Result<Option<VaultKey>, EngineError> {
    let Some(vault_cfg) = repo_cfg.vault.as_ref() else {
        if required {
            return Err(EngineError::Config(
                crate::config::ConfigError::MissingVaultConfig,
            ));
        }
        return Ok(None);
    };

    let slot = VaultSlot::from_base64(&vault_cfg.password_slot)?;

    if let Ok(env_pass) = std::env::var(PASSPHRASE_ENV_VAR) {
        let trimmed = env_pass.trim_end_matches(['\r', '\n']);
        if !trimmed.is_empty() {
            let secret = SecretString::new(trimmed.to_string());
            match slot.unwrap(&secret, Some(&vault_cfg.vault_id)) {
                Ok(key) => return Ok(Some(key)),
                Err(e) if !is_interactive && required => return Err(EngineError::Vault(e)),
                Err(_) => {}
            }
        }
    }

    let keyring_secret = if use_keyring {
        OsKeyring::get().ok().flatten()
    } else {
        None
    };
    if let Some(ref sec) = keyring_secret
        && let Ok(key) = slot.unwrap(sec, Some(&vault_cfg.vault_id))
    {
        return Ok(Some(key));
    }

    if !required {
        return Ok(None);
    }

    if !is_interactive {
        return Err(EngineError::VaultLocked {
            reason: "Passphrase required in non-interactive mode. Run 'dotler key set' or export DOTLER_PASSPHRASE.".to_string(),
        });
    }

    let prompt_msg = match vault_cfg
        .vault_hint
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(h) => format!("Enter dotler vault passphrase (hint: {h}): "),
        None => "Enter dotler vault passphrase: ".to_string(),
    };
    let resolved = OsKeyring::prompt_passphrase_with_message(&prompt_msg)
        .map_err(|e| EngineError::Crypto(crate::crypto::CryptoError::Keyring(e)))?;
    let key = slot.unwrap(&resolved.secret, Some(&vault_cfg.vault_id))?;

    if use_keyring && keyring_secret.is_none() {
        let _ = OsKeyring::set(&resolved.secret);
    }

    Ok(Some(key))
}

/// Rotates vault passphrases across the specified repository or all matching registered repositories.
pub fn rotate_vault_passphrases(
    local_cfg: &LocalConfig,
    requested_label: Option<&str>,
    password_stdin: bool,
    new_hint: Option<&str>,
    is_interactive: bool,
) -> Result<VaultPasswdReport, EngineError> {
    let mut candidates: Vec<(String, PathBuf)> = Vec::new();
    let explicit_repo = requested_label.is_some();

    if let Some(label) = requested_label {
        let (resolved_label, path) = local_cfg
            .resolve_repo(Some(label))
            .map_err(EngineError::Config)?;
        candidates.push((resolved_label, path));
    } else {
        for (label, raw_path) in &local_cfg.repos {
            candidates.push((label.clone(), expand_tilde(raw_path)));
        }

        if let Ok(current_dir) = std::env::current_dir()
            && let Some(repo_dir) = find_ancestor_repo_dir(&current_dir)
        {
            let canon_cwd = fs::canonicalize(&repo_dir).unwrap_or_else(|_| repo_dir.clone());
            let already_listed = candidates
                .iter()
                .any(|(_, p)| fs::canonicalize(p).unwrap_or_else(|_| p.clone()) == canon_cwd);
            if !already_listed {
                let cwd_label = repo_dir
                    .file_name()
                    .map(|f| f.to_string_lossy().to_string())
                    .unwrap_or_else(|| "current".to_string());
                candidates.push((cwd_label, repo_dir));
            }
        }
    }

    if candidates.is_empty() {
        return Err(EngineError::Config(
            crate::config::ConfigError::NoReposConfigured,
        ));
    }

    let mut vault_targets: Vec<(String, PathBuf, VaultConfig)> = Vec::new();
    let mut skipped_repos: Vec<String> = Vec::new();

    for (label, repo_path) in candidates {
        let manifest_path = repo_path.join("dotler.toml");
        if !manifest_path.is_file() {
            if explicit_repo {
                return Err(EngineError::Config(
                    crate::config::ConfigError::RepoPathNotFound(repo_path.display().to_string()),
                ));
            }
            skipped_repos.push(label);
            continue;
        }

        let repo_cfg = match RepoConfig::load(&manifest_path) {
            Ok(cfg) => cfg,
            Err(e) if explicit_repo => return Err(EngineError::Config(e)),
            Err(_) => {
                skipped_repos.push(label);
                continue;
            }
        };

        match repo_cfg.vault {
            Some(vault_cfg) => vault_targets.push((label, manifest_path, vault_cfg)),
            None if explicit_repo => {
                return Err(EngineError::VaultLocked {
                    reason: "Vault is not configured".to_string(),
                });
            }
            None => skipped_repos.push(label),
        }
    }

    if vault_targets.is_empty() {
        return Err(EngineError::VaultLocked {
            reason: "Vault is not configured in any registered repository".to_string(),
        });
    }

    let old_pass =
        resolve_old_passphrase_for_vaults(&vault_targets, local_cfg.use_keyring, is_interactive)?;
    let new_pass = read_new_passphrase(
        password_stdin,
        false,
        is_interactive,
        "Enter new vault passphrase: ",
    )?;

    let mut pending_writes: Vec<(String, PathBuf, String, String)> = Vec::new();
    let mut already_synced_repos: Vec<String> = Vec::new();

    for (label, manifest_path, vault_cfg) in vault_targets {
        match change_password(&vault_cfg, &old_pass, &new_pass) {
            Ok(mut new_cfg) => {
                if let Some(h) = new_hint {
                    let trimmed = h.trim();
                    new_cfg.vault_hint = if trimmed.is_empty() {
                        None
                    } else {
                        Some(trimmed.to_string())
                    };
                }
                let manifest_str = fs::read_to_string(&manifest_path)?;
                let updated_manifest =
                    update_vault_manifest_section(&manifest_str, &vault_cfg, &new_cfg);
                pending_writes.push((label, manifest_path, updated_manifest, new_cfg.vault_id));
            }
            Err(crate::crypto::vault::VaultError::WeakPassphrase(msg)) => {
                return Err(EngineError::Vault(
                    crate::crypto::vault::VaultError::WeakPassphrase(msg),
                ));
            }
            Err(crate::crypto::vault::VaultError::InvalidSecret) => {
                if let Ok(slot) = VaultSlot::from_base64(&vault_cfg.password_slot)
                    && slot.unwrap(&new_pass, Some(&vault_cfg.vault_id)).is_ok()
                {
                    already_synced_repos.push(label);
                    continue;
                }
                if explicit_repo {
                    return Err(EngineError::Vault(
                        crate::crypto::vault::VaultError::InvalidSecret,
                    ));
                }
                skipped_repos.push(label);
            }
            Err(other) => {
                if explicit_repo {
                    return Err(EngineError::Vault(other));
                }
                skipped_repos.push(label);
            }
        }
    }

    if pending_writes.is_empty() && already_synced_repos.is_empty() {
        return Err(EngineError::Vault(
            crate::crypto::vault::VaultError::InvalidSecret,
        ));
    }

    let mut rotated_repos = Vec::new();
    let mut primary_vault_id: Option<String> = None;

    for (label, manifest_path, updated_manifest, vault_id) in pending_writes {
        write_file_safe(&manifest_path, updated_manifest.as_bytes())?;
        if primary_vault_id.is_none() {
            primary_vault_id = Some(vault_id);
        }
        rotated_repos.push(label);
    }

    let keyring_updated = local_cfg.use_keyring && OsKeyring::set(&new_pass).is_ok();
    skipped_repos.sort();

    Ok(VaultPasswdReport {
        status: "password_rotated".to_string(),
        rotated_repos,
        skipped_repos,
        keyring_updated,
        already_synced_repos,
        vault_id: primary_vault_id,
    })
}

/// Resolves the current passphrase matching at least one target vault.
pub fn resolve_old_passphrase_for_vaults(
    vault_targets: &[(String, PathBuf, VaultConfig)],
    use_keyring: bool,
    is_interactive: bool,
) -> Result<SecretString, EngineError> {
    let matches_any = |candidate: &SecretString| -> bool {
        vault_targets.iter().any(|(_, _, vcfg)| {
            VaultSlot::from_base64(&vcfg.password_slot)
                .ok()
                .and_then(|slot| slot.unwrap(candidate, Some(&vcfg.vault_id)).ok())
                .is_some()
        })
    };

    if let Ok(env_pass) = std::env::var(PASSPHRASE_ENV_VAR) {
        let trimmed = env_pass.trim_end_matches(['\r', '\n']);
        if !trimmed.is_empty() {
            let secret = SecretString::new(trimmed.to_string());
            if matches_any(&secret) || !is_interactive {
                return Ok(secret);
            }
        }
    }

    if use_keyring
        && let Ok(Some(sec)) = OsKeyring::get()
        && matches_any(&sec)
    {
        return Ok(sec);
    }

    if !is_interactive {
        return Err(EngineError::Crypto(crate::crypto::CryptoError::Keyring(
            crate::crypto::keyring::KeyringError::PassphraseRequiredInNonInteractiveMode,
        )));
    }

    let first_hint = vault_targets
        .iter()
        .filter_map(|(_, _, vcfg)| vcfg.vault_hint.as_deref())
        .map(str::trim)
        .find(|s| !s.is_empty());
    let prompt_msg = match first_hint {
        Some(h) => format!("Enter current vault passphrase (hint: {h}): "),
        None => "Enter current vault passphrase: ".to_string(),
    };

    let resolved = OsKeyring::prompt_passphrase_with_message(&prompt_msg)
        .map_err(|e| EngineError::Crypto(crate::crypto::CryptoError::Keyring(e)))?;
    Ok(resolved.secret)
}

/// Reads a new passphrase from stdin, environment variable, or interactive prompt.
pub fn read_new_passphrase(
    password_stdin: bool,
    allow_env_var: bool,
    is_interactive: bool,
    prompt_msg: &str,
) -> Result<SecretString, EngineError> {
    if password_stdin {
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            return Err(EngineError::Crypto(crate::crypto::CryptoError::Vault(
                crate::crypto::vault::VaultError::WeakPassphrase(
                    "Passphrase cannot be empty".to_string(),
                ),
            )));
        }
        return Ok(SecretString::new(trimmed.to_string()));
    }

    if allow_env_var && let Ok(env_pass) = std::env::var(PASSPHRASE_ENV_VAR) {
        let trimmed = env_pass.trim_end_matches(['\r', '\n']);
        if !trimmed.is_empty() {
            return Ok(SecretString::new(trimmed.to_string()));
        }
    }

    if !is_interactive {
        return Err(EngineError::Crypto(crate::crypto::CryptoError::Keyring(
            crate::crypto::keyring::KeyringError::PassphraseRequiredInNonInteractiveMode,
        )));
    }

    let resolved = OsKeyring::prompt_passphrase_with_message(prompt_msg)
        .map_err(|e| EngineError::Crypto(crate::crypto::CryptoError::Keyring(e)))?;
    Ok(resolved.secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::vault::init_vault;

    #[test]
    fn plain_only_repo_skips_vault_unlock() {
        let repo_cfg = RepoConfig::default();
        assert!(!has_encrypted_rules(&repo_cfg));
        let res = unlock_vault_if_needed(&repo_cfg, false, false, false).unwrap();
        assert!(res.is_none());
    }

    #[test]
    fn non_interactive_encrypted_repo_returns_vault_locked() {
        let _guard = crate::crypto::keyring::MOCK_KEYRING_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        OsKeyring::enable_mock();
        OsKeyring::clear_mock();
        unsafe {
            std::env::remove_var(PASSPHRASE_ENV_VAR);
        }

        let pass = SecretString::new("test-secret-123".to_string());
        let (vault_cfg, _, _) = init_vault(&pass).unwrap();
        let repo_cfg = RepoConfig {
            vault: Some(vault_cfg),
            ..Default::default()
        };

        let err = unlock_vault_if_needed(&repo_cfg, true, false, true).unwrap_err();
        assert!(matches!(err, EngineError::VaultLocked { .. }));
        assert_eq!(err.exit_code(), 4);

        OsKeyring::clear_mock();
        OsKeyring::disable_mock();
    }
}
