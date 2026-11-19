//! Conditional vault master key loader and multi-repository passphrase rotation.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::local::{LocalConfig, WalkDir};
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
pub struct VaultRotateReport {
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

    let vault_keyring_secret = if use_keyring && !vault_cfg.vault_id.trim().is_empty() {
        OsKeyring::get_for_vault(&vault_cfg.vault_id).ok().flatten()
    } else {
        None
    };
    if let Some(ref sec) = vault_keyring_secret
        && let Ok(key) = slot.unwrap(sec, Some(&vault_cfg.vault_id))
    {
        return Ok(Some(key));
    }

    let default_keyring_secret = if use_keyring {
        OsKeyring::get().ok().flatten()
    } else {
        None
    };
    if let Some(ref sec) = default_keyring_secret
        && let Ok(key) = slot.unwrap(sec, Some(&vault_cfg.vault_id))
    {
        return Ok(Some(key));
    }

    if !required {
        return Ok(None);
    }

    if !is_interactive {
        return Err(EngineError::VaultLocked {
            reason: "Passphrase required in non-interactive mode. Run 'dotler vault init' or export DOTLER_PASSPHRASE.".to_string(),
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

    if use_keyring && vault_keyring_secret.is_none() {
        let _ = OsKeyring::set_with_fallback(Some(&vault_cfg.vault_id), &resolved.secret);
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
) -> Result<VaultRotateReport, EngineError> {
    let candidates: Vec<(String, PathBuf)> = if let Some(label) = requested_label {
        let (resolved_label, path) = local_cfg
            .resolve_repo(Some(label))
            .map_err(EngineError::Config)?;
        vec![(resolved_label, path)]
    } else {
        local_cfg.candidate_repos_with_cwd()
    };

    let explicit_repo = requested_label.is_some();
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
    let mut synced_vault_ids: Vec<String> = Vec::new();

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
                    if !vault_cfg.vault_id.trim().is_empty()
                        && !synced_vault_ids.contains(&vault_cfg.vault_id)
                    {
                        synced_vault_ids.push(vault_cfg.vault_id.clone());
                    }
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
    let mut target_vault_ids: Vec<String> = synced_vault_ids;

    for (label, manifest_path, updated_manifest, vault_id) in pending_writes {
        write_file_safe(&manifest_path, updated_manifest.as_bytes())?;
        if primary_vault_id.is_none() {
            primary_vault_id = Some(vault_id.clone());
        }
        if !vault_id.trim().is_empty() && !target_vault_ids.contains(&vault_id) {
            target_vault_ids.push(vault_id);
        }
        rotated_repos.push(label);
    }
    if primary_vault_id.is_none() {
        primary_vault_id = target_vault_ids.first().cloned();
    }

    let mut keyring_updated = false;
    if local_cfg.use_keyring {
        use crate::crypto::ExposeSecret;
        for vid in &target_vault_ids {
            if OsKeyring::set_for_vault(vid, &new_pass).is_ok() {
                keyring_updated = true;
            }
        }
        let existing_default = OsKeyring::get().ok().flatten();
        let should_update_default = match existing_default {
            None => true,
            Some(ref sec) => {
                sec.expose_secret() == old_pass.expose_secret()
                    || sec.expose_secret() == new_pass.expose_secret()
            }
        };
        if should_update_default && OsKeyring::set(&new_pass).is_ok() {
            keyring_updated = true;
        }
    }
    skipped_repos.sort();

    Ok(VaultRotateReport {
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

    if use_keyring {
        for (_, _, vcfg) in vault_targets {
            if !vcfg.vault_id.trim().is_empty()
                && let Ok(Some(sec)) = OsKeyring::get_for_vault(&vcfg.vault_id)
                && matches_any(&sec)
            {
                return Ok(sec);
            }
        }
        if let Ok(Some(sec)) = OsKeyring::get()
            && matches_any(&sec)
        {
            return Ok(sec);
        }
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

    #[test]
    fn multi_vault_isolation_and_default_fallback_unlock() {
        let _guard = crate::crypto::keyring::MOCK_KEYRING_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        OsKeyring::enable_mock();
        OsKeyring::clear_mock();
        unsafe {
            std::env::remove_var(PASSPHRASE_ENV_VAR);
        }

        let pass_pub = SecretString::new("public-dots-pass-111".to_string());
        let pass_priv = SecretString::new("private-vault-pass-222".to_string());
        let (vcfg_pub, key_pub, _) = init_vault(&pass_pub).unwrap();
        let (vcfg_priv, key_priv, _) = init_vault(&pass_priv).unwrap();
        let repo_pub = RepoConfig {
            vault: Some(vcfg_pub.clone()),
            ..Default::default()
        };
        let repo_priv = RepoConfig {
            vault: Some(vcfg_priv.clone()),
            ..Default::default()
        };

        // Store both passphrases using set_with_fallback:
        // public fills <vid_pub> + default; private fills <vid_priv> without touching default.
        OsKeyring::set_with_fallback(Some(&vcfg_pub.vault_id), &pass_pub).unwrap();
        OsKeyring::set_with_fallback(Some(&vcfg_priv.vault_id), &pass_priv).unwrap();

        // Both unlock non-interactively in Tier 1 without env vars or prompt
        let unlocked_pub = unlock_vault_if_needed(&repo_pub, true, false, true)
            .unwrap()
            .unwrap();
        assert_eq!(unlocked_pub.vault_id(), key_pub.vault_id());

        let unlocked_priv = unlock_vault_if_needed(&repo_priv, true, false, true)
            .unwrap()
            .unwrap();
        assert_eq!(unlocked_priv.vault_id(), key_priv.vault_id());

        // Fallback test: delete <vid_pub> slot; public still unlocks via default slot
        OsKeyring::delete_for_vault(&vcfg_pub.vault_id).unwrap();
        let unlocked_pub_fallback = unlock_vault_if_needed(&repo_pub, true, false, true)
            .unwrap()
            .unwrap();
        assert_eq!(unlocked_pub_fallback.vault_id(), key_pub.vault_id());

        // Interactive unlock on a missing <vid_pub> slot auto-populates <vid_pub>
        let (vcfg_fresh, key_fresh, _) =
            init_vault(&SecretString::new("fresh-pass-333".into())).unwrap();
        let repo_fresh = RepoConfig {
            vault: Some(vcfg_fresh.clone()),
            ..Default::default()
        };
        OsKeyring::push_mock_prompt_reply("fresh-pass-333");
        let unlocked_fresh = unlock_vault_if_needed(&repo_fresh, true, true, true)
            .unwrap()
            .unwrap();
        assert_eq!(unlocked_fresh.vault_id(), key_fresh.vault_id());
        assert_eq!(
            crate::crypto::ExposeSecret::expose_secret(
                &OsKeyring::get_for_vault(&vcfg_fresh.vault_id)
                    .unwrap()
                    .unwrap()
            ),
            "fresh-pass-333"
        );

        OsKeyring::clear_mock();
        OsKeyring::disable_mock();
    }

    #[test]
    fn test_interactive_prompt_unlocks_vault_and_autosaves_to_keyring() {
        let _guard = crate::crypto::keyring::MockKeyringGuard::new();
        unsafe {
            std::env::remove_var(PASSPHRASE_ENV_VAR);
        }
        let pass = SecretString::new("interactive-day0-secret".to_string());
        let (vault_cfg, expected_key, _mnemonic) = init_vault(&pass).unwrap();
        let repo_cfg = RepoConfig {
            vault: Some(vault_cfg.clone()),
            ..Default::default()
        };

        assert!(OsKeyring::get().unwrap().is_none());
        OsKeyring::push_mock_prompt_reply("interactive-day0-secret");

        let unlocked = unlock_vault_if_needed(&repo_cfg, true, true, true)
            .expect("interactive unlock must succeed")
            .expect("vault key must be returned");
        assert_eq!(unlocked.vault_id(), expected_key.vault_id());
        assert_eq!(
            crate::crypto::ExposeSecret::expose_secret(&OsKeyring::get().unwrap().unwrap()),
            "interactive-day0-secret"
        );

        OsKeyring::push_mock_prompt_reply("rotated-new-secret-999");
        let targets = vec![(
            "primary".to_string(),
            PathBuf::from("/tmp/dummy"),
            vault_cfg.clone(),
        )];
        let resolved_old = resolve_old_passphrase_for_vaults(&targets, true, true).unwrap();
        assert_eq!(
            crate::crypto::ExposeSecret::expose_secret(&resolved_old),
            "interactive-day0-secret"
        );

        let resolved_new =
            read_new_passphrase(false, false, true, "Enter new vault passphrase: ").unwrap();
        assert_eq!(
            crate::crypto::ExposeSecret::expose_secret(&resolved_new),
            "rotated-new-secret-999"
        );

        let rotated_cfg = change_password(&vault_cfg, &resolved_old, &resolved_new).unwrap();
        let rotated_slot = VaultSlot::from_base64(&rotated_cfg.password_slot).unwrap();
        assert!(
            rotated_slot
                .unwrap(&resolved_new, Some(&rotated_cfg.vault_id))
                .is_ok()
        );
    }

    #[test]
    fn test_rotate_vault_passphrases_updates_all_matching_repos_and_keyring() {
        let _guard = crate::crypto::keyring::MockKeyringGuard::new();
        unsafe {
            std::env::remove_var(PASSPHRASE_ENV_VAR);
        }
        let tmp = tempfile::tempdir().unwrap();
        let (repo_a, repo_b, repo_other, repo_plain, repo_missing) = (
            tmp.path().join("repo_a"),
            tmp.path().join("repo_b"),
            tmp.path().join("repo_other"),
            tmp.path().join("repo_plain"),
            tmp.path().join("repo_missing"),
        );
        for dir in [&repo_a, &repo_b, &repo_other, &repo_plain] {
            fs::create_dir_all(dir.join("shell")).unwrap();
        }

        let old_pass = SecretString::new("shared-old-pass-111".to_string());
        let other_pass = SecretString::new("third-party-pass-222".to_string());
        let (vcfg_a, vkey_a, _) = init_vault(&old_pass).unwrap();
        let (vcfg_b, vkey_b, _) = init_vault(&old_pass).unwrap();
        let (vcfg_other, _, _) = init_vault(&other_pass).unwrap();

        let enc_a = vkey_a.encrypt_file(b"secret-a-payload").unwrap().to_bytes();
        let enc_b = vkey_b.encrypt_file(b"secret-b-payload").unwrap().to_bytes();
        write_file_safe(&repo_a.join("shell/token.enc"), &enc_a).unwrap();
        write_file_safe(&repo_b.join("shell/token.enc"), &enc_b).unwrap();

        let write_vault_manifest = |dir: &Path, vcfg: &VaultConfig| {
            let content = format!(
                "vault_id = \"{}\"\npassword_slot = \"{}\"\nrecovery_slot = \"{}\"\n\n[shell]\nos-nux = \"~\"\nos-mac = \"~\"\nos-win = \"~\"\nfiles = \"* enc\"\n",
                vcfg.vault_id, vcfg.password_slot, vcfg.recovery_slot
            );
            write_file_safe(&dir.join("dotler.toml"), content.as_bytes()).unwrap();
        };
        write_vault_manifest(&repo_a, &vcfg_a);
        write_vault_manifest(&repo_b, &vcfg_b);
        write_vault_manifest(&repo_other, &vcfg_other);
        write_file_safe(
            &repo_plain.join("dotler.toml"),
            b"[shell]\nos-nux = \"~\"\nos-mac = \"~\"\nos-win = \"~\"\nfiles = \"*\"\n",
        )
        .unwrap();

        let mut local_cfg = LocalConfig::default();
        for (name, dir) in [
            ("repo_a", &repo_a),
            ("repo_b", &repo_b),
            ("repo_other", &repo_other),
            ("repo_plain", &repo_plain),
            ("repo_missing", &repo_missing),
        ] {
            local_cfg
                .repos
                .insert(name.to_string(), dir.to_string_lossy().to_string());
        }

        OsKeyring::push_mock_prompt_reply("wrong-old-pass-000");
        OsKeyring::push_mock_prompt_reply("shared-new-pass-999");
        assert!(rotate_vault_passphrases(&local_cfg, None, false, None, true).is_err());
        assert!(OsKeyring::get().unwrap().is_none());

        OsKeyring::set(&old_pass).unwrap();
        OsKeyring::push_mock_prompt_reply("shared-new-pass-999");
        let report =
            rotate_vault_passphrases(&local_cfg, None, false, Some("updated-hint"), true).unwrap();
        assert_eq!(report.status, "password_rotated");
        assert_eq!(
            report.rotated_repos,
            vec!["repo_a".to_string(), "repo_b".to_string()]
        );
        assert_eq!(
            report.skipped_repos,
            vec!["repo_missing", "repo_other", "repo_plain"]
        );
        assert!(report.keyring_updated);

        let keyring_secret = OsKeyring::get().unwrap().unwrap();
        assert_eq!(
            crate::crypto::ExposeSecret::expose_secret(&keyring_secret),
            "shared-new-pass-999"
        );
        for (repo_dir, orig_enc, expected) in [
            (&repo_a, &enc_a, b"secret-a-payload".as_slice()),
            (&repo_b, &enc_b, b"secret-b-payload".as_slice()),
        ] {
            let disk_enc = fs::read(repo_dir.join("shell/token.enc")).unwrap();
            assert_eq!(&disk_enc, orig_enc);
            let vcfg = RepoConfig::load(&repo_dir.join("dotler.toml"))
                .unwrap()
                .vault
                .unwrap();
            assert_eq!(vcfg.vault_hint.as_deref(), Some("updated-hint"));
            let slot = VaultSlot::from_base64(&vcfg.password_slot).unwrap();
            assert!(slot.unwrap(&old_pass, Some(&vcfg.vault_id)).is_err());
            let unlocked = slot.unwrap(&keyring_secret, Some(&vcfg.vault_id)).unwrap();
            let dec = unlocked
                .decrypt_file(&crate::crypto::vault::EncryptedFile::from_bytes(&disk_enc).unwrap())
                .unwrap();
            assert_eq!(
                crate::crypto::ExposeSecret::expose_secret(&dec).as_slice(),
                expected
            );
        }
        assert_eq!(
            RepoConfig::load(&repo_other.join("dotler.toml"))
                .unwrap()
                .vault
                .unwrap()
                .password_slot,
            vcfg_other.password_slot
        );
    }

    #[test]
    fn test_unlock_vault_if_needed_respects_use_keyring_false() {
        let _guard = crate::crypto::keyring::MockKeyringGuard::new();
        unsafe {
            std::env::remove_var(PASSPHRASE_ENV_VAR);
        }
        let pass = SecretString::new("keyring-disabled-secret-123".to_string());
        let (mut vault_cfg, expected_key, _) = init_vault(&pass).unwrap();
        vault_cfg.vault_hint = Some("my hint".to_string());
        let repo_cfg = RepoConfig {
            vault: Some(vault_cfg),
            ..Default::default()
        };

        OsKeyring::set(&pass).unwrap();
        assert!(unlock_vault_if_needed(&repo_cfg, false, false, true).is_err());

        OsKeyring::clear_mock();
        OsKeyring::push_mock_prompt_reply("keyring-disabled-secret-123");
        let unlocked = unlock_vault_if_needed(&repo_cfg, false, true, true)
            .unwrap()
            .unwrap();
        assert_eq!(unlocked.vault_id(), expected_key.vault_id());
        assert!(OsKeyring::get().unwrap().is_none());
    }

    #[test]
    fn test_rotate_vault_passphrases_preserves_other_vault_slots_and_nonmatching_default() {
        let _guard = crate::crypto::keyring::MockKeyringGuard::new();
        unsafe {
            std::env::remove_var(PASSPHRASE_ENV_VAR);
        }
        let tmp = tempfile::tempdir().unwrap();
        let repo_a = tmp.path().join("repo_a");
        let repo_b = tmp.path().join("repo_b");
        fs::create_dir_all(&repo_a).unwrap();
        fs::create_dir_all(&repo_b).unwrap();

        let pass_a = SecretString::new("vault-a-old-pass".to_string());
        let pass_b = SecretString::new("vault-b-stay-pass".to_string());
        let (vcfg_a, _, _) = init_vault(&pass_a).unwrap();
        let (vcfg_b, _, _) = init_vault(&pass_b).unwrap();

        let write_manifest = |dir: &Path, vcfg: &VaultConfig| {
            let content = format!(
                "vault_id = \"{}\"\npassword_slot = \"{}\"\nrecovery_slot = \"{}\"\n",
                vcfg.vault_id, vcfg.password_slot, vcfg.recovery_slot
            );
            write_file_safe(&dir.join("dotler.toml"), content.as_bytes()).unwrap();
        };
        write_manifest(&repo_a, &vcfg_a);
        write_manifest(&repo_b, &vcfg_b);

        let mut local_cfg = LocalConfig::default();
        local_cfg
            .repos
            .insert("a".to_string(), repo_a.to_string_lossy().to_string());
        local_cfg
            .repos
            .insert("b".to_string(), repo_b.to_string_lossy().to_string());

        // Set default slot to vault_b's passphrase, while vault_a has its own <vid_a> slot
        OsKeyring::set(&pass_b).unwrap();
        OsKeyring::set_for_vault(&vcfg_a.vault_id, &pass_a).unwrap();
        OsKeyring::set_for_vault(&vcfg_b.vault_id, &pass_b).unwrap();

        OsKeyring::push_mock_prompt_reply("vault-a-rotated-new");
        let report = rotate_vault_passphrases(&local_cfg, Some("a"), false, None, true).unwrap();
        assert_eq!(report.rotated_repos, vec!["a".to_string()]);
        assert!(report.keyring_updated);

        // <vid_a> updated to new pass, <vid_b> and non-matching default preserved
        assert_eq!(
            crate::crypto::ExposeSecret::expose_secret(
                &OsKeyring::get_for_vault(&vcfg_a.vault_id).unwrap().unwrap()
            ),
            "vault-a-rotated-new"
        );
        assert_eq!(
            crate::crypto::ExposeSecret::expose_secret(
                &OsKeyring::get_for_vault(&vcfg_b.vault_id).unwrap().unwrap()
            ),
            "vault-b-stay-pass"
        );
        assert_eq!(
            crate::crypto::ExposeSecret::expose_secret(&OsKeyring::get().unwrap().unwrap()),
            "vault-b-stay-pass"
        );
    }
}
