//! Conditional vault master key loader and multi-repository vault rotation.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::local::{LocalConfig, WalkDir, resolve_repo_path_with_cwd};
use crate::config::repo::{
    RepoConfig, VaultConfig, parse_selection_rules, rules_have_effective_encryption,
    update_vault_manifest_section,
};
use crate::config::state::write_file_safe;
use crate::crypto::keyring::{OsKeyring, PASSPHRASE_ENV_VAR};
use crate::crypto::vault::{
    CONTENT_ENC_SUFFIX, EncryptedFile, FullEncryptedFile, LEGACY_CONTENT_ENC_SUFFIX, VaultKey,
    VaultSlot, change_password, init_vault, is_content_enc_name, is_full_enc_name,
    is_legacy_dotler_archive_bytes, parse_legacy_fenc_filename_stem, rotate_recovery_slot,
};
use crate::crypto::{ExposeSecret, SecretString};
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

/// Summary report returned by [`rotate_vault_recovery`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultRotateRecoveryReport {
    pub status: String,
    pub vault_id: String,
    pub rotated_repos: Vec<String>,
    pub skipped_repos: Vec<String>,
    pub new_mnemonic: String,
}

/// Summary report returned by [`rotate_vault_key`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultRotateKeyReport {
    pub status: String,
    pub old_vault_id: String,
    pub vault_id: String,
    pub rotated_repos: Vec<String>,
    pub skipped_repos: Vec<String>,
    pub rekeyed_files: usize,
    pub keyring_updated: bool,
    pub new_mnemonic: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

/// Pending atomic file write produced by in-memory vault re-keying.
#[derive(Debug, Clone)]
pub struct PendingRekeyWrite {
    pub dest_path: PathBuf,
    pub bytes: Vec<u8>,
    pub stale_path: Option<PathBuf>,
}

/// Prepares in-memory re-keying writes for all encrypted artifacts in `repo_path`
/// whose embedded `vault_id` differs from `new_vault_key`.
pub fn plan_repo_rekey_writes(
    repo_path: &Path,
    repo_cfg: &RepoConfig,
    old_vault_key: &VaultKey,
    new_vault_key: &VaultKey,
) -> Result<Vec<PendingRekeyWrite>, EngineError> {
    let old_vid_hex = old_vault_key.vault_id();
    let new_vid_bytes = new_vault_key.vault_id_bytes();
    let mut writes = Vec::new();

    for g_name in repo_cfg.groups.keys() {
        let group_dir = crate::config::repo::group_repo_dir(repo_path, g_name);
        let delegated = repo_cfg.descendant_subpaths(g_name);
        if !group_dir.is_dir() {
            continue;
        }
        for entry in WalkDir::new(&group_dir)
            .filter_entry(|e| {
                if e.depth() == 0 {
                    return true;
                }
                !e.path().strip_prefix(&group_dir).is_ok_and(|rel| {
                    crate::config::repo::is_delegated_to_subgroup(
                        &rel.to_string_lossy(),
                        &delegated,
                    )
                })
            })
            .filter_map(|e| e.ok())
        {
            if !entry.file_type().is_file() {
                continue;
            }
            let fname = entry.file_name().to_string_lossy().to_string();
            let entry_path = entry.path().to_path_buf();

            if is_content_enc_name(&fname) {
                let bytes = fs::read(&entry_path)?;
                let enc_file = EncryptedFile::from_bytes(&bytes)?;
                if enc_file.vault_id != new_vid_bytes {
                    let plain = old_vault_key.decrypt_file(&enc_file)?;
                    let rekeyed = new_vault_key.encrypt_file(plain.expose_secret())?;
                    writes.push(PendingRekeyWrite {
                        dest_path: entry_path,
                        bytes: rekeyed.to_bytes(),
                        stale_path: None,
                    });
                }
            } else if is_full_enc_name(&fname) {
                let bytes = fs::read(&entry_path)?;
                let fenc_file = FullEncryptedFile::from_bytes(&bytes)?;
                if fenc_file.vault_id != new_vid_bytes {
                    let (rel_path, plain) = old_vault_key.decrypt_full_file(&fname, &fenc_file)?;
                    let (new_fname, rekeyed) =
                        new_vault_key.encrypt_full_file(&rel_path, plain.expose_secret())?;
                    let parent = entry_path.parent().unwrap_or(repo_path);
                    let new_path = parent.join(new_fname);
                    let stale_path = (new_path != entry_path).then_some(entry_path);
                    writes.push(PendingRekeyWrite {
                        dest_path: new_path,
                        bytes: rekeyed.to_bytes(),
                        stale_path,
                    });
                }
            } else if let Some(stem) = fname.strip_suffix(LEGACY_CONTENT_ENC_SUFFIX) {
                let bytes = fs::read(&entry_path)?;
                if is_legacy_dotler_archive_bytes(&bytes, Some(&old_vid_hex)) {
                    let enc_file = EncryptedFile::from_bytes(&bytes)?;
                    let plain = old_vault_key.decrypt_file(&enc_file)?;
                    let rekeyed = new_vault_key.encrypt_file(plain.expose_secret())?;
                    let parent = entry_path.parent().unwrap_or(repo_path);
                    let new_path = parent.join(format!("{stem}{CONTENT_ENC_SUFFIX}"));
                    let stale_path = (new_path != entry_path).then_some(entry_path);
                    writes.push(PendingRekeyWrite {
                        dest_path: new_path,
                        bytes: rekeyed.to_bytes(),
                        stale_path,
                    });
                }
            } else if parse_legacy_fenc_filename_stem(&fname).is_some() {
                let bytes = fs::read(&entry_path)?;
                if is_legacy_dotler_archive_bytes(&bytes, Some(&old_vid_hex)) {
                    let fenc_file = FullEncryptedFile::from_bytes(&bytes)?;
                    let (rel_path, plain) = old_vault_key.decrypt_full_file(&fname, &fenc_file)?;
                    let (new_fname, rekeyed) =
                        new_vault_key.encrypt_full_file(&rel_path, plain.expose_secret())?;
                    let parent = entry_path.parent().unwrap_or(repo_path);
                    let new_path = parent.join(new_fname);
                    let stale_path = (new_path != entry_path).then_some(entry_path);
                    writes.push(PendingRekeyWrite {
                        dest_path: new_path,
                        bytes: rekeyed.to_bytes(),
                        stale_path,
                    });
                }
            }
        }
    }

    Ok(writes)
}

/// Commits planned re-keying writes atomically and removes superseded paths.
pub fn apply_rekey_writes(writes: Vec<PendingRekeyWrite>) -> Result<usize, EngineError> {
    let rekeyed_count = writes.len();
    let written_paths: HashSet<PathBuf> = writes.iter().map(|w| w.dest_path.clone()).collect();
    let mut stale_to_remove = Vec::new();
    for item in writes {
        write_file_safe(&item.dest_path, &item.bytes)?;
        if let Some(old_path) = item.stale_path
            && !written_paths.contains(&old_path)
        {
            stale_to_remove.push(old_path);
        }
    }
    for old_path in stale_to_remove {
        let _ = fs::remove_file(old_path);
    }
    Ok(rekeyed_count)
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

/// Returns `true` if `path` has a recognized encrypted dotfile suffix (`.dotler.enc` or `.dotler.fenc`).
pub fn is_encrypted_repo_extension(path: &Path) -> bool {
    path.file_name().and_then(|s| s.to_str()).is_some_and(|n| {
        crate::crypto::is_content_enc_name(n) || crate::crypto::is_full_enc_name(n)
    })
}

/// Returns `true` if any group directory in `repo_path` contains a `.dotler.enc`, `.dotler.fenc`,
/// or vault-matching legacy `.enc`/`.fenc` archive.
pub fn has_encrypted_repo_files(repo_path: &Path, repo_cfg: &RepoConfig) -> bool {
    let expected_vid = repo_cfg.vault.as_ref().map(|v| v.vault_id.as_str());
    for g_name in repo_cfg.groups.keys() {
        let group_dir = crate::config::repo::group_repo_dir(repo_path, g_name);
        if !group_dir.is_dir() {
            continue;
        }
        for entry in WalkDir::new(&group_dir).into_iter().filter_map(|e| e.ok()) {
            if !entry.file_type().is_file() {
                continue;
            }
            if is_encrypted_repo_extension(entry.path()) {
                return true;
            }
            let fname = entry.file_name().to_string_lossy();
            if (fname.ends_with(crate::crypto::LEGACY_CONTENT_ENC_SUFFIX)
                || fname.ends_with(crate::crypto::LEGACY_FULL_ENC_SUFFIX))
                && let Ok(bytes) = fs::read(entry.path())
                && crate::crypto::is_legacy_dotler_archive_bytes(&bytes, expected_vid)
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
    unlock_vault_if_needed_with_prompt(repo_cfg, use_keyring, is_interactive, required, None)
}

/// Conditionally unlocks the repository [`VaultKey`] with an optional custom prompt prefix.
pub fn unlock_vault_if_needed_with_prompt(
    repo_cfg: &RepoConfig,
    use_keyring: bool,
    is_interactive: bool,
    required: bool,
    prompt_prefix: Option<&str>,
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
        let reason = if use_keyring {
            "Passphrase required in non-interactive mode. Run 'dotler vault init' or export DOTLER_PASSPHRASE.".to_string()
        } else {
            "Passphrase required in non-interactive mode (OS keyring is disabled via use_keyring = false). Export DOTLER_PASSPHRASE.".to_string()
        };
        return Err(EngineError::VaultLocked { reason });
    }

    let prefix = prompt_prefix.unwrap_or("Enter dotler vault passphrase");
    let prompt_msg = match vault_cfg
        .vault_hint
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(h) => format!("{prefix} (hint: {h}): "),
        None => format!("{prefix}: "),
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

fn canonical_or_raw(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

struct VaultIdTargetRepo {
    label: String,
    repo_path: PathBuf,
    manifest_path: PathBuf,
    repo_cfg: RepoConfig,
    vault_cfg: VaultConfig,
}

fn collect_repos_sharing_vault_id(
    local_cfg: &LocalConfig,
    requested_label: Option<&str>,
) -> Result<(VaultIdTargetRepo, Vec<VaultIdTargetRepo>, Vec<String>, bool), EngineError> {
    let (active_label, active_path) = resolve_repo_path_with_cwd(local_cfg, requested_label)?;
    let active_manifest = active_path.join("dotler.toml");
    if !active_manifest.is_file() {
        return Err(EngineError::Config(
            crate::config::ConfigError::RepoPathNotFound(active_path.display().to_string()),
        ));
    }
    let active_repo_cfg = RepoConfig::load(&active_manifest)?;
    let active_vault_cfg =
        active_repo_cfg
            .vault
            .clone()
            .ok_or_else(|| EngineError::VaultLocked {
                reason: "Vault is not configured".to_string(),
            })?;
    let target_vid = active_vault_cfg.vault_id.clone();
    let active_canon = canonical_or_raw(&active_path);

    let active_target = VaultIdTargetRepo {
        label: active_label.clone(),
        repo_path: active_path.clone(),
        manifest_path: active_manifest.clone(),
        repo_cfg: active_repo_cfg.clone(),
        vault_cfg: active_vault_cfg.clone(),
    };

    if requested_label.is_some() {
        let mut other_uses_vid = false;
        for (_label, cand_path) in local_cfg.candidate_repos_with_cwd() {
            if canonical_or_raw(&cand_path) == active_canon {
                continue;
            }
            let manifest = cand_path.join("dotler.toml");
            if let Ok(cfg) = RepoConfig::load_without_vault_check(&manifest)
                && cfg.vault.as_ref().is_some_and(|v| v.vault_id == target_vid)
            {
                other_uses_vid = true;
                break;
            }
        }
        return Ok((
            VaultIdTargetRepo {
                label: active_label,
                repo_path: active_path,
                manifest_path: active_manifest,
                repo_cfg: active_repo_cfg,
                vault_cfg: active_vault_cfg,
            },
            vec![active_target],
            Vec::new(),
            other_uses_vid,
        ));
    }

    let mut targets = Vec::new();
    let mut skipped_repos = Vec::new();
    let mut seen_paths = HashSet::new();

    for (label, cand_path) in local_cfg.candidate_repos_with_cwd() {
        let canon = canonical_or_raw(&cand_path);
        if !seen_paths.insert(canon) {
            continue;
        }
        let manifest = cand_path.join("dotler.toml");
        if !manifest.is_file() {
            skipped_repos.push(label);
            continue;
        }
        let Ok(cfg) = RepoConfig::load(&manifest) else {
            skipped_repos.push(label);
            continue;
        };
        match cfg.vault.clone() {
            Some(vcfg) if vcfg.vault_id == target_vid => {
                targets.push(VaultIdTargetRepo {
                    label,
                    repo_path: cand_path,
                    manifest_path: manifest,
                    repo_cfg: cfg,
                    vault_cfg: vcfg,
                });
            }
            _ => skipped_repos.push(label),
        }
    }

    if !seen_paths.contains(&active_canon) {
        targets.push(VaultIdTargetRepo {
            label: active_label,
            repo_path: active_path,
            manifest_path: active_manifest,
            repo_cfg: active_repo_cfg,
            vault_cfg: active_vault_cfg,
        });
    }

    skipped_repos.sort();
    Ok((active_target, targets, skipped_repos, false))
}

/// Rotates the 12-word recovery mnemonic slot across the specified repository or all
/// locally registered repositories sharing the active repository's `vault_id`.
pub fn rotate_vault_recovery(
    local_cfg: &LocalConfig,
    requested_label: Option<&str>,
    password_stdin: bool,
    is_interactive: bool,
) -> Result<VaultRotateRecoveryReport, EngineError> {
    let (active, targets, skipped_repos, _) =
        collect_repos_sharing_vault_id(local_cfg, requested_label)?;

    let current_pass = if password_stdin {
        read_new_passphrase(
            true,
            false,
            is_interactive,
            "Enter current vault passphrase: ",
        )?
    } else {
        let single_target = vec![(
            active.label.clone(),
            active.manifest_path.clone(),
            active.vault_cfg.clone(),
        )];
        resolve_old_passphrase_for_vaults(&single_target, local_cfg.use_keyring, is_interactive)?
    };

    let (rotated_active_cfg, new_mnemonic) =
        rotate_recovery_slot(&active.vault_cfg, &current_pass)?;
    let new_recovery_slot = rotated_active_cfg.recovery_slot;
    let target_vid = active.vault_cfg.vault_id.clone();

    let mut pending_manifests = Vec::with_capacity(targets.len());
    for target in &targets {
        let updated_vcfg = VaultConfig {
            vault_id: target.vault_cfg.vault_id.clone(),
            password_slot: target.vault_cfg.password_slot.clone(),
            recovery_slot: new_recovery_slot.clone(),
            vault_hint: target.vault_cfg.vault_hint.clone(),
        };
        let manifest_str = fs::read_to_string(&target.manifest_path)?;
        let updated_manifest =
            update_vault_manifest_section(&manifest_str, &target.vault_cfg, &updated_vcfg);
        pending_manifests.push((
            target.label.clone(),
            target.manifest_path.clone(),
            updated_manifest,
        ));
    }

    let mut rotated_repos = Vec::with_capacity(pending_manifests.len());
    for (label, manifest_path, updated_manifest) in pending_manifests {
        write_file_safe(&manifest_path, updated_manifest.as_bytes())?;
        rotated_repos.push(label);
    }

    if local_cfg.use_keyring
        && !target_vid.trim().is_empty()
        && OsKeyring::get_for_vault(&target_vid)
            .ok()
            .flatten()
            .is_none()
    {
        let _ = OsKeyring::set_with_fallback(Some(&target_vid), &current_pass);
    }

    Ok(VaultRotateRecoveryReport {
        status: "recovery_rotated".to_string(),
        vault_id: target_vid,
        rotated_repos,
        skipped_repos,
        new_mnemonic: new_mnemonic.phrase().to_string(),
    })
}

/// Replaces the master `VaultKey` with a newly generated key, re-encrypts all encrypted
/// artifacts in memory before committing to disk, updates `dotler.toml` across all
/// target repositories sharing `old_vault_id`, and synchronizes the OS keyring.
pub fn rotate_vault_key(
    local_cfg: &LocalConfig,
    requested_label: Option<&str>,
    password_stdin: bool,
    new_hint: Option<&str>,
    is_interactive: bool,
) -> Result<VaultRotateKeyReport, EngineError> {
    let (active, targets, skipped_repos, other_repo_uses_old_vid) =
        collect_repos_sharing_vault_id(local_cfg, requested_label)?;

    let old_vault_id = active.vault_cfg.vault_id.clone();
    let single_target = vec![(
        active.label.clone(),
        active.manifest_path.clone(),
        active.vault_cfg.clone(),
    )];
    let old_pass =
        resolve_old_passphrase_for_vaults(&single_target, local_cfg.use_keyring, is_interactive)?;
    let old_pw_slot = VaultSlot::from_base64(&active.vault_cfg.password_slot)?;
    let old_vault_key = old_pw_slot.unwrap(&old_pass, Some(&old_vault_id))?;

    let new_pass = read_new_passphrase(
        password_stdin,
        false,
        is_interactive,
        "Enter new vault passphrase: ",
    )?;
    let (new_base_cfg, new_vault_key, new_mnemonic) = init_vault(&new_pass)?;
    let new_vault_id = new_base_cfg.vault_id.clone();

    let resolved_override_hint: Option<Option<String>> = new_hint.map(|h| {
        let trimmed = h.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    });

    // Fail-fast phase: decrypt and re-encrypt every artifact across all target repos in memory
    // before touching a single file or manifest on disk.
    let mut all_rekey_writes = Vec::new();
    let mut pending_manifests = Vec::with_capacity(targets.len());
    let mut active_final_hint = active.vault_cfg.vault_hint.clone();
    if let Some(ref override_hint) = resolved_override_hint {
        active_final_hint = override_hint.clone();
    }

    for target in &targets {
        let repo_writes = plan_repo_rekey_writes(
            &target.repo_path,
            &target.repo_cfg,
            &old_vault_key,
            &new_vault_key,
        )?;
        all_rekey_writes.extend(repo_writes);

        let target_hint = match &resolved_override_hint {
            Some(override_hint) => override_hint.clone(),
            None => target.vault_cfg.vault_hint.clone(),
        };
        let target_new_cfg = VaultConfig {
            vault_id: new_base_cfg.vault_id.clone(),
            password_slot: new_base_cfg.password_slot.clone(),
            recovery_slot: new_base_cfg.recovery_slot.clone(),
            vault_hint: target_hint,
        };
        let manifest_str = fs::read_to_string(&target.manifest_path)?;
        let updated_manifest =
            update_vault_manifest_section(&manifest_str, &target.vault_cfg, &target_new_cfg);
        pending_manifests.push((
            target.label.clone(),
            target.manifest_path.clone(),
            updated_manifest,
        ));
    }

    let rekeyed_files = apply_rekey_writes(all_rekey_writes)?;

    let mut rotated_repos = Vec::with_capacity(pending_manifests.len());
    for (label, manifest_path, updated_manifest) in pending_manifests {
        write_file_safe(&manifest_path, updated_manifest.as_bytes())?;
        rotated_repos.push(label);
    }

    let mut keyring_updated = false;
    if local_cfg.use_keyring {
        if OsKeyring::set_for_vault(&new_vault_id, &new_pass).is_ok() {
            keyring_updated = true;
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
        if !other_repo_uses_old_vid && !old_vault_id.trim().is_empty() {
            let _ = OsKeyring::delete_for_vault(&old_vault_id);
        }
    }

    Ok(VaultRotateKeyReport {
        status: "key_rotated".to_string(),
        old_vault_id,
        vault_id: new_vault_id,
        rotated_repos,
        skipped_repos,
        rekeyed_files,
        keyring_updated,
        new_mnemonic: new_mnemonic.phrase().to_string(),
        hint: active_final_hint,
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
        let reason = if use_keyring {
            "Current passphrase required in non-interactive mode. Run 'dotler vault init' or export DOTLER_PASSPHRASE.".to_string()
        } else {
            "Current passphrase required in non-interactive mode (OS keyring is disabled via use_keyring = false). Export DOTLER_PASSPHRASE.".to_string()
        };
        return Err(EngineError::VaultLocked { reason });
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
    if !matches_any(&resolved.secret) {
        return Err(EngineError::Vault(
            crate::crypto::vault::VaultError::InvalidSecret,
        ));
    }
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
        let reason = if allow_env_var {
            "Passphrase required in non-interactive mode. Pass '--password-stdin' or export DOTLER_PASSPHRASE.".to_string()
        } else {
            "New passphrase required in non-interactive mode. Pass '--password-stdin'.".to_string()
        };
        return Err(EngineError::VaultLocked { reason });
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
        write_file_safe(&repo_a.join("shell/token.dotler.enc"), &enc_a).unwrap();
        write_file_safe(&repo_b.join("shell/token.dotler.enc"), &enc_b).unwrap();

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
            let disk_enc = fs::read(repo_dir.join("shell/token.dotler.enc")).unwrap();
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

    #[test]
    fn test_rotate_vault_recovery_syncs_shared_vault_id_repos_without_touching_ciphertext() {
        let _guard = crate::crypto::keyring::MockKeyringGuard::new();
        unsafe {
            std::env::remove_var(PASSPHRASE_ENV_VAR);
        }
        let tmp = tempfile::tempdir().unwrap();
        let repo_a = tmp.path().join("repo_a");
        let repo_b = tmp.path().join("repo_b");
        let repo_other = tmp.path().join("repo_other");
        for dir in [&repo_a, &repo_b, &repo_other] {
            fs::create_dir_all(dir.join("sec")).unwrap();
        }

        let pass = SecretString::new("shared-vault-pass-123".to_string());
        let (vcfg_shared, vkey_shared, old_mnemonic) = init_vault(&pass).unwrap();
        let (vcfg_other, _, other_mnemonic) = init_vault(&pass).unwrap();

        let enc_a = vkey_shared.encrypt_file(b"secret-a").unwrap().to_bytes();
        let (fenc_name, fenc_file) = vkey_shared
            .encrypt_full_file("sub/hidden.key", b"hidden-b")
            .unwrap();
        let fenc_bytes = fenc_file.to_bytes();
        write_file_safe(&repo_a.join("sec/a.dotler.enc"), &enc_a).unwrap();
        write_file_safe(&repo_b.join("sec").join(&fenc_name), &fenc_bytes).unwrap();

        let write_manifest = |dir: &Path, vcfg: &VaultConfig| {
            let content = format!(
                "vault_id = \"{}\"\npassword_slot = \"{}\"\nrecovery_slot = \"{}\"\n\n[sec]\nos-nux = \"~\"\nos-mac = \"~\"\nos-win = \"~\"\nfiles = \"* enc\"\n",
                vcfg.vault_id, vcfg.password_slot, vcfg.recovery_slot
            );
            write_file_safe(&dir.join("dotler.toml"), content.as_bytes()).unwrap();
        };
        write_manifest(&repo_a, &vcfg_shared);
        write_manifest(&repo_b, &vcfg_shared);
        write_manifest(&repo_other, &vcfg_other);

        let mut local_cfg = LocalConfig {
            default_repo: Some("a".to_string()),
            ..Default::default()
        };
        local_cfg
            .repos
            .insert("a".to_string(), repo_a.to_string_lossy().to_string());
        local_cfg
            .repos
            .insert("b".to_string(), repo_b.to_string_lossy().to_string());
        local_cfg.repos.insert(
            "other".to_string(),
            repo_other.to_string_lossy().to_string(),
        );

        OsKeyring::set_for_vault(&vcfg_shared.vault_id, &pass).unwrap();

        let report = rotate_vault_recovery(&local_cfg, None, false, false).unwrap();
        assert_eq!(report.status, "recovery_rotated");
        assert_eq!(report.vault_id, vcfg_shared.vault_id);
        assert_eq!(report.rotated_repos, vec!["a".to_string(), "b".to_string()]);
        assert_eq!(report.skipped_repos, vec!["other".to_string()]);
        assert_ne!(report.new_mnemonic, old_mnemonic.phrase());

        // Ciphertexts are untouched byte-for-byte
        assert_eq!(fs::read(repo_a.join("sec/a.dotler.enc")).unwrap(), enc_a);
        assert_eq!(
            fs::read(repo_b.join("sec").join(&fenc_name)).unwrap(),
            fenc_bytes
        );

        // Both a and b accept the new mnemonic and reject the old one; password_slot unchanged
        let new_m_secret = SecretString::new(report.new_mnemonic.clone());
        for dir in [&repo_a, &repo_b] {
            let loaded = RepoConfig::load(&dir.join("dotler.toml"))
                .unwrap()
                .vault
                .unwrap();
            assert_eq!(loaded.vault_id, vcfg_shared.vault_id);
            assert_eq!(loaded.password_slot, vcfg_shared.password_slot);
            assert_ne!(loaded.recovery_slot, vcfg_shared.recovery_slot);
            let rec_slot = VaultSlot::from_base64(&loaded.recovery_slot).unwrap();
            assert!(
                rec_slot
                    .unwrap(&old_mnemonic.0, Some(&loaded.vault_id))
                    .is_err()
            );
            let recovered_key = rec_slot
                .unwrap(&new_m_secret, Some(&loaded.vault_id))
                .unwrap();
            assert_eq!(recovered_key.expose(), vkey_shared.expose());
        }

        // Unrelated repo_other still uses its original mnemonic
        let other_loaded = RepoConfig::load(&repo_other.join("dotler.toml"))
            .unwrap()
            .vault
            .unwrap();
        assert_eq!(other_loaded.recovery_slot, vcfg_other.recovery_slot);
        let other_rec_slot = VaultSlot::from_base64(&other_loaded.recovery_slot).unwrap();
        assert!(
            other_rec_slot
                .unwrap(&other_mnemonic.0, Some(&other_loaded.vault_id))
                .is_ok()
        );
    }

    #[test]
    fn test_rotate_vault_key_rekeys_enc_and_fenc_across_shared_repos_and_updates_keyring() {
        let _guard = crate::crypto::keyring::MockKeyringGuard::new();
        unsafe {
            std::env::remove_var(PASSPHRASE_ENV_VAR);
        }
        let tmp = tempfile::tempdir().unwrap();
        let repo_a = tmp.path().join("repo_a");
        let repo_b = tmp.path().join("repo_b");
        let repo_other = tmp.path().join("repo_other");
        for dir in [&repo_a, &repo_b, &repo_other] {
            fs::create_dir_all(dir.join("sec")).unwrap();
        }

        let old_pass = SecretString::new("old-master-pass-111".to_string());
        let other_pass = SecretString::new("other-vault-pass-222".to_string());
        let (vcfg_shared, vkey_shared, old_mnemonic) = init_vault(&old_pass).unwrap();
        let (vcfg_other, _, _) = init_vault(&other_pass).unwrap();

        let enc_a = vkey_shared.encrypt_file(b"content-secret-a").unwrap();
        let (old_fenc_name, fenc_b) = vkey_shared
            .encrypt_full_file("nested/client.pem", b"full-secret-b")
            .unwrap();
        write_file_safe(&repo_a.join("sec/token.dotler.enc"), &enc_a.to_bytes()).unwrap();
        write_file_safe(&repo_b.join("sec").join(&old_fenc_name), &fenc_b.to_bytes()).unwrap();

        let write_manifest = |dir: &Path, vcfg: &VaultConfig| {
            let content = format!(
                "vault_id = \"{}\"\npassword_slot = \"{}\"\nrecovery_slot = \"{}\"\n\n[sec]\nos-nux = \"~\"\nos-mac = \"~\"\nos-win = \"~\"\nfiles = \"* enc\"\n",
                vcfg.vault_id, vcfg.password_slot, vcfg.recovery_slot
            );
            write_file_safe(&dir.join("dotler.toml"), content.as_bytes()).unwrap();
        };
        write_manifest(&repo_a, &vcfg_shared);
        write_manifest(&repo_b, &vcfg_shared);
        write_manifest(&repo_other, &vcfg_other);

        let mut local_cfg = LocalConfig {
            default_repo: Some("a".to_string()),
            ..Default::default()
        };
        local_cfg
            .repos
            .insert("a".to_string(), repo_a.to_string_lossy().to_string());
        local_cfg
            .repos
            .insert("b".to_string(), repo_b.to_string_lossy().to_string());
        local_cfg.repos.insert(
            "other".to_string(),
            repo_other.to_string_lossy().to_string(),
        );

        OsKeyring::set(&old_pass).unwrap();
        OsKeyring::set_for_vault(&vcfg_shared.vault_id, &old_pass).unwrap();
        OsKeyring::set_for_vault(&vcfg_other.vault_id, &other_pass).unwrap();

        OsKeyring::push_mock_prompt_reply("brand-new-master-pass-999");
        let report = rotate_vault_key(&local_cfg, None, false, Some("new-hint"), true).unwrap();
        assert_eq!(report.status, "key_rotated");
        assert_eq!(report.old_vault_id, vcfg_shared.vault_id);
        assert_ne!(report.vault_id, vcfg_shared.vault_id);
        assert_eq!(report.rotated_repos, vec!["a".to_string(), "b".to_string()]);
        assert_eq!(report.skipped_repos, vec!["other".to_string()]);
        assert_eq!(report.rekeyed_files, 2);
        assert!(report.keyring_updated);
        assert_eq!(report.hint.as_deref(), Some("new-hint"));
        assert_ne!(report.new_mnemonic, old_mnemonic.phrase());

        // Keyring has new_vault_id, removed unused old_vault_id, preserved other_vault_id, updated default
        assert!(
            OsKeyring::get_for_vault(&vcfg_shared.vault_id)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            OsKeyring::get_for_vault(&report.vault_id)
                .unwrap()
                .unwrap()
                .expose_secret(),
            "brand-new-master-pass-999"
        );
        assert_eq!(
            OsKeyring::get_for_vault(&vcfg_other.vault_id)
                .unwrap()
                .unwrap()
                .expose_secret(),
            "other-vault-pass-222"
        );
        assert_eq!(
            OsKeyring::get().unwrap().unwrap().expose_secret(),
            "brand-new-master-pass-999"
        );

        // Unlock new key and verify re-keyed .dotler.enc and .dotler.fenc
        let new_pass_sec = SecretString::new("brand-new-master-pass-999".to_string());
        let loaded_a = RepoConfig::load(&repo_a.join("dotler.toml"))
            .unwrap()
            .vault
            .unwrap();
        let loaded_b = RepoConfig::load(&repo_b.join("dotler.toml"))
            .unwrap()
            .vault
            .unwrap();
        assert_eq!(loaded_a.vault_id, report.vault_id);
        assert_eq!(loaded_b.vault_id, report.vault_id);
        assert_eq!(loaded_a.vault_hint.as_deref(), Some("new-hint"));

        let new_key = VaultSlot::from_base64(&loaded_a.password_slot)
            .unwrap()
            .unwrap(&new_pass_sec, Some(&report.vault_id))
            .unwrap();
        let rekeyed_enc =
            EncryptedFile::from_bytes(&fs::read(repo_a.join("sec/token.dotler.enc")).unwrap())
                .unwrap();
        assert_eq!(rekeyed_enc.vault_id, new_key.vault_id_bytes());
        assert_eq!(
            new_key
                .decrypt_file(&rekeyed_enc)
                .unwrap()
                .expose_secret()
                .as_slice(),
            b"content-secret-a"
        );

        // Old .dotler.fenc filename must be removed and replaced with new derived filename
        assert!(!repo_b.join("sec").join(&old_fenc_name).exists());
        let new_fenc_name = new_key.derive_full_enc_filename("nested/client.pem");
        assert_ne!(new_fenc_name, old_fenc_name);
        let rekeyed_fenc = FullEncryptedFile::from_bytes(
            &fs::read(repo_b.join("sec").join(&new_fenc_name)).unwrap(),
        )
        .unwrap();
        let (dec_rel, dec_plain) = new_key
            .decrypt_full_file(&new_fenc_name, &rekeyed_fenc)
            .unwrap();
        assert_eq!(dec_rel, "nested/client.pem");
        assert_eq!(dec_plain.expose_secret().as_slice(), b"full-secret-b");
    }

    #[test]
    fn test_rotate_vault_key_fail_fast_on_tampered_file_leaves_disk_untouched() {
        let _guard = crate::crypto::keyring::MockKeyringGuard::new();
        unsafe {
            std::env::remove_var(PASSPHRASE_ENV_VAR);
        }
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        fs::create_dir_all(repo.join("sec")).unwrap();

        let old_pass = SecretString::new("old-pass-tamper-test".to_string());
        let (vcfg, vkey, _) = init_vault(&old_pass).unwrap();

        let mut enc_bytes = vkey.encrypt_file(b"intact").unwrap().to_bytes();
        let last = enc_bytes.len() - 1;
        enc_bytes[last] ^= 0xFF; // Tamper MAC tag
        write_file_safe(&repo.join("sec/corrupt.dotler.enc"), &enc_bytes).unwrap();

        let manifest_content = format!(
            "vault_id = \"{}\"\npassword_slot = \"{}\"\nrecovery_slot = \"{}\"\n\n[sec]\nos-nux = \"~\"\nos-mac = \"~\"\nos-win = \"~\"\nfiles = \"* enc\"\n",
            vcfg.vault_id, vcfg.password_slot, vcfg.recovery_slot
        );
        write_file_safe(&repo.join("dotler.toml"), manifest_content.as_bytes()).unwrap();

        let mut local_cfg = LocalConfig {
            default_repo: Some("main".to_string()),
            ..Default::default()
        };
        local_cfg
            .repos
            .insert("main".to_string(), repo.to_string_lossy().to_string());

        OsKeyring::set_for_vault(&vcfg.vault_id, &old_pass).unwrap();
        OsKeyring::push_mock_prompt_reply("new-pass-should-not-apply");

        let res = rotate_vault_key(&local_cfg, None, false, None, true);
        assert!(res.is_err());

        // Manifest and keyring must remain completely untouched
        assert_eq!(
            fs::read_to_string(repo.join("dotler.toml")).unwrap(),
            manifest_content
        );
        assert_eq!(
            OsKeyring::get_for_vault(&vcfg.vault_id)
                .unwrap()
                .unwrap()
                .expose_secret(),
            "old-pass-tamper-test"
        );
    }

    #[test]
    fn test_rotate_commands_respect_use_keyring_false_and_fail_fast_on_wrong_old_pass() {
        let _guard = crate::crypto::keyring::MockKeyringGuard::new();
        unsafe {
            std::env::remove_var(PASSPHRASE_ENV_VAR);
        }
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        fs::create_dir_all(repo.join("sec")).unwrap();

        let pass_v1 = SecretString::new("kr-off-pass-111".to_string());
        let (vcfg, vkey, _) = init_vault(&pass_v1).unwrap();
        write_file_safe(
            &repo.join("sec/item.dotler.enc"),
            &vkey.encrypt_file(b"secret-body").unwrap().to_bytes(),
        )
        .unwrap();
        write_file_safe(
            &repo.join("dotler.toml"),
            format!(
                "vault_id = \"{}\"\npassword_slot = \"{}\"\nrecovery_slot = \"{}\"\n\n[sec]\nos-nux = \"~\"\nos-mac = \"~\"\nos-win = \"~\"\nfiles = \"* enc\"\n",
                vcfg.vault_id, vcfg.password_slot, vcfg.recovery_slot
            )
            .as_bytes(),
        )
        .unwrap();

        let mut local_cfg = LocalConfig {
            default_repo: Some("main".to_string()),
            use_keyring: false,
            ..Default::default()
        };
        local_cfg
            .repos
            .insert("main".to_string(), repo.to_string_lossy().to_string());

        // Populate OS keyring with pass_v1; use_keyring=false must ignore and never modify it
        OsKeyring::set(&pass_v1).unwrap();
        OsKeyring::set_for_vault(&vcfg.vault_id, &pass_v1).unwrap();

        // Non-interactive unlock_vault_if_needed gives use_keyring=false hint (not `dotler vault init`)
        let repo_cfg = RepoConfig::load(&repo.join("dotler.toml")).unwrap();
        let locked_err = unlock_vault_if_needed(&repo_cfg, false, false, true).unwrap_err();
        assert!(locked_err.hint().contains("use_keyring = false"));
        assert!(!locked_err.hint().contains("dotler vault init"));

        // Interactive wrong old passphrase fails immediately before prompting for new passphrase
        OsKeyring::push_mock_prompt_reply("wrong-pass");
        OsKeyring::push_mock_prompt_reply("should-not-be-consumed");
        assert!(rotate_vault_passphrases(&local_cfg, Some("main"), false, None, true).is_err());
        assert_eq!(
            OsKeyring::take_mock_prompt_reply().as_deref(),
            Some("should-not-be-consumed")
        );

        // 1. rotate password interactively with use_keyring=false -> keyring_updated=false
        OsKeyring::push_mock_prompt_reply("kr-off-pass-111");
        OsKeyring::push_mock_prompt_reply("kr-off-pass-222");
        let pw_report =
            rotate_vault_passphrases(&local_cfg, Some("main"), false, None, true).unwrap();
        assert!(!pw_report.keyring_updated);
        assert_eq!(
            OsKeyring::get_for_vault(&vcfg.vault_id)
                .unwrap()
                .unwrap()
                .expose_secret(),
            "kr-off-pass-111"
        );

        // 2. rotate recovery interactively with use_keyring=false
        OsKeyring::push_mock_prompt_reply("kr-off-pass-222");
        let rec_report = rotate_vault_recovery(&local_cfg, Some("main"), false, true).unwrap();
        assert_eq!(rec_report.status, "recovery_rotated");

        // 3. rotate key interactively with use_keyring=false -> keyring_updated=false & old slot untouched
        OsKeyring::push_mock_prompt_reply("kr-off-pass-222");
        OsKeyring::push_mock_prompt_reply("kr-off-pass-333");
        let key_report = rotate_vault_key(&local_cfg, Some("main"), false, None, true).unwrap();
        assert!(!key_report.keyring_updated);
        assert_eq!(key_report.rekeyed_files, 1);
        assert!(
            OsKeyring::get_for_vault(&key_report.vault_id)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            OsKeyring::get_for_vault(&vcfg.vault_id)
                .unwrap()
                .unwrap()
                .expose_secret(),
            "kr-off-pass-111"
        );
    }
}
