//! CLI handlers for `vault` (`init`, `passwd`, `recover`) and `key` (`set`, `del`) commands.

use std::io::Write;

use crate::cli::args::{Cli, KeyCommand, VaultCommand, VaultImportArgs, VaultInitArgs};
use crate::cli::output::{
    KeyLsReport, KeyRepoStatusEntry, KeyReport, VaultImportReport, VaultInitReport,
    VaultRecoverReport, render_success_to,
};
use crate::config::local::{
    LOCAL_CONFIG_FILE, LocalConfig, WalkDir, expand_tilde, find_ancestor_repo_dir,
    get_local_config, resolve_repo_path_with_cwd,
};
use crate::config::repo::{RepoConfig, VaultConfig, get_repo_config, update_vault_manifest_section};
use crate::config::state::{DotlerLockGuard, write_file_safe};
use crate::core::vault_loader::{
    read_new_passphrase, rotate_vault_passphrases, unlock_vault_if_needed,
};
use crate::crypto::{ExposeSecret, SecretString};
use crate::crypto::keyring::OsKeyring;
use crate::crypto::vault::{EncryptedFile, VaultSlot, init_vault, recover_vault};
use crate::engine::EngineError;
use crate::engine::remote::{GitRunner, REMOTE_TOML_FETCH_MAX_BYTES, fetch_http_text, parse_url};
use crate::tui::confirm::{ConfirmError, ConfirmPrompt, confirm_proceed_to};

pub(crate) fn resolve_vault_init_passphrase_for_vault<W: Write>(
    writer: &mut W,
    vault_id: Option<&str>,
    use_keyring: bool,
    password_stdin: bool,
    is_interactive: bool,
    json_mode: bool,
    is_import: bool,
) -> Result<(SecretString, bool), EngineError> {
    let has_env_pass = std::env::var(crate::crypto::keyring::PASSPHRASE_ENV_VAR)
        .is_ok_and(|v| !v.trim_end_matches(['\r', '\n']).is_empty());

    let existing_keyring = if !password_stdin && !has_env_pass && use_keyring {
        vault_id
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .and_then(|vid| OsKeyring::get_for_vault(vid).ok().flatten())
            .or_else(|| OsKeyring::get().ok().flatten())
    } else {
        None
    };

    if let Some(existing_secret) = existing_keyring {
        if json_mode || (!is_interactive && !ConfirmPrompt::has_mock_or_env_input()) {
            return Ok((existing_secret, false));
        }

        let reuse = match confirm_proceed_to(
            writer,
            "A passphrase is already stored in the OS keyring. Use existing keyring passphrase?",
        ) {
            Ok(val) => val,
            Err(ConfirmError::NonTtyError) => true,
            Err(ConfirmError::TerminalIoError(e)) => return Err(EngineError::Io(e)),
        };

        if reuse {
            return Ok((existing_secret, false));
        }
    }

    let prompt = if is_import {
        "Enter vault passphrase: "
    } else {
        "Enter new vault passphrase: "
    };
    let pass = read_new_passphrase(password_stdin, true, is_interactive, prompt)?;
    Ok((pass, true))
}

#[allow(dead_code)]
pub(crate) fn resolve_vault_init_passphrase<W: Write>(
    writer: &mut W,
    use_keyring: bool,
    password_stdin: bool,
    is_interactive: bool,
    json_mode: bool,
    is_import: bool,
) -> Result<(SecretString, bool), EngineError> {
    resolve_vault_init_passphrase_for_vault(
        writer,
        None,
        use_keyring,
        password_stdin,
        is_interactive,
        json_mode,
        is_import,
    )
}

fn resolve_active_repo_vault(
    local_cfg: &LocalConfig,
    repo_override: Option<&str>,
) -> Result<Option<VaultConfig>, EngineError> {
    if let Some(label) = repo_override {
        let (_resolved_label, repo_path) = resolve_repo_path_with_cwd(local_cfg, Some(label))?;
        let manifest_path = repo_path.join("dotler.toml");
        if !manifest_path.is_file() {
            return Err(EngineError::Config(
                crate::config::ConfigError::RepoPathNotFound(repo_path.display().to_string()),
            ));
        }
        let repo_cfg = RepoConfig::load(&manifest_path)?;
        return Ok(repo_cfg.vault);
    }

    let Ok((_label, repo_path)) = resolve_repo_path_with_cwd(local_cfg, None) else {
        return Ok(None);
    };
    let manifest_path = repo_path.join("dotler.toml");
    if !manifest_path.is_file() {
        return Ok(None);
    }
    match RepoConfig::load(&manifest_path) {
        Ok(cfg) => Ok(cfg.vault),
        Err(_) => Ok(None),
    }
}

fn collect_known_vault_ids(local_cfg: &LocalConfig) -> Vec<String> {
    let mut ids = Vec::new();
    let mut push_from_dir = |dir: &std::path::Path| {
        let manifest_path = dir.join("dotler.toml");
        if manifest_path.is_file()
            && let Ok(cfg) = RepoConfig::load(&manifest_path)
            && let Some(v) = cfg.vault
            && !v.vault_id.trim().is_empty()
            && !ids.contains(&v.vault_id)
        {
            ids.push(v.vault_id);
        }
    };

    for raw_path in local_cfg.repos.values() {
        push_from_dir(&expand_tilde(raw_path));
    }
    if let Ok(cwd) = std::env::current_dir()
        && let Some(repo_dir) = find_ancestor_repo_dir(&cwd)
    {
        push_from_dir(&repo_dir);
    }
    ids
}

fn fetch_external_vault_payload(
    local_cfg: &LocalConfig,
    args: &VaultImportArgs,
) -> Result<String, EngineError> {
    if let Some(ref git_url) = args.git {
        let parsed = parse_url(git_url)?;
        let rel_path = match &parsed.subpath {
            Some(sub) if !sub.is_empty() => format!("{}/dotler.toml", sub.trim_matches('/')),
            _ => "dotler.toml".to_string(),
        };
        let raw_bytes = GitRunner::fetch_file_shallow(
            &parsed.clone_url,
            None,
            &rel_path,
            REMOTE_TOML_FETCH_MAX_BYTES,
        )?;
        let raw = String::from_utf8(raw_bytes).map_err(|e| {
            EngineError::Config(crate::config::ConfigError::TomlSyntaxError(e.to_string()))
        })?;
        return Ok(raw);
    }
    if let Some(ref http_url) = args.url {
        let raw = fetch_http_text(http_url, REMOTE_TOML_FETCH_MAX_BYTES)?;
        return Ok(raw);
    }
    if let Some(ref file_source) = args.file {
        let target_file = if let Some(registered) = local_cfg.repos.get(file_source) {
            expand_tilde(registered).join("dotler.toml")
        } else {
            let expanded = expand_tilde(file_source);
            if expanded.is_dir() {
                expanded.join("dotler.toml")
            } else {
                expanded
            }
        };
        if !target_file.exists() {
            return Err(EngineError::FileNotFound { path: target_file });
        }
        return Ok(std::fs::read_to_string(&target_file)?);
    }
    Err(EngineError::Config(
        crate::config::ConfigError::MissingVaultConfig,
    ))
}

pub(crate) fn handle_vault<W: Write>(
    cmd: &VaultCommand,
    cli: &Cli,
    is_interactive: bool,
    stdout: &mut W,
    _lock: &DotlerLockGuard,
) -> Result<i32, EngineError> {
    let local_cfg_res = get_local_config(expand_tilde(LOCAL_CONFIG_FILE));
    let local_cfg = local_cfg_res.get()?;

    match cmd {
        VaultCommand::Init(args) => handle_vault_init(args, local_cfg, cli, is_interactive, stdout),
        VaultCommand::Import(args) => {
            handle_vault_import(args, local_cfg, cli, is_interactive, stdout)
        }
        VaultCommand::Passwd(args) => {
            let data = rotate_vault_passphrases(
                local_cfg,
                cli.repo.as_deref(),
                args.password_stdin,
                args.hint.as_deref(),
                is_interactive,
            )?;
            Ok(render_success_to(stdout, "vault passwd", &data, cli.json))
        }
        VaultCommand::Recover(args) => {
            let (_label, repo_path) = resolve_repo_path_with_cwd(local_cfg, cli.repo.as_deref())?;
            let manifest_path = repo_path.join("dotler.toml");
            let mut repo_cfg_res = get_repo_config(manifest_path);
            let mut repo_cfg = repo_cfg_res.get()?.clone();

            let vault_cfg = repo_cfg
                .vault
                .as_ref()
                .ok_or_else(|| EngineError::VaultLocked {
                    reason: "Vault is not configured".to_string(),
                })?;
            let mnemonic_phrase = if let Some(ref m) = args.mnemonic {
                SecretString::new(m.clone())
            } else {
                read_new_passphrase(
                    false,
                    false,
                    is_interactive,
                    "Enter 12-word recovery mnemonic: ",
                )?
            };
            let new_pass = read_new_passphrase(
                args.password_stdin,
                true,
                is_interactive,
                "Enter new vault passphrase: ",
            )?;

            let (mut new_cfg, new_mnemonic) =
                recover_vault(vault_cfg, &mnemonic_phrase, &new_pass)?;
            if let Some(ref h) = args.hint {
                let trimmed = h.trim();
                new_cfg.vault_hint = (!trimmed.is_empty()).then(|| trimmed.to_string());
            }

            let vault_id = new_cfg.vault_id.clone();
            let vault_hint = new_cfg.vault_hint.clone();
            repo_cfg.vault = Some(new_cfg);
            repo_cfg_res.set(repo_cfg)?;

            if local_cfg.use_keyring {
                let _ = OsKeyring::set_with_fallback(Some(&vault_id), &new_pass);
            }

            let data = VaultRecoverReport {
                vault_id,
                status: "recovered".to_string(),
                new_mnemonic: new_mnemonic.phrase().to_string(),
                hint: vault_hint,
            };
            Ok(render_success_to(stdout, "vault recover", &data, cli.json))
        }
    }
}

fn handle_vault_init<W: Write>(
    args: &VaultInitArgs,
    local_cfg: &LocalConfig,
    cli: &Cli,
    is_interactive: bool,
    stdout: &mut W,
) -> Result<i32, EngineError> {
    let (_label, repo_path) = resolve_repo_path_with_cwd(local_cfg, cli.repo.as_deref())?;
    let manifest_path = repo_path.join("dotler.toml");
    let mut repo_cfg = RepoConfig::load_without_vault_check(&manifest_path)?;

    if repo_cfg.vault.is_some() {
        return Err(EngineError::Config(crate::config::ConfigError::UnknownField {
            field: "vault".to_string(),
            hint: "Vault is already initialized in dotler.toml. Use 'dotler vault passwd' to change password or 'dotler vault import' to replace with another vault."
                .to_string(),
        }));
    }

    let explicit_hint = args
        .hint
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    let (pass, should_update_keyring) = resolve_vault_init_passphrase_for_vault(
        stdout,
        None,
        local_cfg.use_keyring,
        args.password_stdin,
        is_interactive,
        cli.json,
        false,
    )?;
    let (mut vault_cfg, _vault_key, mnemonic) = init_vault(&pass)?;
    vault_cfg.vault_hint = explicit_hint;

    let vault_id = vault_cfg.vault_id.clone();
    let vault_hint = vault_cfg.vault_hint.clone();
    repo_cfg.vault = Some(vault_cfg);

    let mut repo_cfg_res = get_repo_config(manifest_path);
    repo_cfg_res.set(repo_cfg)?;

    if local_cfg.use_keyring
        && (should_update_keyring || OsKeyring::get_for_vault(&vault_id).ok().flatten().is_none())
    {
        let _ = OsKeyring::set_with_fallback(Some(&vault_id), &pass);
    }

    let data = VaultInitReport {
        vault_id,
        mnemonic: Some(mnemonic.phrase().to_string()),
        hint: vault_hint,
    };
    Ok(render_success_to(stdout, "vault init", &data, cli.json))
}

fn handle_vault_import<W: Write>(
    args: &VaultImportArgs,
    local_cfg: &LocalConfig,
    cli: &Cli,
    is_interactive: bool,
    stdout: &mut W,
) -> Result<i32, EngineError> {
    let (_label, repo_path) = resolve_repo_path_with_cwd(local_cfg, cli.repo.as_deref())?;
    let manifest_path = repo_path.join("dotler.toml");
    let mut repo_cfg = RepoConfig::load_without_vault_check(&manifest_path)?;

    let raw_payload = fetch_external_vault_payload(local_cfg, args)?;
    let ext_vault = VaultConfig::parse_external_payload(&raw_payload)?;
    let pw_slot = VaultSlot::from_base64(&ext_vault.password_slot)?;
    let _rec_slot = VaultSlot::from_base64(&ext_vault.recovery_slot)?;

    let explicit_hint = args
        .hint
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    let expected_vid = (!ext_vault.vault_id.is_empty()).then_some(ext_vault.vault_id.as_str());
    let (pass, should_update_keyring) = resolve_vault_init_passphrase_for_vault(
        stdout,
        expected_vid,
        local_cfg.use_keyring,
        args.password_stdin,
        is_interactive,
        cli.json,
        true,
    )?;

    let new_vault_key = pw_slot.unwrap(&pass, expected_vid)?;
    let new_vid_bytes = new_vault_key.vault_id_bytes();
    let imported_cfg = VaultConfig {
        vault_id: new_vault_key.vault_id(),
        password_slot: ext_vault.password_slot,
        recovery_slot: ext_vault.recovery_slot,
        vault_hint: explicit_hint.or(ext_vault.vault_hint),
    };

    // Scan existing .enc files in group directories and collect any belonging to another vault.
    let mut mismatched_enc_files: Vec<(std::path::PathBuf, EncryptedFile)> = Vec::new();
    for g_name in repo_cfg.groups.keys() {
        let group_dir = repo_path.join(g_name);
        if !group_dir.is_dir() {
            continue;
        }
        for entry in WalkDir::new(&group_dir).into_iter().filter_map(|e| e.ok()) {
            if entry.file_type().is_file()
                && entry.path().extension().and_then(|s| s.to_str()) == Some("enc")
            {
                let bytes = std::fs::read(entry.path())?;
                let enc_file = EncryptedFile::from_bytes(&bytes)?;
                if enc_file.vault_id != new_vid_bytes {
                    mismatched_enc_files.push((entry.path().to_path_buf(), enc_file));
                }
            }
        }
    }

    let mut rekeyed_writes: Vec<(std::path::PathBuf, Vec<u8>)> = Vec::new();
    if !mismatched_enc_files.is_empty() {
        let old_vcfg = repo_cfg.vault.as_ref().ok_or(EngineError::Config(
            crate::config::ConfigError::MissingVaultConfig,
        ))?;
        let old_slot = VaultSlot::from_base64(&old_vcfg.password_slot)?;
        let old_vault_key = if let Ok(key) = old_slot.unwrap(&pass, Some(&old_vcfg.vault_id)) {
            key
        } else {
            unlock_vault_if_needed(&repo_cfg, local_cfg.use_keyring, is_interactive, true)?
                .ok_or(EngineError::Config(
                    crate::config::ConfigError::MissingVaultConfig,
                ))?
        };

        for (enc_path, enc_file) in mismatched_enc_files {
            let plain = old_vault_key.decrypt_file(&enc_file)?;
            let rekeyed = new_vault_key.encrypt_file(plain.expose_secret())?;
            rekeyed_writes.push((enc_path, rekeyed.to_bytes()));
        }
    }

    let rekeyed_files = rekeyed_writes.len();
    for (enc_path, bytes) in rekeyed_writes {
        write_file_safe(&enc_path, &bytes)?;
    }

    let vault_id = imported_cfg.vault_id.clone();
    let vault_hint = imported_cfg.vault_hint.clone();
    if let Some(ref old_vcfg) = repo_cfg.vault {
        let manifest_str = std::fs::read_to_string(&manifest_path)?;
        let updated = update_vault_manifest_section(&manifest_str, old_vcfg, &imported_cfg);
        write_file_safe(&manifest_path, updated.as_bytes())?;
    } else {
        repo_cfg.vault = Some(imported_cfg);
        let mut repo_cfg_res = get_repo_config(manifest_path);
        repo_cfg_res.set(repo_cfg)?;
    }

    if local_cfg.use_keyring
        && (should_update_keyring || OsKeyring::get_for_vault(&vault_id).ok().flatten().is_none())
    {
        let _ = OsKeyring::set_with_fallback(Some(&vault_id), &pass);
    }

    let data = VaultImportReport {
        vault_id,
        rekeyed_files,
        hint: vault_hint,
    };
    Ok(render_success_to(stdout, "vault import", &data, cli.json))
}

pub(crate) fn handle_key<W: Write>(
    cmd: &KeyCommand,
    cli: &Cli,
    is_interactive: bool,
    stdout: &mut W,
    _lock: &DotlerLockGuard,
) -> Result<i32, EngineError> {
    let local_cfg_res = get_local_config(expand_tilde(LOCAL_CONFIG_FILE));
    let local_cfg = match local_cfg_res.get() {
        Ok(cfg) => cfg.clone(),
        Err(e) if cli.repo.is_some() => return Err(EngineError::Config(e)),
        Err(_) => LocalConfig::default(),
    };

    match cmd {
        KeyCommand::Ls(_) => {
            let mut candidates: Vec<(String, std::path::PathBuf)> = local_cfg
                .repos
                .iter()
                .map(|(label, raw)| (label.clone(), expand_tilde(raw)))
                .collect();

            if let Ok(cwd) = std::env::current_dir()
                && let Some(repo_dir) = find_ancestor_repo_dir(&cwd)
            {
                let canon_cwd =
                    std::fs::canonicalize(&repo_dir).unwrap_or_else(|_| repo_dir.clone());
                let already = candidates.iter().any(|(_, p)| {
                    std::fs::canonicalize(p).unwrap_or_else(|_| p.clone()) == canon_cwd
                });
                if !already {
                    let cwd_label = repo_dir
                        .file_name()
                        .map(|f| f.to_string_lossy().to_string())
                        .unwrap_or_else(|| "current".to_string());
                    candidates.push((cwd_label, repo_dir));
                }
            }

            let default_secret = if local_cfg.use_keyring {
                OsKeyring::get().ok().flatten()
            } else {
                None
            };

            let mut entries = Vec::with_capacity(candidates.len());
            for (label, repo_path) in candidates {
                let manifest_path = repo_path.join("dotler.toml");
                let path_str = repo_path.display().to_string();
                if !manifest_path.is_file() {
                    entries.push(KeyRepoStatusEntry {
                        label,
                        path: path_str,
                        vault_id: None,
                        vault_hint: None,
                        keyring_status: "missing_repo".to_string(),
                    });
                    continue;
                }
                let Ok(repo_cfg) = RepoConfig::load_without_vault_check(&manifest_path) else {
                    entries.push(KeyRepoStatusEntry {
                        label,
                        path: path_str,
                        vault_id: None,
                        vault_hint: None,
                        keyring_status: "missing_repo".to_string(),
                    });
                    continue;
                };
                let Some(vcfg) = repo_cfg.vault else {
                    entries.push(KeyRepoStatusEntry {
                        label,
                        path: path_str,
                        vault_id: None,
                        vault_hint: None,
                        keyring_status: "no_vault".to_string(),
                    });
                    continue;
                };

                let status = if !local_cfg.use_keyring {
                    "disabled".to_string()
                } else {
                    let slot = VaultSlot::from_base64(&vcfg.password_slot).ok();
                    let vault_sec = OsKeyring::get_for_vault(&vcfg.vault_id).ok().flatten();
                    if let Some(ref sec) = vault_sec
                        && slot
                            .as_ref()
                            .is_some_and(|s| s.unwrap(sec, Some(&vcfg.vault_id)).is_ok())
                    {
                        "vault_slot".to_string()
                    } else if let Some(ref dsec) = default_secret
                        && slot
                            .as_ref()
                            .is_some_and(|s| s.unwrap(dsec, Some(&vcfg.vault_id)).is_ok())
                    {
                        "default_fallback".to_string()
                    } else if vault_sec.is_some() {
                        "mismatch".to_string()
                    } else {
                        "locked".to_string()
                    }
                };

                entries.push(KeyRepoStatusEntry {
                    label,
                    path: path_str,
                    vault_id: Some(vcfg.vault_id),
                    vault_hint: vcfg.vault_hint,
                    keyring_status: status,
                });
            }

            let report = KeyLsReport {
                use_keyring: local_cfg.use_keyring,
                default_slot_set: default_secret.is_some(),
                repos: entries,
            };
            Ok(render_success_to(stdout, "key ls", &report, cli.json))
        }
        KeyCommand::Set(args) => {
            let vault_cfg_opt = resolve_active_repo_vault(&local_cfg, cli.repo.as_deref())?;
            let pass = read_new_passphrase(
                args.password_stdin,
                true,
                is_interactive,
                "Enter vault passphrase to store in keyring: ",
            )?;
            let target_vid = vault_cfg_opt
                .as_ref()
                .map(|v| v.vault_id.trim())
                .filter(|s| !s.is_empty());
            OsKeyring::set_with_fallback(target_vid, &pass)
                .map_err(|e| EngineError::Crypto(crate::crypto::CryptoError::Keyring(e)))?;
            let data = KeyReport {
                status: "keyring_updated".to_string(),
            };
            Ok(render_success_to(stdout, "key set", &data, cli.json))
        }
        KeyCommand::Del(args) => {
            if args.all {
                let vault_ids = collect_known_vault_ids(&local_cfg);
                OsKeyring::delete_all(&vault_ids)
                    .map_err(|e| EngineError::Crypto(crate::crypto::CryptoError::Keyring(e)))?;
            } else {
                let vault_cfg_opt = resolve_active_repo_vault(&local_cfg, cli.repo.as_deref())?;
                if let Some(vault_cfg) = vault_cfg_opt
                    && !vault_cfg.vault_id.trim().is_empty()
                {
                    let vault_sec = OsKeyring::get_for_vault(&vault_cfg.vault_id).ok().flatten();
                    OsKeyring::delete_for_vault(&vault_cfg.vault_id)
                        .map_err(|e| EngineError::Crypto(crate::crypto::CryptoError::Keyring(e)))?;

                    if let Ok(Some(default_sec)) = OsKeyring::get() {
                        let matches_vault_sec = vault_sec
                            .as_ref()
                            .is_some_and(|v| v.expose_secret() == default_sec.expose_secret());
                        let unlocks_vault = VaultSlot::from_base64(&vault_cfg.password_slot)
                            .ok()
                            .and_then(|slot| {
                                slot.unwrap(&default_sec, Some(&vault_cfg.vault_id)).ok()
                            })
                            .is_some();
                        if matches_vault_sec || unlocks_vault {
                            let _ = OsKeyring::delete();
                        }
                    }
                } else {
                    OsKeyring::delete()
                        .map_err(|e| EngineError::Crypto(crate::crypto::CryptoError::Keyring(e)))?;
                }
            }
            let data = KeyReport {
                status: "keyring_deleted".to_string(),
            };
            Ok(render_success_to(stdout, "key del", &data, cli.json))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::state::write_file_safe;
    use crate::core::vault_loader::{resolve_old_passphrase_for_vaults, unlock_vault_if_needed};
    use crate::crypto::ExposeSecret;
    use crate::crypto::keyring::MockKeyringGuard;
    use crate::crypto::vault::{VaultSlot, change_password};
    use std::fs;
    use std::path::{Path, PathBuf};

    fn mock_guard<'a>() -> MockKeyringGuard<'a> {
        let g = MockKeyringGuard::new();
        unsafe {
            std::env::remove_var(crate::crypto::keyring::PASSPHRASE_ENV_VAR);
        }
        g
    }

    #[test]
    fn test_interactive_prompt_unlocks_vault_and_autosaves_to_keyring() {
        let _mock = mock_guard();
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
            OsKeyring::get().unwrap().unwrap().expose_secret(),
            "interactive-day0-secret"
        );

        OsKeyring::push_mock_prompt_reply("rotated-new-secret-999");
        let targets = vec![(
            "primary".to_string(),
            PathBuf::from("/tmp/dummy"),
            vault_cfg.clone(),
        )];
        let resolved_old = resolve_old_passphrase_for_vaults(&targets, true, true).unwrap();
        assert_eq!(resolved_old.expose_secret(), "interactive-day0-secret");

        let resolved_new =
            read_new_passphrase(false, false, true, "Enter new vault passphrase: ").unwrap();
        assert_eq!(resolved_new.expose_secret(), "rotated-new-secret-999");

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
        let _mock = mock_guard();
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
        assert_eq!(keyring_secret.expose_secret(), "shared-new-pass-999");
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
            assert_eq!(dec.expose_secret().as_slice(), expected);
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
        let _mock = mock_guard();
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
    fn test_resolve_vault_init_passphrase_prompts_to_reuse_existing_keyring() {
        let _mock = mock_guard();
        OsKeyring::set(&SecretString::new("existing-keyring-pass-111".to_string())).unwrap();

        ConfirmPrompt::push_mock_input("yes");
        let (resolved_yes, update_yes) =
            resolve_vault_init_passphrase(&mut Vec::new(), true, false, true, false, false)
                .unwrap();
        assert_eq!(resolved_yes.expose_secret(), "existing-keyring-pass-111");
        assert!(!update_yes);

        ConfirmPrompt::push_mock_input("no");
        OsKeyring::push_mock_prompt_reply("brand-new-pass-222");
        let (resolved_no, update_no) =
            resolve_vault_init_passphrase(&mut Vec::new(), true, false, true, false, false)
                .unwrap();
        assert_eq!(resolved_no.expose_secret(), "brand-new-pass-222");
        assert!(update_no);
    }

    #[test]
    fn test_rotate_vault_passphrases_preserves_other_vault_slots_and_nonmatching_default() {
        let _mock = mock_guard();
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
            OsKeyring::get_for_vault(&vcfg_a.vault_id)
                .unwrap()
                .unwrap()
                .expose_secret(),
            "vault-a-rotated-new"
        );
        assert_eq!(
            OsKeyring::get_for_vault(&vcfg_b.vault_id)
                .unwrap()
                .unwrap()
                .expose_secret(),
            "vault-b-stay-pass"
        );
        assert_eq!(
            OsKeyring::get().unwrap().unwrap().expose_secret(),
            "vault-b-stay-pass"
        );
    }

    #[test]
    fn test_handle_key_multi_vault_set_del_and_del_all() {
        use crate::cli::args::Command;
        let _mock = mock_guard();
        let tmp = tempfile::tempdir().unwrap();
        let home_dir = tmp.path().join("home");
        let dotler_cfg_dir = home_dir.join(".config").join("dotler");
        let repo_pub = home_dir.join("my-dotler");
        let repo_priv = home_dir.join("my-life-vault");
        fs::create_dir_all(&dotler_cfg_dir).unwrap();
        fs::create_dir_all(&repo_pub).unwrap();
        fs::create_dir_all(&repo_priv).unwrap();

        let pass_pub = SecretString::new("pub-secret-111".to_string());
        let pass_priv = SecretString::new("priv-secret-222".to_string());
        let (vcfg_pub, _, _) = init_vault(&pass_pub).unwrap();
        let (vcfg_priv, _, _) = init_vault(&pass_priv).unwrap();

        let write_manifest = |dir: &Path, vcfg: &VaultConfig| {
            let content = format!(
                "vault_id = \"{}\"\npassword_slot = \"{}\"\nrecovery_slot = \"{}\"\n",
                vcfg.vault_id, vcfg.password_slot, vcfg.recovery_slot
            );
            write_file_safe(&dir.join("dotler.toml"), content.as_bytes()).unwrap();
        };
        write_manifest(&repo_pub, &vcfg_pub);
        write_manifest(&repo_priv, &vcfg_priv);

        let mut local_cfg = LocalConfig {
            default_repo: Some("my-dotler".to_string()),
            ..Default::default()
        };
        local_cfg
            .repos
            .insert("my-dotler".to_string(), "~/my-dotler".to_string());
        local_cfg.repos.insert(
            "my-life-vault".to_string(),
            "~/my-life-vault".to_string(),
        );

        let orig_home = std::env::var_os("HOME");
        unsafe {
            std::env::set_var("HOME", &home_dir);
        }
        local_cfg.save_atomic(&dotler_cfg_dir.join("config.toml")).unwrap();

        let lock_res = crate::config::state::get_lock(dotler_cfg_dir.join("dotler.lock"));
        let lock_guard = lock_res.get().unwrap();

        let make_cli = |repo: Option<&str>, cmd: Command| Cli {
            json: true,
            device: None,
            repo: repo.map(str::to_string),
            dry_run: false,
            verbose: false,
            command: cmd,
        };

        // `dotler key set -r my-dotler`
        OsKeyring::push_mock_prompt_reply("pub-secret-111");
        handle_key(
            &KeyCommand::Set(crate::cli::args::KeySetArgs::default()),
            &make_cli(
                Some("my-dotler"),
                Command::Key {
                    command: KeyCommand::Set(crate::cli::args::KeySetArgs::default()),
                },
            ),
            true,
            &mut Vec::new(),
            lock_guard,
        )
        .unwrap();

        // `dotler key set -r my-life-vault`
        OsKeyring::push_mock_prompt_reply("priv-secret-222");
        handle_key(
            &KeyCommand::Set(crate::cli::args::KeySetArgs::default()),
            &make_cli(
                Some("my-life-vault"),
                Command::Key {
                    command: KeyCommand::Set(crate::cli::args::KeySetArgs::default()),
                },
            ),
            true,
            &mut Vec::new(),
            lock_guard,
        )
        .unwrap();

        assert_eq!(
            OsKeyring::get_for_vault(&vcfg_pub.vault_id)
                .unwrap()
                .unwrap()
                .expose_secret(),
            "pub-secret-111"
        );
        assert_eq!(
            OsKeyring::get_for_vault(&vcfg_priv.vault_id)
                .unwrap()
                .unwrap()
                .expose_secret(),
            "priv-secret-222"
        );

        // `dotler key ls` reports both vault_id slots and default_fallback / locked status
        let mut ls_out = Vec::new();
        handle_key(
            &KeyCommand::Ls(crate::cli::args::KeyLsArgs::default()),
            &make_cli(
                None,
                Command::Key {
                    command: KeyCommand::Ls(crate::cli::args::KeyLsArgs::default()),
                },
            ),
            true,
            &mut ls_out,
            lock_guard,
        )
        .unwrap();
        let ls_json: serde_json::Value = serde_json::from_slice(&ls_out).unwrap();
        assert_eq!(ls_json["command"], "key ls");
        assert_eq!(ls_json["data"]["default_slot_set"], true);
        let repos = ls_json["data"]["repos"].as_array().unwrap();
        assert_eq!(repos[0]["label"], "my-dotler");
        assert_eq!(repos[0]["keyring_status"], "vault_slot");
        assert_eq!(repos[1]["label"], "my-life-vault");
        assert_eq!(repos[1]["keyring_status"], "vault_slot");

        // `dotler key del -r my-dotler` deletes pub slot (and matching default) while keeping priv
        handle_key(
            &KeyCommand::Del(crate::cli::args::KeyDelArgs { all: false }),
            &make_cli(
                Some("my-dotler"),
                Command::Key {
                    command: KeyCommand::Del(crate::cli::args::KeyDelArgs { all: false }),
                },
            ),
            true,
            &mut Vec::new(),
            lock_guard,
        )
        .unwrap();
        assert!(OsKeyring::get_for_vault(&vcfg_pub.vault_id).unwrap().is_none());
        assert!(OsKeyring::get().unwrap().is_none());
        assert_eq!(
            OsKeyring::get_for_vault(&vcfg_priv.vault_id)
                .unwrap()
                .unwrap()
                .expose_secret(),
            "priv-secret-222"
        );

        // `dotler key ls` now shows my-dotler as locked and my-life-vault as vault_slot
        let mut ls_after_del = Vec::new();
        handle_key(
            &KeyCommand::Ls(crate::cli::args::KeyLsArgs::default()),
            &make_cli(
                None,
                Command::Key {
                    command: KeyCommand::Ls(crate::cli::args::KeyLsArgs::default()),
                },
            ),
            true,
            &mut ls_after_del,
            lock_guard,
        )
        .unwrap();
        let ls_after_json: serde_json::Value = serde_json::from_slice(&ls_after_del).unwrap();
        assert_eq!(ls_after_json["data"]["default_slot_set"], false);
        assert_eq!(ls_after_json["data"]["repos"][0]["keyring_status"], "locked");
        assert_eq!(ls_after_json["data"]["repos"][1]["keyring_status"], "vault_slot");

        // `dotler key del --all` clears remaining priv slot too
        OsKeyring::set(&SecretString::new("dangling-default".to_string())).unwrap();
        handle_key(
            &KeyCommand::Del(crate::cli::args::KeyDelArgs { all: true }),
            &make_cli(
                None,
                Command::Key {
                    command: KeyCommand::Del(crate::cli::args::KeyDelArgs { all: true }),
                },
            ),
            true,
            &mut Vec::new(),
            lock_guard,
        )
        .unwrap();
        assert!(OsKeyring::get_for_vault(&vcfg_priv.vault_id).unwrap().is_none());
        assert!(OsKeyring::get().unwrap().is_none());

        if let Some(h) = orig_home {
            unsafe {
                std::env::set_var("HOME", h);
            }
        }
    }

    #[test]
    fn test_handle_vault_import_rekeys_existing_enc_files_with_distinct_passphrases() {
        use crate::cli::args::Command;
        let _mock = mock_guard();
        let tmp = tempfile::tempdir().unwrap();
        let home_dir = tmp.path().join("home");
        let dotler_cfg_dir = home_dir.join(".config").join("dotler");
        let repo_src = home_dir.join("repo_src");
        let repo_dst = home_dir.join("repo_dst");
        fs::create_dir_all(&dotler_cfg_dir).unwrap();
        fs::create_dir_all(&repo_src).unwrap();
        fs::create_dir_all(repo_dst.join("sec")).unwrap();

        let pass_src = SecretString::new("src-vault-pass-999".to_string());
        let pass_dst = SecretString::new("dst-vault-pass-111".to_string());
        let (vcfg_src, vkey_src, _) = init_vault(&pass_src).unwrap();
        let (vcfg_dst, vkey_dst, _) = init_vault(&pass_dst).unwrap();

        write_file_safe(
            &repo_src.join("dotler.toml"),
            format!(
                "vault_id = \"{}\"\npassword_slot = \"{}\"\nrecovery_slot = \"{}\"\n",
                vcfg_src.vault_id, vcfg_src.password_slot, vcfg_src.recovery_slot
            )
            .as_bytes(),
        )
        .unwrap();

        write_file_safe(
            &repo_dst.join("dotler.toml"),
            format!(
                "vault_id = \"{}\"\npassword_slot = \"{}\"\nrecovery_slot = \"{}\"\n\n[sec]\nos-nux = \"~\"\nos-mac = \"~\"\nos-win = \"~\"\nfiles = \"secret.env enc\"\n",
                vcfg_dst.vault_id, vcfg_dst.password_slot, vcfg_dst.recovery_slot
            )
            .as_bytes(),
        )
        .unwrap();
        let orig_enc = vkey_dst.encrypt_file(b"API_KEY=hello_world").unwrap().to_bytes();
        write_file_safe(&repo_dst.join("sec/secret.env.enc"), &orig_enc).unwrap();

        let mut local_cfg = LocalConfig {
            default_repo: Some("dst".to_string()),
            ..Default::default()
        };
        local_cfg.repos.insert("src".to_string(), "~/repo_src".to_string());
        local_cfg.repos.insert("dst".to_string(), "~/repo_dst".to_string());

        let orig_home = std::env::var_os("HOME");
        unsafe {
            std::env::set_var("HOME", &home_dir);
        }
        local_cfg.save_atomic(&dotler_cfg_dir.join("config.toml")).unwrap();

        // Store dst passphrase in keyring under vcfg_dst.vault_id; supply src passphrase via prompt
        OsKeyring::set_for_vault(&vcfg_dst.vault_id, &pass_dst).unwrap();
        OsKeyring::push_mock_prompt_reply("src-vault-pass-999");

        let lock_res = crate::config::state::get_lock(dotler_cfg_dir.join("dotler.lock"));
        let lock_guard = lock_res.get().unwrap();

        let import_args = VaultImportArgs {
            file: Some("src".to_string()),
            ..Default::default()
        };
        let cli = Cli {
            json: true,
            device: None,
            repo: Some("dst".to_string()),
            dry_run: false,
            verbose: false,
            command: Command::Vault {
                command: VaultCommand::Import(import_args.clone()),
            },
        };
        let mut out = Vec::new();
        handle_vault(
            &VaultCommand::Import(import_args),
            &cli,
            true,
            &mut out,
            lock_guard,
        )
        .unwrap();

        let resp: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(resp["command"], "vault import");
        assert_eq!(resp["data"]["vault_id"], vcfg_src.vault_id);
        assert_eq!(resp["data"]["rekeyed_files"], 1);

        // Verify .enc file is now encrypted with vkey_src and decrypts back to original plaintext
        let rekeyed_bytes = fs::read(repo_dst.join("sec/secret.env.enc")).unwrap();
        let rekeyed_enc = EncryptedFile::from_bytes(&rekeyed_bytes).unwrap();
        assert_eq!(rekeyed_enc.vault_id, vkey_src.vault_id_bytes());
        let plain = vkey_src.decrypt_file(&rekeyed_enc).unwrap();
        assert_eq!(plain.expose_secret(), b"API_KEY=hello_world");

        let updated_dst_cfg = RepoConfig::load(&repo_dst.join("dotler.toml")).unwrap();
        assert_eq!(updated_dst_cfg.vault.unwrap().vault_id, vcfg_src.vault_id);

        if let Some(h) = orig_home {
            unsafe {
                std::env::set_var("HOME", h);
            }
        }
    }
}
