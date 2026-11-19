//! CLI handlers for `vault` (`init`, `ls`, `from`, `rotate`, `recover`) commands.

use std::io::Write;

use crate::cli::args::{Cli, VaultCommand, VaultInitArgs};
use crate::cli::output::{
    VaultInitReport, VaultLsReport, VaultRecoverReport, VaultRepoStatusEntry, render_success_to,
};
use crate::cli::vault_from::{handle_vault_from, unlock_imported_vault_slot};
use crate::config::local::{
    LOCAL_CONFIG_FILE, LocalConfig, expand_tilde, get_local_config, resolve_repo_path_with_cwd,
};
use crate::config::repo::{RepoConfig, VaultConfig, get_repo_config};
use crate::config::state::DotlerLockGuard;
use crate::core::vault_loader::{read_new_passphrase, rotate_vault_passphrases};
use crate::crypto::SecretString;
use crate::crypto::keyring::{OsKeyring, PASSPHRASE_ENV_VAR};
use crate::crypto::vault::{VaultSlot, init_vault, recover_vault};
use crate::engine::EngineError;
use crate::tui::confirm::{ConfirmError, ConfirmPrompt, confirm_proceed_to};

pub(crate) fn resolve_vault_init_passphrase<W: Write>(
    writer: &mut W,
    use_keyring: bool,
    password_stdin: bool,
    is_interactive: bool,
    json_mode: bool,
) -> Result<(SecretString, bool), EngineError> {
    let has_env_pass = std::env::var(PASSPHRASE_ENV_VAR)
        .is_ok_and(|v| !v.trim_end_matches(['\r', '\n']).is_empty());

    let existing_keyring = if !password_stdin && !has_env_pass && use_keyring {
        OsKeyring::get().ok().flatten()
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

    let pass = read_new_passphrase(
        password_stdin,
        true,
        is_interactive,
        "Enter new vault passphrase: ",
    )?;
    Ok((pass, true))
}

pub(crate) fn ensure_repo_vault_in_keyring(
    vault_cfg: &VaultConfig,
    use_keyring: bool,
    password_stdin: bool,
    is_interactive: bool,
) -> Result<(), EngineError> {
    let pw_slot = VaultSlot::from_base64(&vault_cfg.password_slot)?;
    let expected_vid =
        (!vault_cfg.vault_id.trim().is_empty()).then_some(vault_cfg.vault_id.as_str());
    let (_key, pass, should_update_keyring) = unlock_imported_vault_slot(
        &pw_slot,
        expected_vid,
        vault_cfg.vault_hint.as_deref(),
        use_keyring,
        password_stdin,
        is_interactive,
    )?;
    if use_keyring
        && let Some(vid) = expected_vid
        && (should_update_keyring || OsKeyring::get_for_vault(vid).ok().flatten().is_none())
    {
        let _ = OsKeyring::set_with_fallback(Some(vid), &pass);
    }
    Ok(())
}

pub(crate) fn handle_vault<W: Write>(
    cmd: &VaultCommand,
    cli: &Cli,
    is_interactive: bool,
    stdout: &mut W,
    _lock: &DotlerLockGuard,
) -> Result<i32, EngineError> {
    let local_cfg_res = get_local_config(expand_tilde(LOCAL_CONFIG_FILE));
    if let VaultCommand::Ls(_) = cmd {
        let local_cfg = match local_cfg_res.get() {
            Ok(cfg) => cfg.clone(),
            Err(e) if cli.repo.is_some() => return Err(EngineError::Config(e)),
            Err(_) => LocalConfig::default(),
        };
        return handle_vault_ls(&local_cfg, cli, stdout);
    }
    let local_cfg = local_cfg_res.get()?;

    match cmd {
        VaultCommand::Init(args) => handle_vault_init(args, local_cfg, cli, is_interactive, stdout),
        VaultCommand::Ls(_) => unreachable!(),
        VaultCommand::From { command } => {
            handle_vault_from(command, local_cfg, cli, is_interactive, stdout)
        }
        VaultCommand::Rotate(args) => {
            let data = rotate_vault_passphrases(
                local_cfg,
                cli.repo.as_deref(),
                args.password_stdin,
                args.hint.as_deref(),
                is_interactive,
            )?;
            Ok(render_success_to(stdout, "vault rotate", &data, cli.json))
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

    if let Some(ref existing_vault) = repo_cfg.vault {
        let has_env_pass = std::env::var(PASSPHRASE_ENV_VAR)
            .is_ok_and(|v| !v.trim_end_matches(['\r', '\n']).is_empty());
        let needs_keyring = local_cfg.use_keyring
            && !existing_vault.vault_id.trim().is_empty()
            && !OsKeyring::get_for_vault(&existing_vault.vault_id)
                .ok()
                .flatten()
                .is_some_and(|sec| {
                    VaultSlot::from_base64(&existing_vault.password_slot)
                        .ok()
                        .is_some_and(|slot| {
                            slot.unwrap(&sec, Some(&existing_vault.vault_id)).is_ok()
                        })
                });
        if args.password_stdin || has_env_pass || needs_keyring {
            ensure_repo_vault_in_keyring(
                existing_vault,
                local_cfg.use_keyring,
                args.password_stdin,
                is_interactive,
            )?;
            let data = VaultInitReport {
                vault_id: existing_vault.vault_id.clone(),
                mnemonic: None,
                hint: existing_vault.vault_hint.clone(),
            };
            return Ok(render_success_to(stdout, "vault init", &data, cli.json));
        }

        return Err(EngineError::Config(crate::config::ConfigError::UnknownField {
            field: "vault".to_string(),
            hint: "Vault is already initialized in dotler.toml. Use 'dotler vault rotate' to change password or 'dotler vault from <file|git|url>' to replace with another vault."
                .to_string(),
        }));
    }

    let explicit_hint = args
        .hint
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    let (pass, should_update_keyring) = resolve_vault_init_passphrase(
        stdout,
        local_cfg.use_keyring,
        args.password_stdin,
        is_interactive,
        cli.json,
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

fn handle_vault_ls<W: Write>(
    local_cfg: &LocalConfig,
    cli: &Cli,
    stdout: &mut W,
) -> Result<i32, EngineError> {
    let candidates = local_cfg.candidate_repos_with_cwd();

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
            entries.push(VaultRepoStatusEntry {
                label,
                path: path_str,
                vault_id: None,
                vault_hint: None,
                keyring_status: "missing_repo".to_string(),
            });
            continue;
        }
        let Ok(repo_cfg) = RepoConfig::load_without_vault_check(&manifest_path) else {
            entries.push(VaultRepoStatusEntry {
                label,
                path: path_str,
                vault_id: None,
                vault_hint: None,
                keyring_status: "missing_repo".to_string(),
            });
            continue;
        };
        let Some(vcfg) = repo_cfg.vault else {
            entries.push(VaultRepoStatusEntry {
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

        entries.push(VaultRepoStatusEntry {
            label,
            path: path_str,
            vault_id: Some(vcfg.vault_id),
            vault_hint: vcfg.vault_hint,
            keyring_status: status,
        });
    }

    let report = VaultLsReport {
        use_keyring: local_cfg.use_keyring,
        default_slot_set: default_secret.is_some(),
        repos: entries,
    };
    Ok(render_success_to(stdout, "vault ls", &report, cli.json))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::args::{Command, VaultLsArgs};
    use crate::config::state::write_file_safe;
    use crate::crypto::ExposeSecret;
    use crate::crypto::keyring::MockKeyringGuard;
    use std::fs;
    use std::path::Path;

    fn mock_guard<'a>() -> MockKeyringGuard<'a> {
        let g = MockKeyringGuard::new();
        unsafe {
            std::env::remove_var(crate::crypto::keyring::PASSPHRASE_ENV_VAR);
        }
        g
    }

    #[test]
    fn test_resolve_vault_init_passphrase_prompts_to_reuse_existing_keyring() {
        let _mock = mock_guard();
        OsKeyring::set(&SecretString::new("existing-keyring-pass-111".to_string())).unwrap();

        ConfirmPrompt::push_mock_input("yes");
        let (resolved_yes, update_yes) =
            resolve_vault_init_passphrase(&mut Vec::new(), true, false, true, false).unwrap();
        assert_eq!(resolved_yes.expose_secret(), "existing-keyring-pass-111");
        assert!(!update_yes);

        ConfirmPrompt::push_mock_input("no");
        OsKeyring::push_mock_prompt_reply("brand-new-pass-222");
        let (resolved_no, update_no) =
            resolve_vault_init_passphrase(&mut Vec::new(), true, false, true, false).unwrap();
        assert_eq!(resolved_no.expose_secret(), "brand-new-pass-222");
        assert!(update_no);
    }

    #[test]
    fn test_handle_vault_ls_and_existing_vault_init_keyring_registration() {
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
        local_cfg
            .repos
            .insert("my-life-vault".to_string(), "~/my-life-vault".to_string());

        let orig_home = std::env::var_os("HOME");
        unsafe {
            std::env::set_var("HOME", &home_dir);
        }
        local_cfg
            .save_atomic(&dotler_cfg_dir.join("config.toml"))
            .unwrap();

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

        // `dotler vault init -r my-dotler` on an already-initialized repo whose <vault_id> is not in keyring
        // verifies password_slot and registers <vault_id> in OS keyring.
        OsKeyring::push_mock_prompt_reply("pub-secret-111");
        handle_vault(
            &VaultCommand::Init(VaultInitArgs::default()),
            &make_cli(
                Some("my-dotler"),
                Command::Vault {
                    command: VaultCommand::Init(VaultInitArgs::default()),
                },
            ),
            true,
            &mut Vec::new(),
            lock_guard,
        )
        .unwrap();

        // Calling `dotler vault init -r my-dotler` again when <vault_id> is already unlocked returns an error.
        assert!(
            handle_vault(
                &VaultCommand::Init(VaultInitArgs::default()),
                &make_cli(
                    Some("my-dotler"),
                    Command::Vault {
                        command: VaultCommand::Init(VaultInitArgs::default()),
                    },
                ),
                true,
                &mut Vec::new(),
                lock_guard,
            )
            .is_err()
        );

        // `dotler vault init -r my-life-vault` registers priv slot
        OsKeyring::push_mock_prompt_reply("priv-secret-222");
        handle_vault(
            &VaultCommand::Init(VaultInitArgs::default()),
            &make_cli(
                Some("my-life-vault"),
                Command::Vault {
                    command: VaultCommand::Init(VaultInitArgs::default()),
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

        // `dotler vault ls` reports both vault_id slots and default_slot_set status
        let mut ls_out = Vec::new();
        handle_vault(
            &VaultCommand::Ls(VaultLsArgs::default()),
            &make_cli(
                None,
                Command::Vault {
                    command: VaultCommand::Ls(VaultLsArgs::default()),
                },
            ),
            true,
            &mut ls_out,
            lock_guard,
        )
        .unwrap();
        let ls_json: serde_json::Value = serde_json::from_slice(&ls_out).unwrap();
        assert_eq!(ls_json["command"], "vault ls");
        assert_eq!(ls_json["data"]["default_slot_set"], true);
        let repos = ls_json["data"]["repos"].as_array().unwrap();
        assert_eq!(repos[0]["label"], "my-dotler");
        assert_eq!(repos[0]["keyring_status"], "vault_slot");
        assert_eq!(repos[1]["label"], "my-life-vault");
        assert_eq!(repos[1]["keyring_status"], "vault_slot");

        if let Some(h) = orig_home {
            unsafe {
                std::env::set_var("HOME", h);
            }
        }
    }
}
