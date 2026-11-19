//! CLI handlers for `vault from <file|git|url>` external vault import and `.enc` re-keying.

use std::io::Write;

use crate::cli::args::{Cli, VaultFromCommand};
use crate::cli::output::{VaultFromReport, render_success_to};
use crate::config::local::{LocalConfig, WalkDir, expand_tilde, resolve_repo_path_with_cwd};
use crate::config::repo::{
    RepoConfig, VaultConfig, get_repo_config, update_vault_manifest_section,
};
use crate::config::state::write_file_safe;
use crate::core::vault_loader::{read_new_passphrase, unlock_vault_if_needed};
use crate::crypto::keyring::{OsKeyring, PASSPHRASE_ENV_VAR};
use crate::crypto::vault::{EncryptedFile, FullEncryptedFile, VaultKey, VaultSlot};
use crate::crypto::{ExposeSecret, SecretString};
use crate::engine::EngineError;
use crate::engine::remote::{GitRunner, REMOTE_TOML_FETCH_MAX_BYTES, fetch_http_text, parse_url};

pub(crate) fn unlock_imported_vault_slot(
    pw_slot: &VaultSlot,
    expected_vid: Option<&str>,
    vault_hint: Option<&str>,
    use_keyring: bool,
    password_stdin: bool,
    is_interactive: bool,
) -> Result<(VaultKey, SecretString, bool), EngineError> {
    if password_stdin {
        let pass = read_new_passphrase(true, false, is_interactive, "Enter vault passphrase: ")?;
        let key = pw_slot.unwrap(&pass, expected_vid)?;
        return Ok((key, pass, true));
    }

    if let Ok(env_pass) = std::env::var(PASSPHRASE_ENV_VAR) {
        let trimmed = env_pass.trim_end_matches(['\r', '\n']);
        if !trimmed.is_empty() {
            let pass = SecretString::new(trimmed.to_string());
            let key = pw_slot.unwrap(&pass, expected_vid)?;
            return Ok((key, pass, true));
        }
    }

    if use_keyring
        && let Some(vid) = expected_vid.map(str::trim).filter(|s| !s.is_empty())
        && let Ok(Some(sec)) = OsKeyring::get_for_vault(vid)
        && let Ok(key) = pw_slot.unwrap(&sec, expected_vid)
    {
        return Ok((key, sec, false));
    }

    let prompt_msg = match vault_hint.map(str::trim).filter(|s| !s.is_empty()) {
        Some(h) => format!("Enter vault passphrase (hint: {h}): "),
        None => "Enter vault passphrase: ".to_string(),
    };
    let pass = read_new_passphrase(false, false, is_interactive, &prompt_msg)?;
    let key = pw_slot.unwrap(&pass, expected_vid)?;
    Ok((key, pass, true))
}

fn fetch_external_vault_payload(
    local_cfg: &LocalConfig,
    cmd: &VaultFromCommand,
) -> Result<String, EngineError> {
    match cmd {
        VaultFromCommand::Git(args) => {
            let parsed = parse_url(&args.source)?;
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
            Ok(raw)
        }
        VaultFromCommand::Url(args) => fetch_http_text(&args.source, REMOTE_TOML_FETCH_MAX_BYTES),
        VaultFromCommand::File(args) => {
            let target_file = if let Some(registered) = local_cfg.repos.get(&args.source) {
                expand_tilde(registered).join("dotler.toml")
            } else {
                let expanded = expand_tilde(&args.source);
                if expanded.is_dir() {
                    expanded.join("dotler.toml")
                } else {
                    expanded
                }
            };
            if !target_file.exists() {
                return Err(EngineError::FileNotFound { path: target_file });
            }
            Ok(std::fs::read_to_string(&target_file)?)
        }
    }
}

pub(crate) fn handle_vault_from<W: Write>(
    cmd: &VaultFromCommand,
    local_cfg: &LocalConfig,
    cli: &Cli,
    is_interactive: bool,
    stdout: &mut W,
) -> Result<i32, EngineError> {
    let (_label, repo_path) = resolve_repo_path_with_cwd(local_cfg, cli.repo.as_deref())?;
    let manifest_path = repo_path.join("dotler.toml");
    let mut repo_cfg = RepoConfig::load_without_vault_check(&manifest_path)?;

    let raw_payload = fetch_external_vault_payload(local_cfg, cmd)?;
    let args = cmd.source_args();
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
    let (new_vault_key, pass, should_update_keyring) = unlock_imported_vault_slot(
        &pw_slot,
        expected_vid,
        ext_vault.vault_hint.as_deref(),
        local_cfg.use_keyring,
        args.password_stdin,
        is_interactive,
    )?;
    let new_vid_bytes = new_vault_key.vault_id_bytes();
    let imported_cfg = VaultConfig {
        vault_id: new_vault_key.vault_id(),
        password_slot: ext_vault.password_slot,
        recovery_slot: ext_vault.recovery_slot,
        vault_hint: explicit_hint.or(ext_vault.vault_hint),
    };

    // Scan existing .enc and .fenc files in group directories belonging to another vault.
    enum MismatchedArtifact {
        Content(std::path::PathBuf, EncryptedFile),
        Full(std::path::PathBuf, String, FullEncryptedFile),
    }
    let mut mismatched_files: Vec<MismatchedArtifact> = Vec::new();
    for g_name in repo_cfg.groups.keys() {
        let group_dir = repo_path.join(g_name);
        if !group_dir.is_dir() {
            continue;
        }
        for entry in WalkDir::new(&group_dir).into_iter().filter_map(|e| e.ok()) {
            if !entry.file_type().is_file() {
                continue;
            }
            match entry.path().extension().and_then(|s| s.to_str()) {
                Some("enc") => {
                    let bytes = std::fs::read(entry.path())?;
                    let enc_file = EncryptedFile::from_bytes(&bytes)?;
                    if enc_file.vault_id != new_vid_bytes {
                        mismatched_files.push(MismatchedArtifact::Content(
                            entry.path().to_path_buf(),
                            enc_file,
                        ));
                    }
                }
                Some("fenc") => {
                    let bytes = std::fs::read(entry.path())?;
                    let fenc_file = FullEncryptedFile::from_bytes(&bytes)?;
                    if fenc_file.vault_id != new_vid_bytes {
                        let fname = entry.file_name().to_string_lossy().to_string();
                        mismatched_files.push(MismatchedArtifact::Full(
                            entry.path().to_path_buf(),
                            fname,
                            fenc_file,
                        ));
                    }
                }
                _ => {}
            }
        }
    }

    let mut rekeyed_writes: Vec<(std::path::PathBuf, Vec<u8>, Option<std::path::PathBuf>)> =
        Vec::new();
    if !mismatched_files.is_empty() {
        let old_vcfg = repo_cfg.vault.as_ref().ok_or(EngineError::Config(
            crate::config::ConfigError::MissingVaultConfig,
        ))?;
        let old_slot = VaultSlot::from_base64(&old_vcfg.password_slot)?;
        let old_vault_key = if let Ok(key) = old_slot.unwrap(&pass, Some(&old_vcfg.vault_id)) {
            key
        } else {
            unlock_vault_if_needed(&repo_cfg, local_cfg.use_keyring, is_interactive, true)?.ok_or(
                EngineError::Config(crate::config::ConfigError::MissingVaultConfig),
            )?
        };

        for item in mismatched_files {
            match item {
                MismatchedArtifact::Content(enc_path, enc_file) => {
                    let plain = old_vault_key.decrypt_file(&enc_file)?;
                    let rekeyed = new_vault_key.encrypt_file(plain.expose_secret())?;
                    rekeyed_writes.push((enc_path, rekeyed.to_bytes(), None));
                }
                MismatchedArtifact::Full(old_path, fname, fenc_file) => {
                    let (rel_path, plain) = old_vault_key.decrypt_full_file(&fname, &fenc_file)?;
                    let (new_fname, rekeyed) =
                        new_vault_key.encrypt_full_file(&rel_path, plain.expose_secret())?;
                    let parent = old_path.parent().unwrap_or(&repo_path);
                    let new_path = parent.join(new_fname);
                    let stale = (new_path != old_path).then_some(old_path);
                    rekeyed_writes.push((new_path, rekeyed.to_bytes(), stale));
                }
            }
        }
    }

    let rekeyed_files = rekeyed_writes.len();
    let written_paths: std::collections::HashSet<std::path::PathBuf> =
        rekeyed_writes.iter().map(|(p, _, _)| p.clone()).collect();
    let mut stale_to_remove = Vec::new();
    for (dst_path, bytes, stale_opt) in rekeyed_writes {
        write_file_safe(&dst_path, &bytes)?;
        if let Some(old_path) = stale_opt
            && !written_paths.contains(&old_path)
        {
            stale_to_remove.push(old_path);
        }
    }
    for old_path in stale_to_remove {
        let _ = std::fs::remove_file(old_path);
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

    let data = VaultFromReport {
        vault_id,
        rekeyed_files,
        hint: vault_hint,
    };
    Ok(render_success_to(stdout, "vault from", &data, cli.json))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::args::{Command, VaultCommand, VaultFromSourceArgs};
    use crate::cli::vault::handle_vault;
    use crate::crypto::keyring::MockKeyringGuard;
    use crate::crypto::vault::init_vault;
    use std::fs;

    fn mock_guard<'a>() -> MockKeyringGuard<'a> {
        let g = MockKeyringGuard::new();
        unsafe {
            std::env::remove_var(PASSPHRASE_ENV_VAR);
        }
        g
    }

    #[test]
    fn test_handle_vault_from_rekeys_existing_enc_files_with_distinct_passphrases() {
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
        let orig_enc = vkey_dst
            .encrypt_file(b"API_KEY=hello_world")
            .unwrap()
            .to_bytes();
        write_file_safe(&repo_dst.join("sec/secret.env.enc"), &orig_enc).unwrap();

        let mut local_cfg = LocalConfig {
            default_repo: Some("dst".to_string()),
            ..Default::default()
        };
        local_cfg
            .repos
            .insert("src".to_string(), "~/repo_src".to_string());
        local_cfg
            .repos
            .insert("dst".to_string(), "~/repo_dst".to_string());

        let orig_home = std::env::var_os("HOME");
        unsafe {
            std::env::set_var("HOME", &home_dir);
        }
        local_cfg
            .save_atomic(&dotler_cfg_dir.join("config.toml"))
            .unwrap();

        // Store dst passphrase in both <vid_dst> and default slot; vault from checks keyring first,
        // sees dst passphrase does not unlock src, and falls straight through to prompt for src without ConfirmPrompt.
        OsKeyring::set(&pass_dst).unwrap();
        OsKeyring::set_for_vault(&vcfg_dst.vault_id, &pass_dst).unwrap();
        OsKeyring::push_mock_prompt_reply("src-vault-pass-999");

        let lock_res = crate::config::state::get_lock(dotler_cfg_dir.join("dotler.lock"));
        let lock_guard = lock_res.get().unwrap();

        let from_cmd = VaultFromCommand::File(VaultFromSourceArgs {
            source: "src".to_string(),
            ..Default::default()
        });
        let cli = Cli {
            json: true,
            device: None,
            repo: Some("dst".to_string()),
            dry_run: false,
            verbose: false,
            command: Command::Vault {
                command: VaultCommand::From {
                    command: from_cmd.clone(),
                },
            },
        };
        let mut out = Vec::new();
        handle_vault(
            &VaultCommand::From { command: from_cmd },
            &cli,
            true,
            &mut out,
            lock_guard,
        )
        .unwrap();

        let resp: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(resp["command"], "vault from");
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
        assert_eq!(
            OsKeyring::get_for_vault(&vcfg_src.vault_id)
                .unwrap()
                .unwrap()
                .expose_secret(),
            "src-vault-pass-999"
        );

        if let Some(h) = orig_home {
            unsafe {
                std::env::set_var("HOME", h);
            }
        }
    }

    #[test]
    fn test_vault_from_auto_verifies_os_keyring_without_confirm_prompt() {
        let _mock = mock_guard();
        let tmp = tempfile::tempdir().unwrap();
        let home_dir = tmp.path().join("home");
        let dotler_cfg_dir = home_dir.join(".config").join("dotler");
        let repo_src = home_dir.join("repo_src");
        let repo_dst = home_dir.join("repo_dst");
        fs::create_dir_all(&dotler_cfg_dir).unwrap();
        fs::create_dir_all(&repo_src).unwrap();
        fs::create_dir_all(&repo_dst).unwrap();

        let pass_src = SecretString::new("src-keyring-auto-777".to_string());
        let (vcfg_src, _, _) = init_vault(&pass_src).unwrap();

        write_file_safe(
            &repo_src.join("dotler.toml"),
            format!(
                "vault_id = \"{}\"\npassword_slot = \"{}\"\nrecovery_slot = \"{}\"\n",
                vcfg_src.vault_id, vcfg_src.password_slot, vcfg_src.recovery_slot
            )
            .as_bytes(),
        )
        .unwrap();
        write_file_safe(&repo_dst.join("dotler.toml"), b"").unwrap();

        let mut local_cfg = LocalConfig {
            default_repo: Some("dst".to_string()),
            ..Default::default()
        };
        local_cfg
            .repos
            .insert("src".to_string(), "~/repo_src".to_string());
        local_cfg
            .repos
            .insert("dst".to_string(), "~/repo_dst".to_string());

        let orig_home = std::env::var_os("HOME");
        unsafe {
            std::env::set_var("HOME", &home_dir);
        }
        local_cfg
            .save_atomic(&dotler_cfg_dir.join("config.toml"))
            .unwrap();

        let lock_res = crate::config::state::get_lock(dotler_cfg_dir.join("dotler.lock"));
        let lock_guard = lock_res.get().unwrap();

        let from_cmd = VaultFromCommand::File(VaultFromSourceArgs {
            source: "src".to_string(),
            ..Default::default()
        });
        let cli_interactive = Cli {
            json: false,
            device: None,
            repo: Some("dst".to_string()),
            dry_run: false,
            verbose: false,
            command: Command::Vault {
                command: VaultCommand::From {
                    command: from_cmd.clone(),
                },
            },
        };

        // 1. Matching <vault_id> slot unlocks immediately in interactive mode with zero prompts
        OsKeyring::set_for_vault(&vcfg_src.vault_id, &pass_src).unwrap();
        let mut out1 = Vec::new();
        handle_vault(
            &VaultCommand::From {
                command: from_cmd.clone(),
            },
            &cli_interactive,
            true,
            &mut out1,
            lock_guard,
        )
        .unwrap();
        assert!(String::from_utf8_lossy(&out1).contains(&vcfg_src.vault_id));

        // 2. When <vault_id> is NOT registered in OS keyring (even if `default` has a passphrase),
        //    `vault from` prompts at the boundary and registers <vault_id> into OS keyring.
        OsKeyring::clear_mock();
        write_file_safe(&repo_dst.join("dotler.toml"), b"").unwrap();
        OsKeyring::set(&pass_src).unwrap();
        OsKeyring::push_mock_prompt_reply("src-keyring-auto-777");
        let mut out2 = Vec::new();
        handle_vault(
            &VaultCommand::From {
                command: from_cmd.clone(),
            },
            &cli_interactive,
            true,
            &mut out2,
            lock_guard,
        )
        .unwrap();
        assert!(OsKeyring::take_mock_prompt_reply().is_none());
        assert_eq!(
            OsKeyring::get_for_vault(&vcfg_src.vault_id)
                .unwrap()
                .unwrap()
                .expose_secret(),
            "src-keyring-auto-777"
        );

        // 3. Mismatched keyring entries fall through cleanly to passphrase prompt (zero ConfirmPrompt)
        OsKeyring::clear_mock();
        write_file_safe(&repo_dst.join("dotler.toml"), b"").unwrap();
        OsKeyring::set(&SecretString::new("other-vault-pass-000".to_string())).unwrap();
        OsKeyring::set_for_vault(
            &vcfg_src.vault_id,
            &SecretString::new("stale-wrong-pass-000".to_string()),
        )
        .unwrap();
        OsKeyring::push_mock_prompt_reply("src-keyring-auto-777");
        let mut out3 = Vec::new();
        handle_vault(
            &VaultCommand::From { command: from_cmd },
            &cli_interactive,
            true,
            &mut out3,
            lock_guard,
        )
        .unwrap();
        assert_eq!(
            OsKeyring::get_for_vault(&vcfg_src.vault_id)
                .unwrap()
                .unwrap()
                .expose_secret(),
            "src-keyring-auto-777"
        );

        if let Some(h) = orig_home {
            unsafe {
                std::env::set_var("HOME", h);
            }
        }
    }
}
