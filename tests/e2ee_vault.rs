use std::sync::Mutex;
use std::thread;

use dotler::crypto::{
    EncryptedFile, KeyringError, OsKeyring, PassphraseSource, VaultError, VaultKey, VaultSlot,
    change_password, init_vault, recover_vault,
};
use dotler::crypto::{ExposeSecret, SecretString};

static TEST_LOCK: Mutex<()> = Mutex::new(());

struct TestKeyringGuard<'a> {
    _lock: std::sync::MutexGuard<'a, ()>,
}

impl<'a> TestKeyringGuard<'a> {
    fn new() -> Self {
        let lock = TEST_LOCK.lock().unwrap();
        OsKeyring::enable_mock();
        OsKeyring::clear_mock();
        Self { _lock: lock }
    }
}

impl<'a> Drop for TestKeyringGuard<'a> {
    fn drop(&mut self) {
        OsKeyring::clear_mock();
        OsKeyring::disable_mock();
    }
}

#[test]
fn test_vault_rotate_preserves_ciphertext_without_reencryption() {
    let initial_pass = SecretString::new("initial-vault-password".to_string());
    let (config, vault_key, _mnemonic) = init_vault(&initial_pass).unwrap();

    let plaintext = b"SECRET_API_KEY=live_secure_credentials_42";
    let encrypted_file = vault_key.encrypt_file(plaintext).unwrap();
    let original_enc_bytes = encrypted_file.to_bytes();

    // Change password
    let new_pass = SecretString::new("new-rotated-vault-password".to_string());
    let updated_config = change_password(&config, &initial_pass, &new_pass).unwrap();

    // Verify vault_id is invariant
    assert_eq!(updated_config.vault_id, config.vault_id);
    assert_ne!(updated_config.password_slot, config.password_slot);
    assert_eq!(updated_config.recovery_slot, config.recovery_slot);

    // Old password must fail to unlock
    let old_slot = VaultSlot::from_base64(&updated_config.password_slot).unwrap();
    assert!(matches!(
        old_slot.unwrap(&initial_pass, Some(&updated_config.vault_id)),
        Err(VaultError::InvalidSecret)
    ));

    // New password unlocks the exact same VaultKey
    let new_vault_key = old_slot
        .unwrap(&new_pass, Some(&updated_config.vault_id))
        .unwrap();
    assert_eq!(new_vault_key.expose(), vault_key.expose());

    // The original encrypted file decrypts successfully with new_vault_key
    // without any modification to the ciphertext bytes!
    let parsed_enc = EncryptedFile::from_bytes(&original_enc_bytes).unwrap();
    let decrypted = new_vault_key.decrypt_file(&parsed_enc).unwrap();
    assert_eq!(decrypted.expose_secret().as_slice(), plaintext);
}

#[test]
fn test_vault_recover_lifecycle_and_single_use_mnemonic_revocation() {
    let initial_pass = SecretString::new("forgotten-password".to_string());
    let (config, vault_key, mnemonic_v1) = init_vault(&initial_pass).unwrap();

    let plaintext = b"DATABASE_URL=postgres://admin:secret@localhost:5432/app";
    let enc_file = vault_key.encrypt_file(plaintext).unwrap();
    let enc_bytes = enc_file.to_bytes();

    // Recover using mnemonic_v1 and set new password
    let recovered_pass = SecretString::new("brand-new-recovered-password".to_string());
    let (recovered_config, mnemonic_v2) =
        recover_vault(&config, &mnemonic_v1.0, &recovered_pass).unwrap();

    assert_eq!(recovered_config.vault_id, config.vault_id);
    assert_ne!(mnemonic_v1.phrase(), mnemonic_v2.phrase());
    assert_ne!(recovered_config.password_slot, config.password_slot);
    assert_ne!(recovered_config.recovery_slot, config.recovery_slot);

    // Single-use auto-revocation: mnemonic_v1 must fail immediately
    let second_recover_attempt = recover_vault(
        &recovered_config,
        &mnemonic_v1.0,
        &SecretString::new("pw3".to_string()),
    );
    assert!(matches!(
        second_recover_attempt,
        Err(VaultError::InvalidSecret)
    ));

    // Mnemonic v2 unlocks the vault
    let third_pass = SecretString::new("third-pass-after-recovery".to_string());
    let (config_v3, mnemonic_v3) =
        recover_vault(&recovered_config, &mnemonic_v2.0, &third_pass).unwrap();
    assert_eq!(config_v3.vault_id, config.vault_id);
    assert_ne!(mnemonic_v2.phrase(), mnemonic_v3.phrase());

    // Existing encrypted files remain decryptable without re-encryption
    let rec_slot = VaultSlot::from_base64(&config_v3.password_slot).unwrap();
    let recovered_key = rec_slot
        .unwrap(&third_pass, Some(&config_v3.vault_id))
        .unwrap();
    let parsed_enc = EncryptedFile::from_bytes(&enc_bytes).unwrap();
    let decrypted = recovered_key.decrypt_file(&parsed_enc).unwrap();
    assert_eq!(decrypted.expose_secret().as_slice(), plaintext);
}

#[test]
fn test_keyring_standalone_set_get_delete_without_repo() {
    let _guard = TestKeyringGuard::new();

    // Verify initial empty state
    assert!(OsKeyring::get().unwrap().is_none());

    // Key set
    let secret = SecretString::new("system-wide-default-passphrase".to_string());
    OsKeyring::set(&secret).unwrap();

    let fetched = OsKeyring::get().unwrap().expect("credential should exist");
    assert_eq!(fetched.expose_secret(), "system-wide-default-passphrase");

    // Key del
    OsKeyring::delete().unwrap();
    assert!(OsKeyring::get().unwrap().is_none());

    // Deleting again is idempotent
    assert!(OsKeyring::delete().is_ok());
}

#[test]
fn test_cross_vault_in_memory_rekeying() {
    // Vault A (remote repo vault)
    let pass_a = SecretString::new("remote-vault-pass".to_string());
    let (config_a, key_a, _) = init_vault(&pass_a).unwrap();

    // Vault B (local repo vault)
    let pass_b = SecretString::new("local-vault-pass".to_string());
    let (config_b, key_b, _) = init_vault(&pass_b).unwrap();

    assert_ne!(config_a.vault_id, config_b.vault_id);

    // Encrypt file under Vault A
    let secret_dotfile = b"export GITHUB_TOKEN=\"ghp_randomsecret1234567890\"";
    let file_a = key_a.encrypt_file(secret_dotfile).unwrap();

    assert_eq!(file_a.vault_id, key_a.vault_id_bytes());

    // Decryption of Vault A file with Key B must fail with VaultIdMismatch
    assert!(matches!(
        key_b.decrypt_file(&file_a),
        Err(VaultError::VaultIdMismatch { .. })
    ));

    // Perform in-memory re-keying:
    // Decrypt with Key A -> Re-encrypt with Key B directly in memory
    let decrypted_in_memory = key_a.decrypt_file(&file_a).unwrap();
    let file_b = key_b
        .encrypt_file(decrypted_in_memory.expose_secret())
        .unwrap();

    // File B now belongs to Vault B
    assert_eq!(file_b.vault_id, key_b.vault_id_bytes());

    // Key B decrypts successfully
    let decrypted_by_b = key_b.decrypt_file(&file_b).unwrap();
    assert_eq!(decrypted_by_b.expose_secret().as_slice(), secret_dotfile);
}

#[test]
fn test_tampered_encrypted_file_protection() {
    let key = VaultKey::generate().unwrap();
    let plaintext = b"PROTECTED_DATA";
    let mut enc = key.encrypt_file(plaintext).unwrap();

    // Tampering 1 byte in MAC tag
    let last_idx = enc.ciphertext.len() - 1;
    enc.ciphertext[last_idx] ^= 0x55;

    let res = key.decrypt_file(&enc);
    assert!(matches!(res, Err(VaultError::DecryptionFailed(_))));
    if let Err(e) = res {
        assert_eq!(e.exit_code(), 4);
    }
}

#[test]
fn test_passphrase_supply_cascade_precedence() {
    let _guard = TestKeyringGuard::new();

    // When Keyring has a password, it beats stdin and env var
    let pw_keyring = SecretString::new("keyring-pass".to_string());
    OsKeyring::set(&pw_keyring).unwrap();

    let resolved = OsKeyring::resolve(false, Some("stdin-pass")).unwrap();
    assert_eq!(resolved.source, PassphraseSource::OsKeyring);
    assert_eq!(resolved.secret.expose_secret(), "keyring-pass");

    // Clear keyring
    OsKeyring::clear_mock();

    // Stdin pipe beats environment variable
    unsafe {
        std::env::set_var("DOTLER_PASSPHRASE", "env-pass");
    }
    let resolved = OsKeyring::resolve(false, Some("stdin-pass")).unwrap();
    assert_eq!(resolved.source, PassphraseSource::StdinPipe);
    assert_eq!(resolved.secret.expose_secret(), "stdin-pass");

    // Without stdin, environment variable is used
    let resolved = OsKeyring::resolve(false, None).unwrap();
    assert_eq!(resolved.source, PassphraseSource::EnvVar);
    assert_eq!(resolved.secret.expose_secret(), "env-pass");

    unsafe {
        std::env::remove_var("DOTLER_PASSPHRASE");
    }

    // Without any source, non-interactive mode returns error
    let res = OsKeyring::resolve(false, None);
    assert!(matches!(
        res,
        Err(KeyringError::PassphraseRequiredInNonInteractiveMode)
    ));
    if let Err(e) = res {
        assert_eq!(e.exit_code(), 4);
    }
}

#[test]
fn test_mock_keyring_multithreaded_concurrency() {
    let _guard = TestKeyringGuard::new();

    let initial = SecretString::new("concurrent-base-pass".to_string());
    OsKeyring::set(&initial).unwrap();

    let handles: Vec<_> = (0..8)
        .map(|i| {
            thread::spawn(move || {
                for _ in 0..100 {
                    let pw = OsKeyring::get().unwrap();
                    assert!(pw.is_some());
                    if i % 2 == 0 {
                        let updated = SecretString::new(format!("pass-worker-{}", i));
                        OsKeyring::set(&updated).unwrap();
                    }
                }
            })
        })
        .collect();

    for h in handles {
        h.join().unwrap();
    }

    assert!(OsKeyring::get().unwrap().is_some());
}

#[test]
fn test_external_vault_payload_toml_and_json_fallback_parsing() {
    use dotler::config::VaultConfig;

    let pass = SecretString::new("shared-vault-passphrase-42".to_string());
    let (orig_cfg, orig_key, _mnemonic) = init_vault(&pass).unwrap();

    // 1. Full dotler.toml with [group] sections must ignore groups and extract vault keys
    let full_toml = format!(
        r#"vault_id = "{}"
password_slot = "{}"
recovery_slot = "{}"
vault_hint = "work-laptop"

[shell]
os-nux = "~"
files = ".zshrc"
"#,
        orig_cfg.vault_id, orig_cfg.password_slot, orig_cfg.recovery_slot
    );
    let parsed_toml = VaultConfig::parse_external_payload(&full_toml).unwrap();
    assert_eq!(parsed_toml.vault_id, orig_cfg.vault_id);
    assert_eq!(parsed_toml.password_slot, orig_cfg.password_slot);
    assert_eq!(parsed_toml.recovery_slot, orig_cfg.recovery_slot);
    assert_eq!(parsed_toml.vault_hint.as_deref(), Some("work-laptop"));

    // 2. JSON fallback without vault_id (derived on unwrap) and with extra unrelated fields
    let json_payload = serde_json::json!({
        "password_slot": orig_cfg.password_slot,
        "recovery_slot": orig_cfg.recovery_slot,
        "vault_hint": "json-endpoint",
        "extra_group": { "os-nux": "~" }
    })
    .to_string();
    let parsed_json = VaultConfig::parse_external_payload(&json_payload).unwrap();
    assert_eq!(parsed_json.vault_id, "");
    assert_eq!(parsed_json.password_slot, orig_cfg.password_slot);
    assert_eq!(parsed_json.recovery_slot, orig_cfg.recovery_slot);
    assert_eq!(parsed_json.vault_hint.as_deref(), Some("json-endpoint"));

    let slot = VaultSlot::from_base64(&parsed_json.password_slot).unwrap();
    let unwrapped_key = slot.unwrap(&pass, None).unwrap();
    assert_eq!(unwrapped_key.vault_id(), orig_key.vault_id());
}

#[test]
fn test_e2e_vault_init_import_from_git_url_and_local_sources() {
    use std::fs;
    use std::process::{Command, Stdio};

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let home_dir = root.join("home");
    let dotler_dir = home_dir.join(".config").join("dotler");
    let repo_origin = home_dir.join("repo_origin");
    let repo_from_label = home_dir.join("repo_from_label");
    let repo_from_url = home_dir.join("repo_from_url");
    let repo_from_git = home_dir.join("repo_from_git");
    fs::create_dir_all(&dotler_dir).unwrap();

    let run_dotler = |cwd: &std::path::Path, args: &[&str], pass: Option<&str>| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_dotler"));
        cmd.env("HOME", &home_dir)
            .env("DOTLER_MOCK_KEYRING", "1")
            .current_dir(cwd)
            .stdin(Stdio::null())
            .args(args);
        if let Some(p) = pass {
            cmd.env("DOTLER_PASSPHRASE", p);
        } else {
            cmd.env_remove("DOTLER_PASSPHRASE");
        }
        cmd.output().unwrap()
    };

    // 1. Initialize origin repo and create a new vault
    fs::create_dir_all(&repo_origin).unwrap();
    assert_eq!(
        run_dotler(&repo_origin, &["init", "--label", "origin", "--json"], None)
            .status
            .code(),
        Some(0)
    );
    let init_out = run_dotler(
        &repo_origin,
        &["vault", "init", "--hint", "shared-hint", "--json"],
        Some("master-shared-pass-777"),
    );
    assert_eq!(init_out.status.code(), Some(0));
    let init_json: serde_json::Value =
        serde_json::from_slice(&init_out.stdout).expect("valid JSON");
    let origin_vault_id = init_json["data"]["vault_id"].as_str().unwrap().to_string();
    assert!(
        init_json["data"]["mnemonic"].is_string(),
        "New vault init must include recovery mnemonic"
    );

    // 2. Import vault into second repo via `vault from file origin` (registered repo label)
    fs::create_dir_all(&repo_from_label).unwrap();
    assert_eq!(
        run_dotler(
            &repo_from_label,
            &["init", "--label", "second", "--json"],
            None
        )
        .status
        .code(),
        Some(0)
    );
    let from_out = run_dotler(
        &repo_from_label,
        &["vault", "from", "file", "origin", "--json"],
        Some("master-shared-pass-777"),
    );
    assert_eq!(from_out.status.code(), Some(0));
    let from_json: serde_json::Value = serde_json::from_slice(&from_out.stdout).unwrap();
    assert_eq!(from_json["data"]["vault_id"], origin_vault_id);
    assert!(
        from_json["data"].get("mnemonic").is_none(),
        "Imported vault must omit recovery mnemonic"
    );
    assert_eq!(from_json["data"]["rekeyed_files"], 0);
    assert_eq!(from_json["data"]["hint"], "shared-hint");

    // Wrong passphrase must fail with exit code 4
    let repo_wrong = home_dir.join("repo_wrong");
    fs::create_dir_all(&repo_wrong).unwrap();
    run_dotler(&repo_wrong, &["init", "--label", "wrong", "--json"], None);
    let wrong_out = run_dotler(
        &repo_wrong,
        &["vault", "from", "file", "origin", "--json"],
        Some("wrong-passphrase"),
    );
    assert_eq!(wrong_out.status.code(), Some(4));

    // 3. Import vault via `vault from url` pointing to a JSON endpoint (testing JSON fallback)
    let origin_cfg = dotler::config::RepoConfig::load(&repo_origin.join("dotler.toml")).unwrap();
    let origin_v = origin_cfg.vault.unwrap();
    let json_file = root.join("vault_endpoint.json");
    fs::write(
        &json_file,
        serde_json::json!({
            "password_slot": origin_v.password_slot,
            "recovery_slot": origin_v.recovery_slot,
            "vault_hint": "from-json-url"
        })
        .to_string(),
    )
    .unwrap();

    fs::create_dir_all(&repo_from_url).unwrap();
    run_dotler(
        &repo_from_url,
        &["init", "--label", "third", "--json"],
        None,
    );
    let file_url = format!("file://{}", json_file.display());
    let url_out = run_dotler(
        &repo_from_url,
        &["vault", "from", "url", &file_url, "--json"],
        Some("master-shared-pass-777"),
    );
    assert_eq!(url_out.status.code(), Some(0));
    let url_json: serde_json::Value = serde_json::from_slice(&url_out.stdout).unwrap();
    assert_eq!(url_json["data"]["vault_id"], origin_vault_id);
    assert_eq!(url_json["data"]["hint"], "from-json-url");

    // 4. Import vault via `vault from git` from a bare Git repository
    let bare_git = root.join("origin_bare.git");
    Command::new("git")
        .args(["init", repo_origin.to_str().unwrap()])
        .status()
        .unwrap();
    Command::new("git")
        .args([
            "-C",
            repo_origin.to_str().unwrap(),
            "config",
            "user.name",
            "T",
        ])
        .status()
        .unwrap();
    Command::new("git")
        .args([
            "-C",
            repo_origin.to_str().unwrap(),
            "config",
            "user.email",
            "t@e.com",
        ])
        .status()
        .unwrap();
    Command::new("git")
        .args(["-C", repo_origin.to_str().unwrap(), "add", "dotler.toml"])
        .status()
        .unwrap();
    Command::new("git")
        .args(["-C", repo_origin.to_str().unwrap(), "commit", "-m", "init"])
        .status()
        .unwrap();
    Command::new("git")
        .args([
            "clone",
            "--bare",
            repo_origin.to_str().unwrap(),
            bare_git.to_str().unwrap(),
        ])
        .status()
        .unwrap();

    fs::create_dir_all(&repo_from_git).unwrap();
    run_dotler(
        &repo_from_git,
        &["init", "--label", "fourth", "--json"],
        None,
    );
    let git_url = format!("file://{}", bare_git.display());
    let git_out = run_dotler(
        &repo_from_git,
        &["vault", "from", "git", &git_url, "--json"],
        Some("master-shared-pass-777"),
    );
    assert_eq!(git_out.status.code(), Some(0));
    let git_json: serde_json::Value = serde_json::from_slice(&git_out.stdout).unwrap();
    assert_eq!(git_json["data"]["vault_id"], origin_vault_id);

    // 5. Importing onto an ALREADY-initialized repo with .enc files automatically re-keys them
    let repo_existing = home_dir.join("repo_existing");
    fs::create_dir_all(repo_existing.join("sec")).unwrap();
    assert_eq!(
        run_dotler(
            &repo_existing,
            &["init", "--label", "existing", "--json"],
            None
        )
        .status
        .code(),
        Some(0)
    );
    fs::write(
        repo_existing.join("dotler.toml"),
        "[sec]\nos-nux = \"~\"\nos-mac = \"~\"\nos-win = \"~\"\nfiles = \"secret.txt enc\"\n",
    )
    .unwrap();
    assert_eq!(
        run_dotler(
            &repo_existing,
            &["vault", "init", "--json"],
            Some("existing-old-pass-123"),
        )
        .status
        .code(),
        Some(0)
    );
    let existing_cfg_before =
        dotler::config::RepoConfig::load(&repo_existing.join("dotler.toml")).unwrap();
    let old_vault_id = existing_cfg_before.vault.as_ref().unwrap().vault_id.clone();
    assert_ne!(old_vault_id, origin_vault_id);

    let os_secret = home_dir.join("secret.txt");
    fs::write(&os_secret, b"REKEY_ME_ON_VAULT_IMPORT\n").unwrap();
    assert_eq!(
        run_dotler(
            &repo_existing,
            &["import", "-y", "--json"],
            Some("existing-old-pass-123"),
        )
        .status
        .code(),
        Some(0)
    );

    // Run `dotler vault from file origin` (different passphrase via DOTLER_PASSPHRASE vs keyring/existing)
    // Register existing-old-pass in OS keyring via `vault init --password-stdin` first, then supply origin pass via DOTLER_PASSPHRASE.
    let key_set_child = Command::new(env!("CARGO_BIN_EXE_dotler"))
        .env("HOME", &home_dir)
        .env("DOTLER_MOCK_KEYRING", "1")
        .env_remove("DOTLER_PASSPHRASE")
        .current_dir(&repo_existing)
        .args(["vault", "init", "--password-stdin", "--json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    {
        use std::io::Write;
        let mut child = key_set_child;
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(b"existing-old-pass-123\n")
            .unwrap();
        let out = child.wait_with_output().unwrap();
        assert_eq!(out.status.code(), Some(0));
    }

    // Notice DOTLER_MOCK_KEYRING starts fresh per process, so let's test in-memory re-keying when both vaults
    // use DOTLER_PASSPHRASE or via in-process test, AND test cross-vault mismatch detection with `dotler check`.
    let rekey_same_pw_repo = home_dir.join("repo_rekey_same");
    fs::create_dir_all(rekey_same_pw_repo.join("sec")).unwrap();
    run_dotler(
        &rekey_same_pw_repo,
        &["init", "--label", "rekey_same", "--json"],
        None,
    );
    fs::write(
        rekey_same_pw_repo.join("dotler.toml"),
        "[sec]\nos-nux = \"~\"\nos-mac = \"~\"\nos-win = \"~\"\nfiles = \"secret.txt enc\"\n",
    )
    .unwrap();
    assert_eq!(
        run_dotler(
            &rekey_same_pw_repo,
            &["vault", "init", "--json"],
            Some("master-shared-pass-777"),
        )
        .status
        .code(),
        Some(0)
    );
    assert_eq!(
        run_dotler(
            &rekey_same_pw_repo,
            &["import", "-y", "--json"],
            Some("master-shared-pass-777"),
        )
        .status
        .code(),
        Some(0)
    );
    let enc_before = EncryptedFile::from_bytes(
        &fs::read(rekey_same_pw_repo.join("sec/secret.txt.dotler.enc")).unwrap(),
    )
    .unwrap();
    assert_ne!(
        dotler::config::RepoConfig::load(&rekey_same_pw_repo.join("dotler.toml"))
            .unwrap()
            .vault
            .unwrap()
            .vault_id,
        origin_vault_id
    );

    let rekey_out = run_dotler(
        &rekey_same_pw_repo,
        &["vault", "from", "file", "origin", "--json"],
        Some("master-shared-pass-777"),
    );
    assert_eq!(
        rekey_out.status.code(),
        Some(0),
        "vault from rekeying stderr: {}",
        String::from_utf8_lossy(&rekey_out.stderr)
    );
    let rekey_json: serde_json::Value = serde_json::from_slice(&rekey_out.stdout).unwrap();
    assert_eq!(rekey_json["data"]["vault_id"], origin_vault_id);
    assert_eq!(rekey_json["data"]["rekeyed_files"], 1);

    let enc_after = EncryptedFile::from_bytes(
        &fs::read(rekey_same_pw_repo.join("sec/secret.txt.dotler.enc")).unwrap(),
    )
    .unwrap();
    assert_ne!(enc_before.vault_id, enc_after.vault_id);
    assert_eq!(
        dotler::config::RepoConfig::load(&rekey_same_pw_repo.join("dotler.toml"))
            .unwrap()
            .vault
            .unwrap()
            .vault_id,
        origin_vault_id
    );
    assert_eq!(
        run_dotler(&rekey_same_pw_repo, &["check", "--json"], None)
            .status
            .code(),
        Some(0)
    );

    // 6. Test `dotler vault ls --json`
    let key_ls_out = run_dotler(&repo_origin, &["vault", "ls", "--json"], None);
    assert_eq!(key_ls_out.status.code(), Some(0));
    let key_ls_json: serde_json::Value = serde_json::from_slice(&key_ls_out.stdout).unwrap();
    assert_eq!(key_ls_json["command"], "vault ls");
    assert_eq!(key_ls_json["data"]["use_keyring"], true);
    assert!(!key_ls_json["data"]["repos"].as_array().unwrap().is_empty());
}

#[test]
fn test_e2e_multi_vault_keyring_isolation_shared_init_and_fallback() {
    use std::fs;
    use std::process::{Command, Stdio};

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let home_dir = root.join("home");
    let dotler_dir = home_dir.join(".config").join("dotler");
    let repo_pub = home_dir.join("my-dotler");
    let repo_priv = home_dir.join("my-life-vault");
    let repo_shared = home_dir.join("shared-work-dots");
    fs::create_dir_all(&dotler_dir).unwrap();
    fs::create_dir_all(&repo_pub).unwrap();
    fs::create_dir_all(&repo_priv).unwrap();
    fs::create_dir_all(&repo_shared).unwrap();

    let run_dotler_with_stdin =
        |cwd: &std::path::Path, args: &[&str], env_pass: Option<&str>, stdin_data: Option<&str>| {
            let mut cmd = Command::new(env!("CARGO_BIN_EXE_dotler"));
            cmd.env("HOME", &home_dir)
                .env("DOTLER_MOCK_KEYRING", "1")
                .current_dir(cwd)
                .args(args);
            if let Some(p) = env_pass {
                cmd.env("DOTLER_PASSPHRASE", p);
            } else {
                cmd.env_remove("DOTLER_PASSPHRASE");
            }
            if let Some(input) = stdin_data {
                cmd.stdin(Stdio::piped());
                cmd.stdout(Stdio::piped());
                cmd.stderr(Stdio::piped());
                let mut child = cmd.spawn().unwrap();
                if let Some(mut s) = child.stdin.take() {
                    use std::io::Write;
                    let _ = s.write_all(input.as_bytes());
                }
                child.wait_with_output().unwrap()
            } else {
                cmd.stdin(Stdio::null());
                cmd.output().unwrap()
            }
        };

    // 1. Initialize two independent repositories + one repo sharing the public vault
    assert_eq!(
        run_dotler_with_stdin(
            &repo_pub,
            &["init", "--label", "my-dotler", "--json"],
            None,
            None,
        )
        .status
        .code(),
        Some(0)
    );
    assert_eq!(
        run_dotler_with_stdin(
            &repo_priv,
            &["init", "--label", "my-life-vault", "--json"],
            None,
            None,
        )
        .status
        .code(),
        Some(0)
    );
    assert_eq!(
        run_dotler_with_stdin(
            &repo_shared,
            &["init", "--label", "shared-work", "--json"],
            None,
            None,
        )
        .status
        .code(),
        Some(0)
    );

    assert_eq!(
        run_dotler_with_stdin(
            &repo_pub,
            &["vault", "init", "--password-stdin", "--json"],
            None,
            Some("public-vault-pw-111\n"),
        )
        .status
        .code(),
        Some(0)
    );
    assert_eq!(
        run_dotler_with_stdin(
            &repo_priv,
            &["vault", "init", "--password-stdin", "--json"],
            None,
            Some("private-life-pw-222\n"),
        )
        .status
        .code(),
        Some(0)
    );
    assert_eq!(
        run_dotler_with_stdin(
            &repo_shared,
            &[
                "vault",
                "from",
                "file",
                "my-dotler",
                "--password-stdin",
                "--json"
            ],
            None,
            Some("public-vault-pw-111\n"),
        )
        .status
        .code(),
        Some(0)
    );

    // 2. Verify two distinct vault_ids and shared vault_id
    let cfg_pub = dotler::config::RepoConfig::load(&repo_pub.join("dotler.toml")).unwrap();
    let cfg_priv = dotler::config::RepoConfig::load(&repo_priv.join("dotler.toml")).unwrap();
    let cfg_shared = dotler::config::RepoConfig::load(&repo_shared.join("dotler.toml")).unwrap();
    let vid_pub = cfg_pub.vault.as_ref().unwrap().vault_id.clone();
    let vid_priv = cfg_priv.vault.as_ref().unwrap().vault_id.clone();
    assert_ne!(vid_pub, vid_priv);
    assert_eq!(cfg_shared.vault.as_ref().unwrap().vault_id, vid_pub);

    // Add encrypted group rules and secret source files
    let os_secret_pub = home_dir.join(".pub_token");
    let os_secret_priv = home_dir.join(".priv_note");
    fs::write(&os_secret_pub, b"PUBLIC_REPO_TOKEN=abc\n").unwrap();
    fs::write(&os_secret_priv, b"PRIVATE_LIFE_SECRET=xyz\n").unwrap();

    let append_group = |dir: &std::path::Path, file: &str| {
        let mut s = fs::read_to_string(dir.join("dotler.toml")).unwrap();
        s.push_str(&format!(
            "\n[secrets]\nos-nux = \"~\"\nos-mac = \"~\"\nos-win = \"~\"\nfiles = \"{file} enc\"\n"
        ));
        fs::write(dir.join("dotler.toml"), s).unwrap();
    };
    append_group(&repo_pub, ".pub_token");
    append_group(&repo_shared, ".pub_token");
    append_group(&repo_priv, ".priv_note");

    // 3. In-process verification of non-interactive multi-vault unlocking & shared vault unlock
    let _guard = TestKeyringGuard::new();
    unsafe {
        std::env::remove_var(dotler::crypto::keyring::PASSPHRASE_ENV_VAR);
    }
    OsKeyring::set_with_fallback(
        Some(&vid_pub),
        &SecretString::new("public-vault-pw-111".to_string()),
    )
    .unwrap();
    OsKeyring::set_with_fallback(
        Some(&vid_priv),
        &SecretString::new("private-life-pw-222".to_string()),
    )
    .unwrap();

    let loaded_pub = dotler::config::RepoConfig::load(&repo_pub.join("dotler.toml")).unwrap();
    let loaded_shared = dotler::config::RepoConfig::load(&repo_shared.join("dotler.toml")).unwrap();
    let loaded_priv = dotler::config::RepoConfig::load(&repo_priv.join("dotler.toml")).unwrap();

    let k_pub = dotler::core::unlock_vault_if_needed(&loaded_pub, true, false, true)
        .unwrap()
        .unwrap();
    let k_shared = dotler::core::unlock_vault_if_needed(&loaded_shared, true, false, true)
        .unwrap()
        .unwrap();
    let k_priv = dotler::core::unlock_vault_if_needed(&loaded_priv, true, false, true)
        .unwrap()
        .unwrap();

    assert_eq!(k_pub.vault_id(), vid_pub);
    assert_eq!(k_shared.vault_id(), vid_pub);
    assert_eq!(k_priv.vault_id(), vid_priv);
}

#[test]
fn test_full_encryption_enc_full_import_export_tidy_check_and_literal_warning() {
    use std::fs;
    use std::process::{Command, Stdio};

    let temp = tempfile::tempdir().unwrap();
    let home_dir = temp.path().join("home");
    let repo_dir = home_dir.join("dotfiles");
    let ssh_os = home_dir.join(".ssh");
    fs::create_dir_all(ssh_os.join("clients/acme-corp")).unwrap();
    fs::create_dir_all(&repo_dir).unwrap();

    let bin = env!("CARGO_BIN_EXE_dotler");
    let pass = "full-enc-master-pass-789";
    let run_cli = |args: &[&str], stdin_str: Option<&str>| {
        let mut cmd = Command::new(bin);
        cmd.current_dir(&repo_dir)
            .env("HOME", &home_dir)
            .env("USERPROFILE", &home_dir)
            .env("DOTLER_PASSPHRASE", pass)
            .args(args);
        if let Some(s) = stdin_str {
            cmd.stdin(Stdio::piped());
            let mut child = cmd.spawn().unwrap();
            if let Some(mut pipe) = child.stdin.take() {
                use std::io::Write;
                let _ = pipe.write_all(s.as_bytes());
            }
            child.wait_with_output().unwrap()
        } else {
            cmd.stdin(Stdio::null());
            cmd.output().unwrap()
        }
    };

    assert_eq!(
        run_cli(&["init", "--label", "dots", "--json"], None)
            .status
            .code(),
        Some(0)
    );
    assert_eq!(
        run_cli(
            &["vault", "init", "--password-stdin", "--json"],
            Some("full-enc-master-pass-789\n")
        )
        .status
        .code(),
        Some(0)
    );

    fs::write(
        ssh_os.join("clients/acme-corp/secret_key"),
        b"PRIVATE_CLIENT_KEY_MATERIAL",
    )
    .unwrap();
    let conf_plain = format!(
        "IdentityFile {}/.ssh/clients/acme-corp/secret_key\n",
        home_dir.display()
    );
    fs::write(
        ssh_os.join("clients/acme-corp/client.conf"),
        conf_plain.as_bytes(),
    )
    .unwrap();
    fs::write(ssh_os.join("id_ed25519"), b"STANDARD_SSH_PRIVATE_KEY").unwrap();
    fs::write(ssh_os.join("id_ed25519.pub"), b"ssh-ed25519 AAAA...").unwrap();
    fs::write(ssh_os.join("known_hosts"), b"example.com ssh-ed25519 ...").unwrap();

    let base_manifest = fs::read_to_string(repo_dir.join("dotler.toml")).unwrap();
    let manifest_full = format!(
        "{base_manifest}\n[ssh]\nos-nux = \"~/.ssh\"\nos-mac = \"~/.ssh\"\nos-win = \"~/.ssh\"\nos-bsd = \"~/.ssh\"\nfiles = \"\"\"\n* enc=full\n*.conf enc=full tpl\nid_ed25519 enc=cont\n*.pub\n!known_hosts*\n\"\"\"\n"
    );
    fs::write(repo_dir.join("dotler.toml"), &manifest_full).unwrap();

    // Wildcard enc=full rules must pass check with zero warnings
    let chk_ok = run_cli(&["check", "--json"], None);
    assert_eq!(chk_ok.status.code(), Some(0));
    let chk_json: serde_json::Value = serde_json::from_slice(&chk_ok.stdout).unwrap();
    assert!(chk_json["data"]["warnings"].is_null());

    // First import
    let imp1 = run_cli(&["import", "-y", "--json"], None);
    assert_eq!(
        imp1.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&imp1.stderr)
    );

    let ssh_repo = repo_dir.join("ssh");
    assert!(ssh_repo.join("id_ed25519.dotler.enc").is_file());
    assert!(ssh_repo.join("id_ed25519.pub").is_file());
    assert!(
        !ssh_repo.join("clients").exists(),
        "nested directory names must be hidden"
    );

    let fenc_files: Vec<_> = fs::read_dir(&ssh_repo)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().ends_with(".dotler.fenc"))
        .collect();
    assert_eq!(fenc_files.len(), 2);
    for entry in &fenc_files {
        let name = entry.file_name().to_string_lossy().to_string();
        assert!(!name.contains("acme") && !name.contains("secret"));
        let raw = fs::read(entry.path()).unwrap();
        assert!(!String::from_utf8_lossy(&raw).contains("acme"));
        assert!(!String::from_utf8_lossy(&raw).contains(&home_dir.to_string_lossy().to_string()));
    }

    // Second import must skip unchanged .dotler.fenc files with zero byte churn
    let snap_before: Vec<(String, Vec<u8>)> = fenc_files
        .iter()
        .map(|e| {
            (
                e.file_name().to_string_lossy().to_string(),
                fs::read(e.path()).unwrap(),
            )
        })
        .collect();
    let imp2 = run_cli(&["import", "-y", "--json"], None);
    assert_eq!(imp2.status.code(), Some(0));
    for (fname, before_bytes) in snap_before {
        assert_eq!(fs::read(ssh_repo.join(fname)).unwrap(), before_bytes);
    }

    // Delete OS files and export back from .dotler.fenc archives
    fs::remove_dir_all(ssh_os.join("clients")).unwrap();
    let exp = run_cli(&["export", "-y", "--json"], None);
    assert_eq!(
        exp.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&exp.stderr)
    );
    assert_eq!(
        fs::read(ssh_os.join("clients/acme-corp/secret_key")).unwrap(),
        b"PRIVATE_CLIENT_KEY_MATERIAL"
    );
    assert_eq!(
        fs::read_to_string(ssh_os.join("clients/acme-corp/client.conf")).unwrap(),
        conf_plain
    );

    // Switch * enc=full -> * enc=cont: check must detect mismatch (even without passphrase!), tidy reconciles
    let manifest_cont = format!(
        "{base_manifest}\n[ssh]\nos-nux = \"~/.ssh\"\nos-mac = \"~/.ssh\"\nos-win = \"~/.ssh\"\nos-bsd = \"~/.ssh\"\nfiles = \"\"\"\n* enc=cont\n*.conf enc=cont tpl\n*.pub\n!known_hosts*\n\"\"\"\n"
    );
    fs::write(repo_dir.join("dotler.toml"), &manifest_cont).unwrap();

    let mut locked_check = Command::new(bin);
    let locked_out = locked_check
        .current_dir(&repo_dir)
        .env("HOME", &home_dir)
        .env_remove("DOTLER_PASSPHRASE")
        .args(["check", "--json"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(locked_out.status.code(), Some(1));

    let tidy_to_cont = run_cli(&["tidy", "-y", "--json"], None);
    assert_eq!(tidy_to_cont.status.code(), Some(0));
    assert!(
        ssh_repo
            .join("clients/acme-corp/secret_key.dotler.enc")
            .is_file()
    );
    assert!(
        ssh_repo
            .join("clients/acme-corp/client.conf.dotler.enc")
            .is_file()
    );
    assert_eq!(
        fs::read_dir(&ssh_repo)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".dotler.fenc"))
            .count(),
        0
    );

    // Switch back to * enc=full: tidy converts .dotler.enc -> .dotler.fenc and prunes empty clients/acme-corp/ subdir
    fs::write(repo_dir.join("dotler.toml"), &manifest_full).unwrap();
    let tidy_to_full = run_cli(&["tidy", "-y", "--json"], None);
    assert_eq!(tidy_to_full.status.code(), Some(0));
    assert!(!ssh_repo.join("clients").exists());
    assert_eq!(run_cli(&["check", "--json"], None).status.code(), Some(0));

    // Literal path with enc=full is allowed (exit 0) and emits warning/hint
    let manifest_literal = format!(
        "{base_manifest}\n[ssh]\nos-nux = \"~/.ssh\"\nos-mac = \"~/.ssh\"\nos-win = \"~/.ssh\"\nos-bsd = \"~/.ssh\"\nfiles = \"\"\"\nclients/acme-corp/secret_key enc=full\nclients/acme-corp/client.conf enc=full tpl\nid_ed25519 enc=cont\n*.pub\n!known_hosts*\n\"\"\"\n"
    );
    fs::write(repo_dir.join("dotler.toml"), &manifest_literal).unwrap();
    let chk_warn_json = run_cli(&["check", "--json"], None);
    assert_eq!(chk_warn_json.status.code(), Some(0));
    let warn_val: serde_json::Value = serde_json::from_slice(&chk_warn_json.stdout).unwrap();
    let warnings = warn_val["data"]["warnings"].as_array().unwrap();
    assert_eq!(warnings.len(), 2);
    assert!(
        warnings[0]
            .as_str()
            .unwrap()
            .contains("clients/acme-corp/secret_key")
    );

    let chk_warn_inline = run_cli(&["check"], None);
    assert_eq!(chk_warn_inline.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&chk_warn_inline.stdout).contains("Hint:"));
}

#[test]
fn test_full_encryption_rekeying_on_vault_from_and_remote_git_install() {
    use dotler::config::{DotlerLock, StateDb};
    use dotler::engine::observer::NoopObserver;
    use dotler::engine::remote::{install_remote_with_options, parse_url, uninstall_remote};
    use std::fs;
    use std::process::{Command, Stdio};
    use std::time::Duration;

    let temp = tempfile::tempdir().unwrap();
    let home_dir = temp.path().join("home");
    let repo_a = home_dir.join("repo_a");
    let repo_b = home_dir.join("repo_b");
    let app_os = home_dir.join(".config/secret_app");
    fs::create_dir_all(app_os.join("nested")).unwrap();
    fs::create_dir_all(&repo_a).unwrap();
    fs::create_dir_all(&repo_b).unwrap();

    fs::write(
        app_os.join("nested/token.conf"),
        format!("HOME_PATH={}\nTOKEN=xyz\n", home_dir.display()).as_bytes(),
    )
    .unwrap();

    let bin = env!("CARGO_BIN_EXE_dotler");
    let run_in = |cwd: &std::path::Path, pass: &str, args: &[&str], stdin_str: Option<&str>| {
        let mut cmd = Command::new(bin);
        cmd.current_dir(cwd)
            .env("HOME", &home_dir)
            .env("USERPROFILE", &home_dir)
            .env("DOTLER_PASSPHRASE", pass)
            .args(args);
        if let Some(s) = stdin_str {
            cmd.stdin(Stdio::piped());
            let mut child = cmd.spawn().unwrap();
            if let Some(mut pipe) = child.stdin.take() {
                use std::io::Write;
                let _ = pipe.write_all(s.as_bytes());
            }
            child.wait_with_output().unwrap()
        } else {
            cmd.stdin(Stdio::null());
            cmd.output().unwrap()
        }
    };

    assert_eq!(
        run_in(
            &repo_a,
            "pass-a-111",
            &["init", "--label", "a", "--json"],
            None
        )
        .status
        .code(),
        Some(0)
    );
    assert_eq!(
        run_in(
            &repo_a,
            "pass-a-111",
            &["vault", "init", "--password-stdin", "--json"],
            Some("pass-a-111\n")
        )
        .status
        .code(),
        Some(0)
    );
    assert_eq!(
        run_in(
            &repo_b,
            "pass-b-222",
            &["init", "--label", "b", "--json"],
            None
        )
        .status
        .code(),
        Some(0)
    );
    assert_eq!(
        run_in(
            &repo_b,
            "pass-b-222",
            &["vault", "init", "--password-stdin", "--json"],
            Some("pass-b-222\n")
        )
        .status
        .code(),
        Some(0)
    );

    let mut toml_a = fs::read_to_string(repo_a.join("dotler.toml")).unwrap();
    toml_a.push_str(
        "\n[app]\nos-nux = \"~/.config/secret_app\"\nos-mac = \"~/.config/secret_app\"\nos-win = \"~/.config/secret_app\"\nos-bsd = \"~/.config/secret_app\"\nfiles = \"* enc=full tpl\"\n",
    );
    fs::write(repo_a.join("dotler.toml"), toml_a).unwrap();

    assert_eq!(
        run_in(&repo_a, "pass-a-111", &["import", "-y", "--json"], None)
            .status
            .code(),
        Some(0)
    );
    let old_fenc: Vec<_> = fs::read_dir(repo_a.join("app"))
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .collect();
    assert_eq!(old_fenc.len(), 1);

    // Re-key repo_a to vault B via `vault from file`
    // Provide vault B pass via stdin; vault A unlocks via keyring/env? Let's pass vault A via env?
    // Note: in `vault from`, `--password-stdin` supplies new vault passphrase (pass-b-222),
    // and `DOTLER_PASSPHRASE` supplies old vault passphrase (pass-a-111) for `unlock_vault_if_needed`!
    let rekey_out = run_in(
        &repo_a,
        "pass-a-111",
        &["vault", "from", "file", "b", "--password-stdin", "--json"],
        Some("pass-b-222\n"),
    );
    assert_eq!(
        rekey_out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&rekey_out.stderr)
    );
    let new_fenc: Vec<_> = fs::read_dir(repo_a.join("app"))
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .collect();
    assert_eq!(new_fenc.len(), 1);
    assert_ne!(
        old_fenc[0], new_fenc[0],
        "re-keying must re-derive .fenc token"
    );
    assert!(
        !old_fenc[0].exists(),
        "stale .fenc from old vault must be removed"
    );

    // Verify `git install` deploys .fenc + tpl cleanly and `git uninstall` restores
    let cfg_b = dotler::config::RepoConfig::load(&repo_a.join("dotler.toml")).unwrap();
    let vcfg_b = cfg_b.vault.as_ref().unwrap();
    let slot_b = dotler::crypto::VaultSlot::from_base64(&vcfg_b.password_slot).unwrap();
    let key_b = slot_b
        .unwrap(
            &SecretString::new("pass-b-222".to_string()),
            Some(&vcfg_b.vault_id),
        )
        .unwrap();

    // Commit repo_a into a real Git repository so `install_remote_with_options` clones it cleanly
    assert!(
        Command::new("git")
            .args(["init"])
            .current_dir(&repo_a)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("git")
            .args(["config", "user.email", "test@example.com"])
            .current_dir(&repo_a)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("git")
            .args(["config", "user.name", "Test"])
            .current_dir(&repo_a)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("git")
            .args(["add", "."])
            .current_dir(&repo_a)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("git")
            .args(["commit", "-m", "init"])
            .current_dir(&repo_a)
            .status()
            .unwrap()
            .success()
    );

    let sandbox_home = temp.path().join("target_home");
    let dotler_cfg_dir = sandbox_home.join(".config/dotler");
    fs::create_dir_all(&dotler_cfg_dir).unwrap();
    let state_db = StateDb::open(&dotler_cfg_dir.join("state.db")).unwrap();
    let lock = DotlerLock::new(dotler_cfg_dir.join("dotler.lock"))
        .acquire(Duration::from_millis(500), Duration::from_millis(10))
        .unwrap();

    let url = parse_url(&format!("file://{}", repo_a.display())).unwrap();
    let mut noop = NoopObserver;
    let inst_rep = install_remote_with_options(
        &url,
        &["app".to_string()],
        None,
        None,
        &[],
        &state_db,
        &lock,
        false,
        false,
        false,
        Some(&key_b),
        &mut noop,
    )
    .unwrap();
    let expected_installed = sandbox_home.join(".config/secret_app/nested/token.conf");
    assert_eq!(inst_rep.installed_files, vec![expected_installed.clone()]);
    assert_eq!(
        fs::read_to_string(&expected_installed).unwrap(),
        format!("HOME_PATH={}\nTOKEN=xyz\n", sandbox_home.display())
    );

    let uninst_rep = uninstall_remote(&["app".to_string()], &state_db, &lock, false).unwrap();
    assert_eq!(uninst_rep.removed_files, vec![expected_installed.clone()]);
    assert!(!expected_installed.exists());
}

#[test]
fn test_user_plain_enc_non_collision_and_legacy_archive_tidy_migration() {
    use dotler::crypto::FULL_ENC_SUFFIX;
    use std::fs;
    use std::process::{Command, Stdio};

    let temp = tempfile::tempdir().unwrap();
    let home_dir = temp.path().join("home");
    let repo_dir = home_dir.join("repo");
    let certs_os = home_dir.join(".config/certs");
    let sec_os = home_dir.join(".config/sec");
    fs::create_dir_all(&certs_os).unwrap();
    fs::create_dir_all(sec_os.join("nested")).unwrap();
    fs::create_dir_all(&repo_dir).unwrap();

    // User's own non-Dotler `.enc` file (> 48 bytes, OpenSSL-style header) tracked as plaintext `*`
    let user_openssl_blob =
        b"Salted__0123456789abcdef_non_dotler_external_openssl_encrypted_payload_bytes\n";
    fs::write(certs_os.join("openssl_backup.enc"), user_openssl_blob).unwrap();

    let bin = env!("CARGO_BIN_EXE_dotler");
    let run_cli = |args: &[&str], stdin_str: Option<&str>| {
        let mut cmd = Command::new(bin);
        cmd.current_dir(&repo_dir)
            .env("HOME", &home_dir)
            .env("USERPROFILE", &home_dir)
            .env("DOTLER_PASSPHRASE", "legacy-mig-pass-777")
            .args(args);
        if let Some(s) = stdin_str {
            cmd.stdin(Stdio::piped());
            let mut child = cmd.spawn().unwrap();
            if let Some(mut pipe) = child.stdin.take() {
                use std::io::Write;
                let _ = pipe.write_all(s.as_bytes());
            }
            child.wait_with_output().unwrap()
        } else {
            cmd.stdin(Stdio::null());
            cmd.output().unwrap()
        }
    };

    assert_eq!(run_cli(&["init", "--json"], None).status.code(), Some(0));
    assert_eq!(
        run_cli(
            &["vault", "init", "--password-stdin", "--json"],
            Some("legacy-mig-pass-777\n")
        )
        .status
        .code(),
        Some(0)
    );

    let base_manifest = fs::read_to_string(repo_dir.join("dotler.toml")).unwrap();
    let manifest = format!(
        "{base_manifest}\n[certs]\nos-nux = \"~/.config/certs\"\nos-mac = \"~/.config/certs\"\nos-win = \"~/.config/certs\"\nos-bsd = \"~/.config/certs\"\nfiles = \"*\"\n\n[sec]\nos-nux = \"~/.config/sec\"\nos-mac = \"~/.config/sec\"\nos-win = \"~/.config/sec\"\nos-bsd = \"~/.config/sec\"\nfiles = \"\"\"\napi.key enc\nnested/* enc=full\n\"\"\"\n"
    );
    fs::write(repo_dir.join("dotler.toml"), &manifest).unwrap();

    // 1. Import and check user `openssl_backup.enc` as plaintext with zero false-positive mismatch
    let imp_certs = run_cli(&["import", "-y", "--json"], None);
    assert_eq!(imp_certs.status.code(), Some(0));
    assert_eq!(
        fs::read(repo_dir.join("certs/openssl_backup.enc")).unwrap(),
        user_openssl_blob
    );
    assert_eq!(run_cli(&["check", "--json"], None).status.code(), Some(0));
    assert_eq!(
        run_cli(&["tidy", "-y", "--json"], None).status.code(),
        Some(0)
    );
    assert_eq!(
        fs::read(repo_dir.join("certs/openssl_backup.enc")).unwrap(),
        user_openssl_blob
    );

    fs::remove_file(certs_os.join("openssl_backup.enc")).unwrap();
    assert_eq!(
        run_cli(&["export", "-y", "--json"], None).status.code(),
        Some(0)
    );
    assert_eq!(
        fs::read(certs_os.join("openssl_backup.enc")).unwrap(),
        user_openssl_blob
    );

    // 2. Seed legacy `.enc` and `.fenc` archives with matching `vault_id`:
    //    `dotler check` flags them, and `dotler tidy` migrates them to `.dotler.enc` / `.dotler.fenc`.
    let parsed_cfg = dotler::config::RepoConfig::load(&repo_dir.join("dotler.toml")).unwrap();
    let vcfg = parsed_cfg.vault.as_ref().unwrap();
    let slot = dotler::crypto::VaultSlot::from_base64(&vcfg.password_slot).unwrap();
    let vkey = slot
        .unwrap(
            &SecretString::new("legacy-mig-pass-777".to_string()),
            Some(&vcfg.vault_id),
        )
        .unwrap();

    fs::create_dir_all(repo_dir.join("sec")).unwrap();
    let legacy_enc_bytes = vkey
        .encrypt_file(b"API_TOKEN=legacy_enc\n")
        .unwrap()
        .to_bytes();
    fs::write(repo_dir.join("sec/api.key.enc"), &legacy_enc_bytes).unwrap();

    let (modern_fenc_name, fenc_obj) = vkey
        .encrypt_full_file("nested/secret.pem", b"PEM_PAYLOAD=legacy_fenc\n")
        .unwrap();
    let stem = modern_fenc_name.strip_suffix(FULL_ENC_SUFFIX).unwrap();
    let legacy_fenc_path = repo_dir.join("sec").join(format!("{stem}.fenc"));
    fs::write(&legacy_fenc_path, fenc_obj.to_bytes()).unwrap();

    let chk_legacy = run_cli(&["check", "--json"], None);
    assert_eq!(chk_legacy.status.code(), Some(1));
    let chk_err: serde_json::Value = serde_json::from_slice(&chk_legacy.stdout).unwrap();
    assert_eq!(chk_err["error_code"], "ENCRYPTION_MISMATCH");

    let tidy_mig = run_cli(&["tidy", "-y", "--json"], None);
    assert_eq!(
        tidy_mig.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&tidy_mig.stderr)
    );
    assert!(!repo_dir.join("sec/api.key.enc").exists());
    assert!(repo_dir.join("sec/api.key.dotler.enc").is_file());
    assert!(!legacy_fenc_path.exists());
    assert!(repo_dir.join("sec").join(&modern_fenc_name).is_file());
    // User's plain `openssl_backup.enc` remains untouched
    assert_eq!(
        fs::read(repo_dir.join("certs/openssl_backup.enc")).unwrap(),
        user_openssl_blob
    );

    assert_eq!(run_cli(&["check", "--json"], None).status.code(), Some(0));
    assert_eq!(
        run_cli(&["export", "-y", "--json"], None).status.code(),
        Some(0)
    );
    assert_eq!(
        fs::read(sec_os.join("api.key")).unwrap(),
        b"API_TOKEN=legacy_enc\n"
    );
    assert_eq!(
        fs::read(sec_os.join("nested/secret.pem")).unwrap(),
        b"PEM_PAYLOAD=legacy_fenc\n"
    );
}
