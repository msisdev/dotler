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
fn test_vault_passwd_preserves_ciphertext_without_reencryption() {
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
    let enc_before =
        EncryptedFile::from_bytes(&fs::read(rekey_same_pw_repo.join("sec/secret.txt.enc")).unwrap())
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

    let enc_after =
        EncryptedFile::from_bytes(&fs::read(rekey_same_pw_repo.join("sec/secret.txt.enc")).unwrap())
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
            &["vault", "from", "file", "my-dotler", "--password-stdin", "--json"],
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
