mod common;

use std::fs;

use common::{ChallengeSandbox, MockGitRepo};
use dotler::crypto::vault::{EncryptedFile, init_vault};
use dotler::crypto::{ExposeSecret, SecretString};
use dotler::engine::EngineError;
use dotler::engine::remote::{
    REMOTE_TOML_FETCH_MAX_BYTES, STAGING_CLONE_PREFIX, clone_repo, install_remote, list_remote,
    parse_url,
};

// ============================================================================
// Suite 1: Payload Limit Boundary Testing (`list_remote`)
// ============================================================================

#[test]
fn test_list_remote_payload_exact_1mib_passes() {
    let sandbox = ChallengeSandbox::new();
    let lock = sandbox.acquire_lock();

    let base = "[shell]\nos-nux = \"~\"\nfiles = \"*.sh\"\n";
    let target_len = REMOTE_TOML_FETCH_MAX_BYTES; // 1,048,576 bytes
    assert!(target_len > base.len());

    let mut padded = String::with_capacity(target_len);
    padded.push_str(base);
    let needed = target_len - base.len();
    let comment_body = "#".repeat(needed.saturating_sub(1));
    padded.push_str(&comment_body);
    padded.push('\n');

    assert_eq!(padded.len(), target_len, "Payload must be exactly 1 MiB");

    let mock_repo = MockGitRepo::new(&padded, &[]);
    let url = parse_url(&mock_repo.clone_url).unwrap();

    let summary = list_remote(&url, None, &lock).expect("Exact 1 MiB payload must succeed");
    assert_eq!(summary.groups.len(), 1);
    assert_eq!(summary.groups[0].name, "shell");
}

#[test]
fn test_list_remote_payload_1mib_plus_one_byte_aborts() {
    let sandbox = ChallengeSandbox::new();
    let lock = sandbox.acquire_lock();

    let base = "[shell]\nos-nux = \"~\"\nfiles = \"*.sh\"\n";
    let target_len = REMOTE_TOML_FETCH_MAX_BYTES + 1; // 1,048,577 bytes

    let mut padded = String::with_capacity(target_len);
    padded.push_str(base);
    let needed = target_len - base.len();
    let comment_body = "#".repeat(needed.saturating_sub(1));
    padded.push_str(&comment_body);
    padded.push('\n');

    assert_eq!(
        padded.len(),
        target_len,
        "Payload must be exactly 1 MiB + 1 byte"
    );

    let mock_repo = MockGitRepo::new(&padded, &[]);
    let url = parse_url(&mock_repo.clone_url).unwrap();

    let err =
        list_remote(&url, None, &lock).expect_err("1 MiB + 1 byte must fail with PayloadExceeded");
    match err {
        EngineError::PayloadExceeded {
            size_bytes,
            limit_bytes,
        } => {
            assert_eq!(size_bytes, 1_048_577);
            assert_eq!(limit_bytes, REMOTE_TOML_FETCH_MAX_BYTES);
            assert_eq!(
                err.exit_code(),
                2,
                "PayloadExceeded must map to exit code 2"
            );
            assert_eq!(err.error_code(), "PAYLOAD_EXCEEDED");
        }
        other => panic!("Expected PayloadExceeded, got: {:?}", other),
    }
}

// ============================================================================
// Suite 2: Security & Path Traversal Attacks (`clone_repo` and `install_remote`)
// ============================================================================

#[test]
fn test_clone_repo_path_traversal_dot_dot_aborts_exit_code_3() {
    let sandbox = ChallengeSandbox::new();
    let lock = sandbox.acquire_lock();

    let malicious_toml = r#"
[attack]
os-nux = "~/../../etc"
files = "passwd"
"#;
    let mock_repo = MockGitRepo::new(malicious_toml, &[("attack/passwd", b"evil")]);
    let url = parse_url(&mock_repo.clone_url).unwrap();
    let dest = sandbox.root.path().join("cloned_attack");

    let err = clone_repo(&url, &[], None, &dest, None, None, None, &lock)
        .expect_err("Path traversal must be rejected");

    assert_eq!(err.exit_code(), 3);
    assert_eq!(err.error_code(), "SECURITY_BLOCKED");
    assert!(!dest.exists());

    let parent = dest.parent().unwrap();
    let lingering_staging = fs::read_dir(parent)
        .unwrap()
        .filter_map(|e| e.ok())
        .any(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with(STAGING_CLONE_PREFIX)
        });
    assert!(!lingering_staging, "Staging directory must be cleaned up");
}

#[test]
fn test_clone_repo_absolute_path_aborts_exit_code_3() {
    let sandbox = ChallengeSandbox::new();
    let lock = sandbox.acquire_lock();

    let malicious_toml = r#"
[attack]
os-nux = "/etc/passwd"
files = "passwd"
"#;
    let mock_repo = MockGitRepo::new(malicious_toml, &[("attack/passwd", b"evil")]);
    let url = parse_url(&mock_repo.clone_url).unwrap();
    let dest = sandbox.root.path().join("cloned_attack");

    let err = clone_repo(&url, &[], None, &dest, None, None, None, &lock)
        .expect_err("Absolute path must be rejected");

    assert_eq!(err.exit_code(), 3);
    assert_eq!(err.error_code(), "SECURITY_BLOCKED");
    assert!(!dest.exists());
}

#[test]
fn test_clone_repo_target_git_directory_aborts_exit_code_3() {
    let sandbox = ChallengeSandbox::new();
    let lock = sandbox.acquire_lock();

    let malicious_toml = r#"
[attack]
os-nux = "~/.git/hooks"
files = "pre-commit"
"#;
    let mock_repo = MockGitRepo::new(malicious_toml, &[("attack/pre-commit", b"evil")]);
    let url = parse_url(&mock_repo.clone_url).unwrap();
    let dest = sandbox.root.path().join("cloned_attack");

    let err = clone_repo(&url, &[], None, &dest, None, None, None, &lock)
        .expect_err(".git target must be rejected");

    assert_eq!(err.exit_code(), 3);
    assert_eq!(err.error_code(), "SECURITY_BLOCKED");
    assert!(!dest.exists());
}

#[test]
fn test_clone_repo_target_internal_dotler_config_aborts_exit_code_3() {
    let sandbox = ChallengeSandbox::new();
    let lock = sandbox.acquire_lock();

    let malicious_toml = r#"
[attack]
os-nux = "~/.config/dotler/evil"
files = "evil.db"
"#;
    let mock_repo = MockGitRepo::new(malicious_toml, &[("attack/evil.db", b"evil")]);
    let url = parse_url(&mock_repo.clone_url).unwrap();
    let dest = sandbox.root.path().join("cloned_attack");

    let err = clone_repo(&url, &[], None, &dest, None, None, None, &lock)
        .expect_err("~/.config/dotler target must be rejected");

    assert_eq!(err.exit_code(), 3);
    assert_eq!(err.error_code(), "SECURITY_BLOCKED");
    assert!(!dest.exists());
}

#[test]
fn test_clone_repo_selection_pattern_traversal_aborts_exit_code_3() {
    let sandbox = ChallengeSandbox::new();
    let lock = sandbox.acquire_lock();

    let malicious_toml = r#"
[attack]
os-nux = "~"
files = "../../../etc/shadow"
"#;
    let mock_repo = MockGitRepo::new(malicious_toml, &[]);
    let url = parse_url(&mock_repo.clone_url).unwrap();
    let dest = sandbox.root.path().join("cloned_attack");

    let err = clone_repo(&url, &[], None, &dest, None, None, None, &lock)
        .expect_err("Selection rule traversal must be rejected");

    assert_eq!(err.exit_code(), 3);
    assert_eq!(err.error_code(), "SECURITY_BLOCKED");
    assert!(!dest.exists());
}

#[test]
fn test_clone_repo_rekeying_across_different_vaults() {
    let sandbox = ChallengeSandbox::new();
    let lock = sandbox.acquire_lock();

    // Vault Remote
    let remote_secret = SecretString::new("remote-vault-pass-secret".to_string());
    let (remote_vault_cfg, remote_vault_key, _) = init_vault(&remote_secret).unwrap();

    // Vault Local
    let local_secret = SecretString::new("local-vault-pass-secret".to_string());
    let (_local_vault_cfg, local_vault_key, _) = init_vault(&local_secret).unwrap();

    assert_ne!(remote_vault_key.vault_id(), local_vault_key.vault_id());

    let secret_dotfile = b"PRIVATE_API_TOKEN_XYZ123456789";
    let encrypted_remote = remote_vault_key.encrypt_file(secret_dotfile).unwrap();

    let remote_toml = format!(
        r#"
vault_id = "{}"
password_slot = "{}"
recovery_slot = "{}"

[secure]
os-nux = "~/.config/app"
files = "@token.enc"
"#,
        remote_vault_cfg.vault_id, remote_vault_cfg.password_slot, remote_vault_cfg.recovery_slot,
    );

    let mock_repo = MockGitRepo::new(
        &remote_toml,
        &[("secure/token.enc", &encrypted_remote.to_bytes())],
    );
    let url = parse_url(&mock_repo.clone_url).unwrap();
    let dest = sandbox.root.path().join("cloned_rekey");

    let report = clone_repo(
        &url,
        &[],
        None,
        &dest,
        None,
        Some(&remote_vault_key),
        Some(&local_vault_key),
        &lock,
    )
    .expect("Clone with in-memory Re-Keying must succeed");

    assert_eq!(report.destination, dest);
    let rekeyed_file_path = dest.join("secure/token.enc");
    assert!(rekeyed_file_path.is_file());

    let rekeyed_bytes = fs::read(&rekeyed_file_path).unwrap();
    let enc_file = EncryptedFile::from_bytes(&rekeyed_bytes).unwrap();

    // File should now be tied to local vault ID
    assert_eq!(enc_file.vault_id, local_vault_key.vault_id_bytes());

    // Remote key should fail to decrypt
    assert!(remote_vault_key.decrypt_file(&enc_file).is_err());

    // Local key should decrypt successfully to original plaintext
    let decrypted = local_vault_key.decrypt_file(&enc_file).unwrap();
    assert_eq!(decrypted.expose_secret(), secret_dotfile);
}

#[test]
fn test_install_remote_path_traversal_aborts_exit_code_3_and_cleans_staging() {
    let sandbox = ChallengeSandbox::new();
    let lock = sandbox.acquire_lock();

    let malicious_toml = r#"
[attack]
os-nux = "~/../../etc"
files = "shadow"
"#;
    let mock_repo = MockGitRepo::new(malicious_toml, &[("attack/shadow", b"evil")]);
    let url = parse_url(&mock_repo.clone_url).unwrap();

    let err = install_remote(
        &url,
        &["attack".to_string()],
        None,
        None,
        &[],
        &sandbox.state_db,
        &lock,
    )
    .expect_err("install_remote must reject path traversal");

    assert_eq!(err.exit_code(), 3);
    assert_eq!(err.error_code(), "SECURITY_BLOCKED");
    assert_eq!(
        sandbox.state_db.list_installed_files(None).unwrap().len(),
        0
    );
}

#[test]
fn test_install_remote_absolute_path_aborts_exit_code_3() {
    let sandbox = ChallengeSandbox::new();
    let lock = sandbox.acquire_lock();

    let malicious_toml = r#"
[attack]
os-nux = "/var/log/attack"
files = "attack.log"
"#;
    let mock_repo = MockGitRepo::new(malicious_toml, &[("attack/attack.log", b"evil")]);
    let url = parse_url(&mock_repo.clone_url).unwrap();

    let err = install_remote(
        &url,
        &["attack".to_string()],
        None,
        None,
        &[],
        &sandbox.state_db,
        &lock,
    )
    .expect_err("install_remote must reject absolute path");

    assert_eq!(err.exit_code(), 3);
    assert_eq!(err.error_code(), "SECURITY_BLOCKED");
}

#[test]
fn test_install_remote_dotler_config_target_aborts_exit_code_3() {
    let sandbox = ChallengeSandbox::new();
    let lock = sandbox.acquire_lock();

    let malicious_toml = r#"
[attack]
os-nux = "~/.config/dotler"
files = "state.db"
"#;
    let mock_repo = MockGitRepo::new(malicious_toml, &[("attack/state.db", b"evil")]);
    let url = parse_url(&mock_repo.clone_url).unwrap();

    let err = install_remote(
        &url,
        &["attack".to_string()],
        None,
        None,
        &[],
        &sandbox.state_db,
        &lock,
    )
    .expect_err("install_remote must reject ~/.config/dotler target");

    assert_eq!(err.exit_code(), 3);
    assert_eq!(err.error_code(), "SECURITY_BLOCKED");
}

