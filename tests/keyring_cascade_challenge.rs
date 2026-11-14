mod common;

use std::sync::{Arc, Barrier};
use std::thread;

use common::TestKeyringGuard;
use dotler::crypto::{
    ExposeSecret, KeyringError, OsKeyring, PASSPHRASE_ENV_VAR, PassphraseSource,
    ResolvedPassphrase, SecretString,
};

// 4. Supply Cascade Precedence Tests
#[test]
fn test_empirical_supply_cascade_precedence_full_matrix() {
    let _guard = TestKeyringGuard::new();

    // Clean initial slate
    unsafe {
        std::env::remove_var(PASSPHRASE_ENV_VAR);
    }

    // Step 1: All three present (Keyring = "k1", Stdin = "s1", Env = "e1")
    // Tier 1 (Keyring) must dominate
    let k_pass = SecretString::new("tier1-keyring-priority".to_string());
    OsKeyring::set(&k_pass).unwrap();
    unsafe {
        std::env::set_var(PASSPHRASE_ENV_VAR, "tier2-env-priority");
    }

    let resolved = OsKeyring::resolve(false, Some("tier2-stdin-priority")).unwrap();
    assert_eq!(resolved.source, PassphraseSource::OsKeyring);
    assert_eq!(resolved.secret.expose_secret(), "tier1-keyring-priority");

    // Step 2: Empty Keyring, Stdin and Env present
    // Tier 2 Stdin must dominate Env
    OsKeyring::clear_mock();
    assert!(OsKeyring::get().unwrap().is_none());

    let resolved = OsKeyring::resolve(false, Some("tier2-stdin-priority\n")).unwrap();
    assert_eq!(resolved.source, PassphraseSource::StdinPipe);
    assert_eq!(resolved.secret.expose_secret(), "tier2-stdin-priority");

    // Step 3: Empty Keyring, Stdin is None, Env is present
    // Tier 2 Env must take effect
    let resolved = OsKeyring::resolve(false, None).unwrap();
    assert_eq!(resolved.source, PassphraseSource::EnvVar);
    assert_eq!(resolved.secret.expose_secret(), "tier2-env-priority");

    // Step 4: Empty Keyring, Stdin is whitespace/newline, Env is present
    // Empty Stdin falls through to Env
    let resolved = OsKeyring::resolve(false, Some("\r\n")).unwrap();
    assert_eq!(resolved.source, PassphraseSource::EnvVar);
    assert_eq!(resolved.secret.expose_secret(), "tier2-env-priority");

    // Step 5: Clean env var; empty Keyring, Stdin present
    unsafe {
        std::env::remove_var(PASSPHRASE_ENV_VAR);
    }
    let resolved = OsKeyring::resolve(false, Some("only-stdin-provided")).unwrap();
    assert_eq!(resolved.source, PassphraseSource::StdinPipe);
    assert_eq!(resolved.secret.expose_secret(), "only-stdin-provided");

    // Step 6: Empty Keyring, empty Stdin, empty Env, non-interactive
    // Must immediately fail with exit code 4
    let err = OsKeyring::resolve(false, None).unwrap_err();
    assert!(matches!(
        err,
        KeyringError::PassphraseRequiredInNonInteractiveMode
    ));
    assert_eq!(err.exit_code(), 4);
}

#[test]
fn test_empirical_whitespace_and_newline_trimming_semantics() {
    let _guard = TestKeyringGuard::new();

    unsafe {
        std::env::remove_var(PASSPHRASE_ENV_VAR);
    }

    // Windows CRLF
    let resolved = OsKeyring::resolve(false, Some("crlf-passphrase\r\n")).unwrap();
    assert_eq!(resolved.secret.expose_secret(), "crlf-passphrase");

    // Unix LF
    let resolved = OsKeyring::resolve(false, Some("lf-passphrase\n")).unwrap();
    assert_eq!(resolved.secret.expose_secret(), "lf-passphrase");

    // Multiple trailing newlines
    let resolved = OsKeyring::resolve(false, Some("multi-newline-pass\n\r\n\n")).unwrap();
    assert_eq!(resolved.secret.expose_secret(), "multi-newline-pass");

    // Spaces inside passphrase must be preserved (e.g. multi-word passphrase)
    let resolved = OsKeyring::resolve(false, Some("correct horse battery staple\n")).unwrap();
    assert_eq!(
        resolved.secret.expose_secret(),
        "correct horse battery staple"
    );

    // Leading spaces must be preserved
    let resolved = OsKeyring::resolve(false, Some("  space-prefixed\n")).unwrap();
    assert_eq!(resolved.secret.expose_secret(), "  space-prefixed");

    // Environment variable trailing newlines trimmed as well
    unsafe {
        std::env::set_var(PASSPHRASE_ENV_VAR, "env-with-trailing-newline\r\n");
    }
    let resolved = OsKeyring::resolve(false, None).unwrap();
    assert_eq!(resolved.secret.expose_secret(), "env-with-trailing-newline");

    unsafe {
        std::env::remove_var(PASSPHRASE_ENV_VAR);
    }
}

// 5. Lifecycle and Redaction Security Tests
#[test]
fn test_empirical_keyring_lifecycle_transitions() {
    let _guard = TestKeyringGuard::new();

    assert!(OsKeyring::get().unwrap().is_none());

    let s1 = SecretString::new("initial-key".to_string());
    OsKeyring::set(&s1).unwrap();
    assert_eq!(
        OsKeyring::get().unwrap().unwrap().expose_secret(),
        "initial-key"
    );

    // Overwrite
    let s2 = SecretString::new("overwritten-key".to_string());
    OsKeyring::set(&s2).unwrap();
    assert_eq!(
        OsKeyring::get().unwrap().unwrap().expose_secret(),
        "overwritten-key"
    );

    // Delete
    OsKeyring::delete().unwrap();
    assert!(OsKeyring::get().unwrap().is_none());

    // Idempotent delete
    assert!(OsKeyring::delete().is_ok());
    assert!(OsKeyring::get().unwrap().is_none());

    // Clear mock
    OsKeyring::set(&s1).unwrap();
    assert!(OsKeyring::get().unwrap().is_some());
    OsKeyring::clear_mock();
    assert!(OsKeyring::get().unwrap().is_none());
}

#[test]
fn test_empirical_resolved_passphrase_redacted_debug() {
    let resolved = ResolvedPassphrase {
        secret: SecretString::new("super-sensitive-unrevealed-password".to_string()),
        source: PassphraseSource::OsKeyring,
    };

    let debug_out = format!("{:?}", resolved);
    assert!(debug_out.contains("[REDACTED]"));
    assert!(!debug_out.contains("super-sensitive-unrevealed-password"));
}


#[test]
fn test_empirical_concurrency_50_threads_chaos_stampede() {
    let _guard = TestKeyringGuard::new();

    const THREAD_COUNT: usize = 50;
    const ITERATIONS: usize = 200;

    let barrier = Arc::new(Barrier::new(THREAD_COUNT));
    let mut handles = Vec::with_capacity(THREAD_COUNT);

    for thread_id in 0..THREAD_COUNT {
        let b = Arc::clone(&barrier);
        let handle = thread::spawn(move || {
            b.wait();

            for i in 0..ITERATIONS {
                match thread_id % 5 {
                    0 => {
                        let pass = SecretString::new(format!("chaos-pass-{}-{}", thread_id, i));
                        let _ = OsKeyring::set(&pass);
                    }
                    1 => {
                        let _ = OsKeyring::get();
                    }
                    2 => {
                        let _ = OsKeyring::delete();
                    }
                    3 => {
                        let _ = OsKeyring::resolve(false, Some("stdin-concurrent-input\n"));
                    }
                    _ => {
                        let _ = OsKeyring::resolve(false, None);
                    }
                }
            }
        });
        handles.push(handle);
    }

    for h in handles {
        h.join()
            .expect("All 50 chaos threads must complete without panic or deadlock");
    }

    // Post-chaos health check
    let health_secret = SecretString::new("post-chaos-health-check".to_string());
    OsKeyring::set(&health_secret).unwrap();
    assert_eq!(
        OsKeyring::get().unwrap().unwrap().expose_secret(),
        "post-chaos-health-check"
    );
    OsKeyring::delete().unwrap();
    assert!(OsKeyring::get().unwrap().is_none());
}


#[test]
fn test_empirical_multibyte_unicode_and_large_passphrase() {
    let _guard = TestKeyringGuard::new();

    unsafe {
        std::env::remove_var(PASSPHRASE_ENV_VAR);
    }

    // Multibyte Unicode in Stdin
    let unicode_pass = "\u{1F512}-secret-passphrase-symbols-\u{1F6E1}\u{FE0F}-test!@#$%^&*()_+";
    let input_with_newline = format!("{}\r\n", unicode_pass);
    let resolved = OsKeyring::resolve(false, Some(&input_with_newline)).unwrap();
    assert_eq!(resolved.source, PassphraseSource::StdinPipe);
    assert_eq!(resolved.secret.expose_secret(), unicode_pass);

    // Multibyte Unicode in Keyring
    let unicode_secret = SecretString::new(unicode_pass.to_string());
    OsKeyring::set(&unicode_secret).unwrap();
    let fetched = OsKeyring::get().unwrap().unwrap();
    assert_eq!(fetched.expose_secret(), unicode_pass);

    // 64 KB Large Passphrase
    let large_pass = "a".repeat(65536);
    let large_secret = SecretString::new(large_pass.clone());
    OsKeyring::set(&large_secret).unwrap();
    let fetched_large = OsKeyring::get().unwrap().unwrap();
    assert_eq!(fetched_large.expose_secret(), &large_pass);
}

#[test]
fn test_empirical_passphrase_source_enum_and_exit_codes() {
    assert_eq!(PassphraseSource::OsKeyring, PassphraseSource::OsKeyring);
    assert_ne!(PassphraseSource::OsKeyring, PassphraseSource::StdinPipe);
    assert_ne!(PassphraseSource::EnvVar, PassphraseSource::TerminalPrompt);

    // Exit code mapping assertions
    let err_non_interactive = KeyringError::PassphraseRequiredInNonInteractiveMode;
    assert_eq!(err_non_interactive.exit_code(), 4);

    let err_prompt = KeyringError::PromptCancelled;
    assert_eq!(err_prompt.exit_code(), 4);

    let err_backend = KeyringError::BackendError("test".to_string());
    assert_eq!(err_backend.exit_code(), 2);

    let err_io = KeyringError::Io(std::io::Error::other("test"));
    assert_eq!(err_io.exit_code(), 2);
}
