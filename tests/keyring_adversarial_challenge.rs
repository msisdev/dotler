use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use dotler::crypto::{ExposeSecret, SecretString};
use dotler::crypto::{
    KeyringError, OsKeyring, PASSPHRASE_ENV_VAR, PassphraseSource, ResolvedPassphrase,
};

static GLOBAL_TEST_MUTEX: Mutex<()> = Mutex::new(());

struct TestKeyringLock<'a> {
    _lock: std::sync::MutexGuard<'a, ()>,
}

impl<'a> TestKeyringLock<'a> {
    fn acquire() -> Self {
        let lock = GLOBAL_TEST_MUTEX.lock().unwrap();
        OsKeyring::enable_mock();
        OsKeyring::clear_mock();
        Self { _lock: lock }
    }
}

impl<'a> Drop for TestKeyringLock<'a> {
    fn drop(&mut self) {
        OsKeyring::clear_mock();
        OsKeyring::enable_mock();
    }
}

fn current_test_binary() -> PathBuf {
    std::env::current_exe().expect("current test binary path must resolve")
}

// Subprocess entry points for headless and non-interactive isolation testing
#[test]
fn helper_headless_dbus_absent_process() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--role-headless-dbus-absent") {
        OsKeyring::disable_mock();

        // When mock is disabled on headless systems lacking D-Bus / Secret Service daemon,
        // OsKeyring::get() must return Ok(None) without panicking or hanging.
        let get_res = OsKeyring::get();
        match get_res {
            Ok(None) => {}
            Ok(Some(_)) => {
                // In case a live desktop session daemon is running on test host,
                // Ok(Some) is also a valid Ok response, but it must not be an Err or panic.
            }
            Err(e) => {
                eprintln!("Unexpected failure in headless get: {:?}", e);
                std::process::exit(1);
            }
        }

        // Resolving with stdin pipe in headless environment must succeed immediately
        let resolve_res = OsKeyring::resolve(false, Some("headless-pipe-secret\n"));
        match resolve_res {
            Ok(resolved) => {
                if resolved.source != PassphraseSource::StdinPipe {
                    eprintln!("Expected StdinPipe source, got: {:?}", resolved.source);
                    std::process::exit(2);
                }
                if resolved.secret.expose_secret() != "headless-pipe-secret" {
                    eprintln!("Password content mismatch");
                    std::process::exit(3);
                }
            }
            Err(e) => {
                eprintln!("Unexpected error resolving via stdin in headless: {:?}", e);
                std::process::exit(4);
            }
        }

        std::process::exit(0);
    }
}

#[test]
fn helper_non_interactive_closed_stdin_process() {
    let args: Vec<String> = std::env::args().collect();
    if args
        .iter()
        .any(|a| a == "--role-non-interactive-closed-stdin")
    {
        OsKeyring::enable_mock();
        OsKeyring::clear_mock();

        unsafe {
            std::env::remove_var(PASSPHRASE_ENV_VAR);
        }

        let start = Instant::now();
        let res = OsKeyring::resolve(false, None);
        let elapsed = start.elapsed();

        if elapsed > Duration::from_millis(500) {
            eprintln!("Resolve took too long ({:?}), possible hang!", elapsed);
            std::process::exit(10);
        }

        match res {
            Err(KeyringError::PassphraseRequiredInNonInteractiveMode) => {
                std::process::exit(4);
            }
            other => {
                eprintln!(
                    "Expected PassphraseRequiredInNonInteractiveMode, got: {:?}",
                    other
                );
                std::process::exit(1);
            }
        }
    }
}

// 1. Concurrency Stress Tests
#[test]
fn test_empirical_concurrency_stress_24_threads_stampede() {
    let _guard = TestKeyringLock::acquire();

    const THREAD_COUNT: usize = 24;
    const ITERATIONS_PER_THREAD: usize = 250;

    let barrier = Arc::new(Barrier::new(THREAD_COUNT));
    let stop_signal = Arc::new(AtomicBool::new(false));
    let successful_gets = Arc::new(AtomicUsize::new(0));
    let successful_sets = Arc::new(AtomicUsize::new(0));
    let successful_deletes = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::with_capacity(THREAD_COUNT);

    for thread_id in 0..THREAD_COUNT {
        let b = Arc::clone(&barrier);
        let stop = Arc::clone(&stop_signal);
        let gets = Arc::clone(&successful_gets);
        let sets = Arc::clone(&successful_sets);
        let dels = Arc::clone(&successful_deletes);

        let handle = thread::spawn(move || {
            // Synchronize all 24 threads to start at the exact same instant
            b.wait();

            for i in 0..ITERATIONS_PER_THREAD {
                if stop.load(Ordering::Relaxed) {
                    break;
                }

                match thread_id % 4 {
                    0 | 1 => {
                        // Setter threads (8 threads)
                        let secret = SecretString::new(format!("secret-t{}-iter{}", thread_id, i));
                        match OsKeyring::set(&secret) {
                            Ok(()) => {
                                sets.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(e) => {
                                panic!(
                                    "Thread {} failed set on iteration {}: {:?}",
                                    thread_id, i, e
                                );
                            }
                        }
                    }
                    2 => {
                        // Getter threads (6 threads)
                        match OsKeyring::get() {
                            Ok(Some(s)) => {
                                assert!(!s.expose_secret().is_empty());
                                gets.fetch_add(1, Ordering::Relaxed);
                            }
                            Ok(None) => {
                                gets.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(e) => {
                                panic!(
                                    "Thread {} failed get on iteration {}: {:?}",
                                    thread_id, i, e
                                );
                            }
                        }
                    }
                    _ => {
                        // Deleter / status threads (6 threads)
                        if i % 3 == 0 {
                            match OsKeyring::delete() {
                                Ok(()) => {
                                    dels.fetch_add(1, Ordering::Relaxed);
                                }
                                Err(e) => {
                                    panic!(
                                        "Thread {} failed delete on iteration {}: {:?}",
                                        thread_id, i, e
                                    );
                                }
                            }
                        } else {
                            assert!(OsKeyring::is_mock_enabled());
                        }
                    }
                }
            }
        });

        handles.push(handle);
    }

    for h in handles {
        h.join()
            .expect("All 24 worker threads must join cleanly without panics");
    }

    assert!(successful_sets.load(Ordering::SeqCst) > 0);
    assert!(successful_gets.load(Ordering::SeqCst) > 0);
    assert!(successful_deletes.load(Ordering::SeqCst) > 0);

    // Verify mock remains completely healthy after heavy contention
    let final_secret = SecretString::new("post-concurrency-verification-passphrase".to_string());
    OsKeyring::set(&final_secret).expect("Post-stampede set must succeed");
    let fetched = OsKeyring::get().expect("Post-stampede get must succeed");
    assert_eq!(
        fetched.as_ref().map(|s| s.expose_secret().as_str()),
        Some("post-concurrency-verification-passphrase")
    );
    OsKeyring::delete().expect("Post-stampede delete must succeed");
    assert!(OsKeyring::get().unwrap().is_none());
}

#[test]
fn test_empirical_concurrency_32_threads_mixed_data_integrity() {
    let _guard = TestKeyringLock::acquire();

    const THREAD_COUNT: usize = 32;
    const ITERATIONS: usize = 120;

    let barrier = Arc::new(Barrier::new(THREAD_COUNT));
    let mut handles = Vec::with_capacity(THREAD_COUNT);

    for thread_id in 0..THREAD_COUNT {
        let b = Arc::clone(&barrier);
        let handle = thread::spawn(move || {
            b.wait();

            for i in 0..ITERATIONS {
                if thread_id % 2 == 0 {
                    // Writer
                    let pass =
                        SecretString::new(format!("shared-concurrency-key-t{}-i{}", thread_id, i));
                    OsKeyring::set(&pass).unwrap();
                } else {
                    // Reader
                    let res = OsKeyring::get().unwrap();
                    if let Some(secret) = res {
                        let text = secret.expose_secret();
                        assert!(
                            text.starts_with("shared-concurrency-key-"),
                            "Secret data corrupted under concurrency: {}",
                            text
                        );
                    }
                }
            }
        });
        handles.push(handle);
    }

    for h in handles {
        h.join().expect("Worker threads must not panic");
    }
}

// 2. Headless Execution Tests
#[test]
fn test_empirical_headless_execution_fallback_when_dbus_absent() {
    let binary = current_test_binary();
    let mut cmd = Command::new(&binary);
    cmd.arg("helper_headless_dbus_absent_process")
        .arg("--exact")
        .arg("--nocapture")
        .arg("--")
        .arg("--role-headless-dbus-absent")
        .env_remove("DBUS_SESSION_BUS_ADDRESS")
        .env_remove("XDG_RUNTIME_DIR")
        .env_remove("DISPLAY")
        .env_remove("WAYLAND_DISPLAY")
        .env("DBUS_SESSION_BUS_ADDRESS", "")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let start = Instant::now();
    let output = cmd
        .output()
        .expect("Failed to execute headless test subprocess");
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_secs(5),
        "Headless execution took too long: {:?}",
        elapsed
    );

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        panic!(
            "Headless subprocess failed with code {:?}. stdout: {}, stderr: {}",
            output.status.code(),
            stdout,
            stderr
        );
    }
}

#[test]
fn test_empirical_in_process_headless_fallback_returns_none() {
    let _guard = TestKeyringLock::acquire();
    // When mock is disabled, running on any host should gracefully return Ok
    // without crashing or panicking.
    OsKeyring::disable_mock();
    assert!(!OsKeyring::is_mock_enabled());

    let res = OsKeyring::get();
    assert!(
        res.is_ok(),
        "OsKeyring::get() must not return Err when daemon missing"
    );
    if let Ok(Some(ref secret)) = res
        && secret.expose_secret() == "shared_final_pass_000"
    {
        let _ = OsKeyring::delete();
    }

    // Re-enable mock for subsequent tests
    OsKeyring::enable_mock();
    assert!(OsKeyring::is_mock_enabled());
}

// 3. Non-Interactive Safety Tests
#[test]
fn test_empirical_non_interactive_never_hangs_and_exit_code_4() {
    let _guard = TestKeyringLock::acquire();

    unsafe {
        std::env::remove_var(PASSPHRASE_ENV_VAR);
    }

    // Matrix of non-interactive inputs where passphrase is not supplied:
    let empty_inputs: Vec<Option<&str>> =
        vec![None, Some(""), Some("\n"), Some("\r\n"), Some("\r\n\n\r\n")];

    for input in empty_inputs {
        let start = Instant::now();
        let result = OsKeyring::resolve(false, input);
        let elapsed = start.elapsed();

        assert!(
            elapsed < Duration::from_millis(50),
            "Non-interactive resolve took {:?}, must return immediately without blocking",
            elapsed
        );

        match result {
            Err(KeyringError::PassphraseRequiredInNonInteractiveMode) => {
                assert_eq!(
                    KeyringError::PassphraseRequiredInNonInteractiveMode.exit_code(),
                    4
                );
            }
            other => {
                panic!(
                    "Expected PassphraseRequiredInNonInteractiveMode for input {:?}, got {:?}",
                    input, other
                );
            }
        }
    }
}

#[test]
fn test_empirical_non_interactive_empty_env_var_falls_through_to_error() {
    let _guard = TestKeyringLock::acquire();

    let empty_env_values = ["", "\n", "\r\n", "\r\n\n"];

    for val in empty_env_values {
        unsafe {
            std::env::set_var(PASSPHRASE_ENV_VAR, val);
        }

        let start = Instant::now();
        let result = OsKeyring::resolve(false, None);
        let elapsed = start.elapsed();

        assert!(elapsed < Duration::from_millis(50));
        assert!(matches!(
            result,
            Err(KeyringError::PassphraseRequiredInNonInteractiveMode)
        ));
        if let Err(e) = result {
            assert_eq!(e.exit_code(), 4);
        }
    }

    unsafe {
        std::env::remove_var(PASSPHRASE_ENV_VAR);
    }
}

#[test]
fn test_empirical_subprocess_non_interactive_closed_stdin_exit_code_4() {
    let binary = current_test_binary();
    let mut cmd = Command::new(&binary);
    cmd.arg("helper_non_interactive_closed_stdin_process")
        .arg("--exact")
        .arg("--nocapture")
        .arg("--")
        .arg("--role-non-interactive-closed-stdin")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let start = Instant::now();
    let output = cmd.output().expect("Execute child process");
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_secs(3),
        "Subprocess non-interactive hang detected! Elapsed: {:?}",
        elapsed
    );
    assert_eq!(output.status.code(), Some(4));
}

// 4. Supply Cascade Precedence Tests
#[test]
fn test_empirical_supply_cascade_precedence_full_matrix() {
    let _guard = TestKeyringLock::acquire();

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
    let _guard = TestKeyringLock::acquire();

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
    let _guard = TestKeyringLock::acquire();

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

// Helper for malformed dbus test
#[test]
fn helper_headless_malformed_dbus_process() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--role-headless-malformed-dbus") {
        OsKeyring::disable_mock();

        // 1. get() must gracefully return Ok(None) without panicking
        let res = OsKeyring::get();
        match res {
            Ok(None) => {}
            Ok(Some(_)) => {}
            Err(e) => {
                eprintln!("Unexpected error on malformed D-Bus get: {:?}", e);
                std::process::exit(1);
            }
        }

        // 2. set() without a daemon should fail with BackendError
        let secret = SecretString::new("test-pass".to_string());
        let set_res = OsKeyring::set(&secret);
        match set_res {
            Err(KeyringError::BackendError(_)) => {
                // Expected failure when daemon is unreachable
            }
            Ok(()) => {
                // In case platform mock or desktop daemon intercepted it
            }
            Err(other) => {
                eprintln!("Unexpected error type on set: {:?}", other);
                std::process::exit(2);
            }
        }

        std::process::exit(0);
    }
}

#[test]
fn test_empirical_concurrency_50_threads_chaos_stampede() {
    let _guard = TestKeyringLock::acquire();

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
fn test_empirical_headless_malformed_dbus_socket_address() {
    let binary = current_test_binary();
    let mut cmd = Command::new(&binary);
    cmd.arg("helper_headless_malformed_dbus_process")
        .arg("--exact")
        .arg("--nocapture")
        .arg("--")
        .arg("--role-headless-malformed-dbus")
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            "unix:path=/dev/null/nonexistent_socket_test.sock",
        )
        .env_remove("DISPLAY")
        .env_remove("WAYLAND_DISPLAY")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let start = Instant::now();
    let output = cmd.output().expect("Execute malformed dbus child");
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_secs(5),
        "Malformed D-Bus execution hung: {:?}",
        elapsed
    );
    assert!(
        output.status.success(),
        "Child process failed: stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_empirical_multibyte_unicode_and_large_passphrase() {
    let _guard = TestKeyringLock::acquire();

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
