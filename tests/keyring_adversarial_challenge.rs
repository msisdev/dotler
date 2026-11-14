use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use dotler::crypto::{ExposeSecret, SecretString};
use dotler::crypto::{KeyringError, OsKeyring, PASSPHRASE_ENV_VAR, PassphraseSource};

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
