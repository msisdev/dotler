use crate::crypto::{ExposeSecret, SecretString};
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

pub const KEYRING_SERVICE_NAME: &str = "dotler";
pub const KEYRING_DEFAULT_USER: &str = "default";
pub const PASSPHRASE_ENV_VAR: &str = "DOTLER_PASSPHRASE";

#[derive(Debug)]
pub enum KeyringError {
    BackendError(String),
    PassphraseRequiredInNonInteractiveMode,
    PromptCancelled,
    Io(std::io::Error),
}

impl std::fmt::Display for KeyringError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BackendError(msg) => write!(f, "Keyring backend error: {msg}"),
            Self::PassphraseRequiredInNonInteractiveMode => write!(
                f,
                "Passphrase required in non-interactive mode. Please register password using 'dotler key set' or export DOTLER_PASSPHRASE"
            ),
            Self::PromptCancelled => write!(f, "Terminal prompt cancelled or unavailable"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for KeyringError {}

impl From<std::io::Error> for KeyringError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl KeyringError {
    pub fn exit_code(&self) -> i32 {
        match self {
            KeyringError::PassphraseRequiredInNonInteractiveMode => 4,
            KeyringError::PromptCancelled => 4,
            _ => 2,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassphraseSource {
    OsKeyring,
    EnvVar,
    StdinPipe,
    TerminalPrompt,
}

pub struct ResolvedPassphrase {
    pub secret: SecretString,
    pub source: PassphraseSource,
}

impl std::fmt::Debug for ResolvedPassphrase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedPassphrase")
            .field("secret", &"[REDACTED]")
            .field("source", &self.source)
            .finish()
    }
}

static MOCK_KEYRING: Mutex<Option<HashMap<String, String>>> = Mutex::new(None);
static MOCK_EXPLICITLY_DISABLED: AtomicBool = AtomicBool::new(false);
static MOCK_PROMPT_QUEUE: Mutex<VecDeque<String>> = Mutex::new(VecDeque::new());

pub struct OsKeyring;

impl OsKeyring {
    pub fn enable_mock() {
        let mut lock = MOCK_KEYRING.lock().unwrap();
        MOCK_EXPLICITLY_DISABLED.store(false, Ordering::SeqCst);
        *lock = Some(HashMap::new());
    }

    pub fn disable_mock() {
        let mut lock = MOCK_KEYRING.lock().unwrap();
        MOCK_EXPLICITLY_DISABLED.store(true, Ordering::SeqCst);
        *lock = None;
        Self::clear_mock_prompt_replies();
    }

    fn ensure_env_mock(lock: &mut Option<HashMap<String, String>>) {
        if lock.is_none()
            && !MOCK_EXPLICITLY_DISABLED.load(Ordering::SeqCst)
            && std::env::var_os("DOTLER_MOCK_KEYRING").is_some()
        {
            *lock = Some(HashMap::new());
        }
    }

    pub fn clear_mock() {
        let mut lock = MOCK_KEYRING.lock().unwrap();
        if let Some(map) = lock.as_mut() {
            map.clear();
        }
        Self::clear_mock_prompt_replies();
    }

    pub fn push_mock_prompt_reply(reply: impl Into<String>) {
        MOCK_PROMPT_QUEUE.lock().unwrap().push_back(reply.into());
    }

    pub fn clear_mock_prompt_replies() {
        MOCK_PROMPT_QUEUE.lock().unwrap().clear();
    }

    fn take_mock_prompt_reply() -> Option<String> {
        MOCK_PROMPT_QUEUE.lock().unwrap().pop_front()
    }

    pub fn is_mock_enabled() -> bool {
        let mut lock = MOCK_KEYRING.lock().unwrap();
        Self::ensure_env_mock(&mut lock);
        lock.is_some()
    }

    pub fn get() -> Result<Option<SecretString>, KeyringError> {
        let mut lock = MOCK_KEYRING.lock().unwrap();
        Self::ensure_env_mock(&mut lock);
        if let Some(map) = lock.as_ref() {
            let key = format!("{}:{}", KEYRING_SERVICE_NAME, KEYRING_DEFAULT_USER);
            return Ok(map.get(&key).map(|v| SecretString::new(v.clone())));
        }
        drop(lock);

        Ok(platform::get_password()
            .ok()
            .flatten()
            .map(SecretString::new))
    }

    pub fn set(secret: &SecretString) -> Result<(), KeyringError> {
        let mut lock = MOCK_KEYRING.lock().unwrap();
        Self::ensure_env_mock(&mut lock);
        if let Some(map) = lock.as_mut() {
            let key = format!("{}:{}", KEYRING_SERVICE_NAME, KEYRING_DEFAULT_USER);
            map.insert(key, secret.expose_secret().to_string());
            return Ok(());
        }
        drop(lock);

        platform::set_password(secret.expose_secret())
    }

    pub fn delete() -> Result<(), KeyringError> {
        let mut lock = MOCK_KEYRING.lock().unwrap();
        Self::ensure_env_mock(&mut lock);
        if let Some(map) = lock.as_mut() {
            let key = format!("{}:{}", KEYRING_SERVICE_NAME, KEYRING_DEFAULT_USER);
            map.remove(&key);
            return Ok(());
        }
        drop(lock);

        platform::delete_password()
    }

    pub fn resolve(
        is_interactive: bool,
        stdin_passphrase: Option<&str>,
    ) -> Result<ResolvedPassphrase, KeyringError> {
        // Tier 1: OS Keyring
        if let Ok(Some(secret)) = Self::get() {
            return Ok(ResolvedPassphrase {
                secret,
                source: PassphraseSource::OsKeyring,
            });
        }

        // Tier 2: Stdin pipe or Environment variable
        if let Some(pass) = stdin_passphrase {
            let trimmed = pass.trim_end_matches(['\r', '\n']);
            if !trimmed.is_empty() {
                return Ok(ResolvedPassphrase {
                    secret: SecretString::new(trimmed.to_string()),
                    source: PassphraseSource::StdinPipe,
                });
            }
        }

        if let Ok(env_pass) = std::env::var(PASSPHRASE_ENV_VAR) {
            let trimmed = env_pass.trim_end_matches(['\r', '\n']);
            if !trimmed.is_empty() {
                return Ok(ResolvedPassphrase {
                    secret: SecretString::new(trimmed.to_string()),
                    source: PassphraseSource::EnvVar,
                });
            }
        }

        // Tier 3: TTY prompt (only in interactive mode)
        if !is_interactive {
            return Err(KeyringError::PassphraseRequiredInNonInteractiveMode);
        }

        Self::prompt_passphrase_with_message("Enter dotler vault passphrase: ")
    }

    /// Prompts the user on the interactive terminal with echo disabled across Unix and Windows.
    pub fn prompt_passphrase_with_message(
        prompt: &str,
    ) -> Result<ResolvedPassphrase, KeyringError> {
        if let Some(mock_reply) = Self::take_mock_prompt_reply() {
            let trimmed = mock_reply.trim_end_matches(['\r', '\n']);
            if trimmed.is_empty() {
                return Err(KeyringError::PromptCancelled);
            }
            return Ok(ResolvedPassphrase {
                secret: SecretString::new(trimmed.to_string()),
                source: PassphraseSource::TerminalPrompt,
            });
        }

        match rpassword::prompt_password(prompt) {
            Ok(line) => {
                let trimmed = line.trim_end_matches(['\r', '\n']);
                if trimmed.is_empty() {
                    Err(KeyringError::PromptCancelled)
                } else {
                    Ok(ResolvedPassphrase {
                        secret: SecretString::new(trimmed.to_string()),
                        source: PassphraseSource::TerminalPrompt,
                    })
                }
            }
            Err(_) => Err(KeyringError::PromptCancelled),
        }
    }
}

mod platform {
    use super::{KEYRING_DEFAULT_USER, KEYRING_SERVICE_NAME, KeyringError};

    #[cfg(target_os = "macos")]
    pub fn get_password() -> Result<Option<String>, KeyringError> {
        let out = std::process::Command::new("/usr/bin/security")
            .args([
                "find-generic-password",
                "-s",
                KEYRING_SERVICE_NAME,
                "-a",
                KEYRING_DEFAULT_USER,
                "-w",
            ])
            .output()
            .map_err(|e| KeyringError::BackendError(e.to_string()))?;
        if !out.status.success() {
            return Ok(None);
        }
        let pass = String::from_utf8_lossy(&out.stdout)
            .trim_end_matches(['\r', '\n'])
            .to_string();
        Ok(if pass.is_empty() { None } else { Some(pass) })
    }

    #[cfg(target_os = "macos")]
    pub fn set_password(secret: &str) -> Result<(), KeyringError> {
        let out = std::process::Command::new("/usr/bin/security")
            .args([
                "add-generic-password",
                "-U",
                "-s",
                KEYRING_SERVICE_NAME,
                "-a",
                KEYRING_DEFAULT_USER,
                "-w",
                secret,
            ])
            .output()
            .map_err(|e| KeyringError::BackendError(e.to_string()))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(KeyringError::BackendError(
                String::from_utf8_lossy(&out.stderr).trim().to_string(),
            ))
        }
    }

    #[cfg(target_os = "macos")]
    pub fn delete_password() -> Result<(), KeyringError> {
        let _ = std::process::Command::new("/usr/bin/security")
            .args([
                "delete-generic-password",
                "-s",
                KEYRING_SERVICE_NAME,
                "-a",
                KEYRING_DEFAULT_USER,
            ])
            .output()
            .map_err(|e| KeyringError::BackendError(e.to_string()))?;
        Ok(())
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    pub fn get_password() -> Result<Option<String>, KeyringError> {
        if std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_none() {
            return Ok(None);
        }
        let out = match std::process::Command::new("secret-tool")
            .args([
                "lookup",
                "service",
                KEYRING_SERVICE_NAME,
                "username",
                KEYRING_DEFAULT_USER,
            ])
            .output()
        {
            Ok(o) => o,
            Err(_) => return Ok(None),
        };
        if !out.status.success() {
            return Ok(None);
        }
        let pass = String::from_utf8_lossy(&out.stdout)
            .trim_end_matches(['\r', '\n'])
            .to_string();
        Ok(if pass.is_empty() { None } else { Some(pass) })
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    pub fn set_password(secret: &str) -> Result<(), KeyringError> {
        use std::io::Write;
        use std::process::Stdio;
        if std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_none() {
            return Err(KeyringError::BackendError(
                "DBUS_SESSION_BUS_ADDRESS is not set".to_string(),
            ));
        }
        let mut child = std::process::Command::new("secret-tool")
            .args([
                "store",
                "--label=dotler",
                "service",
                KEYRING_SERVICE_NAME,
                "username",
                KEYRING_DEFAULT_USER,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| KeyringError::BackendError(format!("secret-tool unavailable: {e}")))?;
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(secret.as_bytes());
        }
        let out = child
            .wait_with_output()
            .map_err(|e| KeyringError::BackendError(e.to_string()))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(KeyringError::BackendError(
                String::from_utf8_lossy(&out.stderr).trim().to_string(),
            ))
        }
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    pub fn delete_password() -> Result<(), KeyringError> {
        if std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_none() {
            return Err(KeyringError::BackendError(
                "DBUS_SESSION_BUS_ADDRESS is not set".to_string(),
            ));
        }
        let _ = std::process::Command::new("secret-tool")
            .args([
                "clear",
                "service",
                KEYRING_SERVICE_NAME,
                "username",
                KEYRING_DEFAULT_USER,
            ])
            .output()
            .map_err(|e| KeyringError::BackendError(format!("secret-tool unavailable: {e}")))?;
        Ok(())
    }

    #[cfg(target_os = "windows")]
    pub fn get_password() -> Result<Option<String>, KeyringError> {
        win_cred::read()
    }

    #[cfg(target_os = "windows")]
    pub fn set_password(secret: &str) -> Result<(), KeyringError> {
        win_cred::write(secret)
    }

    #[cfg(target_os = "windows")]
    pub fn delete_password() -> Result<(), KeyringError> {
        win_cred::delete()
    }

    #[cfg(target_os = "windows")]
    mod win_cred {
        use super::{KEYRING_DEFAULT_USER, KEYRING_SERVICE_NAME, KeyringError};
        use std::ffi::c_void;

        const CRED_TYPE_GENERIC: u32 = 1;
        const CRED_PERSIST_LOCAL_MACHINE: u32 = 2;

        #[repr(C)]
        struct CredentialW {
            flags: u32,
            cred_type: u32,
            target_name: *mut u16,
            comment: *mut u16,
            last_written: u64,
            credential_blob_size: u32,
            credential_blob: *mut u8,
            persist: u32,
            attribute_count: u32,
            attributes: *mut c_void,
            target_alias: *mut u16,
            user_name: *mut u16,
        }

        #[link(name = "Advapi32")]
        unsafe extern "system" {
            fn CredReadW(
                target_name: *const u16,
                cred_type: u32,
                flags: u32,
                credential: *mut *mut CredentialW,
            ) -> i32;
            fn CredWriteW(credential: *const CredentialW, flags: u32) -> i32;
            fn CredDeleteW(target_name: *const u16, cred_type: u32, flags: u32) -> i32;
            fn CredFree(buffer: *mut c_void);
        }

        fn to_wide(s: &str) -> Vec<u16> {
            s.encode_utf16().chain(std::iter::once(0)).collect()
        }

        fn target_name() -> Vec<u16> {
            to_wide(&format!("{KEYRING_DEFAULT_USER}.{KEYRING_SERVICE_NAME}"))
        }

        pub fn read() -> Result<Option<String>, KeyringError> {
            let target = target_name();
            let mut cred_ptr: *mut CredentialW = std::ptr::null_mut();
            let ok = unsafe { CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut cred_ptr) };
            if ok == 0 || cred_ptr.is_null() {
                return Ok(None);
            }
            let pass = unsafe {
                let cred = &*cred_ptr;
                let slice = std::slice::from_raw_parts(
                    cred.credential_blob,
                    cred.credential_blob_size as usize,
                );
                let s = String::from_utf8_lossy(slice).to_string();
                CredFree(cred_ptr.cast());
                s
            };
            Ok(Some(pass))
        }

        pub fn write(secret: &str) -> Result<(), KeyringError> {
            let mut target = target_name();
            let mut user = to_wide(KEYRING_DEFAULT_USER);
            let mut blob = secret.as_bytes().to_vec();
            let cred = CredentialW {
                flags: 0,
                cred_type: CRED_TYPE_GENERIC,
                target_name: target.as_mut_ptr(),
                comment: std::ptr::null_mut(),
                last_written: 0,
                credential_blob_size: blob.len() as u32,
                credential_blob: blob.as_mut_ptr(),
                persist: CRED_PERSIST_LOCAL_MACHINE,
                attribute_count: 0,
                attributes: std::ptr::null_mut(),
                target_alias: std::ptr::null_mut(),
                user_name: user.as_mut_ptr(),
            };
            let ok = unsafe { CredWriteW(&cred, 0) };
            if ok != 0 {
                Ok(())
            } else {
                Err(KeyringError::BackendError(
                    std::io::Error::last_os_error().to_string(),
                ))
            }
        }

        pub fn delete() -> Result<(), KeyringError> {
            let target = target_name();
            unsafe {
                let _ = CredDeleteW(target.as_ptr(), CRED_TYPE_GENERIC, 0);
            }
            Ok(())
        }
    }
}

#[cfg(test)]
pub(crate) static MOCK_KEYRING_TEST_LOCK: Mutex<()> = Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;

    struct MockKeyringGuard<'a> {
        _lock: std::sync::MutexGuard<'a, ()>,
    }

    impl<'a> MockKeyringGuard<'a> {
        fn new() -> Self {
            let lock = MOCK_KEYRING_TEST_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            OsKeyring::enable_mock();
            OsKeyring::clear_mock();
            Self { _lock: lock }
        }
    }

    impl<'a> Drop for MockKeyringGuard<'a> {
        fn drop(&mut self) {
            OsKeyring::clear_mock();
            OsKeyring::disable_mock();
        }
    }

    #[test]
    fn test_mock_keyring_set_get_delete() {
        let _guard = MockKeyringGuard::new();

        assert!(OsKeyring::get().unwrap().is_none());

        let secret = SecretString::new("mock-secret-password".to_string());
        OsKeyring::set(&secret).unwrap();

        let retrieved = OsKeyring::get().unwrap().expect("should find password");
        assert_eq!(retrieved.expose_secret(), "mock-secret-password");

        OsKeyring::delete().unwrap();
        assert!(OsKeyring::get().unwrap().is_none());
    }

    #[test]
    fn test_resolved_passphrase_debug_redacted() {
        let resolved = ResolvedPassphrase {
            secret: SecretString::new("super-secret-pw".to_string()),
            source: PassphraseSource::OsKeyring,
        };
        let debug_str = format!("{:?}", resolved);
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains("super-secret-pw"));
    }

    #[test]
    fn test_passphrase_supply_tier1_keyring() {
        let _guard = MockKeyringGuard::new();

        let secret = SecretString::new("tier1-keyring-pw".to_string());
        OsKeyring::set(&secret).unwrap();

        // Tier 1 should take precedence over env var or stdin
        let resolved = OsKeyring::resolve(false, Some("stdin-pw")).unwrap();
        assert_eq!(resolved.source, PassphraseSource::OsKeyring);
        assert_eq!(resolved.secret.expose_secret(), "tier1-keyring-pw");
    }

    #[test]
    fn test_passphrase_supply_tier2_stdin() {
        let _guard = MockKeyringGuard::new();

        // Stdin provided, keyring empty
        let resolved = OsKeyring::resolve(false, Some("stdin-pw\n")).unwrap();
        assert_eq!(resolved.source, PassphraseSource::StdinPipe);
        assert_eq!(resolved.secret.expose_secret(), "stdin-pw");
    }

    #[test]
    fn test_passphrase_supply_tier2_env() {
        let _guard = MockKeyringGuard::new();

        // No stdin, keyring empty, env var set
        unsafe {
            std::env::set_var(PASSPHRASE_ENV_VAR, "env-variable-pw\n");
        }

        let resolved = OsKeyring::resolve(false, None).unwrap();
        assert_eq!(resolved.source, PassphraseSource::EnvVar);
        assert_eq!(resolved.secret.expose_secret(), "env-variable-pw");

        unsafe {
            std::env::remove_var(PASSPHRASE_ENV_VAR);
        }
    }

    #[test]
    fn test_passphrase_supply_tier3_non_interactive_blocked() {
        let _guard = MockKeyringGuard::new();
        unsafe {
            std::env::remove_var(PASSPHRASE_ENV_VAR);
        }

        // In non-interactive mode with no keyring, no stdin, and no env, it must immediately fail
        let result = OsKeyring::resolve(false, None);
        assert!(matches!(
            result,
            Err(KeyringError::PassphraseRequiredInNonInteractiveMode)
        ));
        if let Err(e) = result {
            assert_eq!(e.exit_code(), 4);
        }
    }

    #[test]
    fn test_keyring_headless_fallback_returns_none() {
        let _lock = MOCK_KEYRING_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // When mock is disabled, running on a headless machine without Secret Service daemon
        // should gracefully return Ok(None) or Ok(Some) if a local daemon happens to be present,
        // but must NEVER panic.
        OsKeyring::disable_mock();
        let result = OsKeyring::get();
        assert!(result.is_ok());
    }
}
