use crate::crypto::{ExposeSecret, SecretString};
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

pub use crate::crypto::passphrase::{
    PassphraseSource, ResolvedPassphrase, get_password, get_password_for_vault,
};

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

    pub(crate) fn take_mock_prompt_reply() -> Option<String> {
        MOCK_PROMPT_QUEUE.lock().unwrap().pop_front()
    }

    pub fn is_mock_enabled() -> bool {
        let mut lock = MOCK_KEYRING.lock().unwrap();
        Self::ensure_env_mock(&mut lock);
        lock.is_some()
    }

    fn normalize_account(account: Option<&str>) -> &str {
        account
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(KEYRING_DEFAULT_USER)
    }

    pub fn get() -> Result<Option<SecretString>, KeyringError> {
        Self::get_account(None)
    }

    pub fn get_for_vault(vault_id: &str) -> Result<Option<SecretString>, KeyringError> {
        Self::get_account(Some(vault_id))
    }

    pub fn get_account(account: Option<&str>) -> Result<Option<SecretString>, KeyringError> {
        let acct = Self::normalize_account(account);
        let mut lock = MOCK_KEYRING.lock().unwrap();
        Self::ensure_env_mock(&mut lock);
        if let Some(map) = lock.as_ref() {
            let key = format!("{KEYRING_SERVICE_NAME}:{acct}");
            return Ok(map.get(&key).map(|v| SecretString::new(v.clone())));
        }
        drop(lock);

        Ok(platform::get_password(acct)
            .ok()
            .flatten()
            .map(SecretString::new))
    }

    pub fn set(secret: &SecretString) -> Result<(), KeyringError> {
        Self::set_account(None, secret)
    }

    pub fn set_for_vault(vault_id: &str, secret: &SecretString) -> Result<(), KeyringError> {
        Self::set_account(Some(vault_id), secret)
    }

    pub fn set_account(account: Option<&str>, secret: &SecretString) -> Result<(), KeyringError> {
        let acct = Self::normalize_account(account);
        let mut lock = MOCK_KEYRING.lock().unwrap();
        Self::ensure_env_mock(&mut lock);
        if let Some(map) = lock.as_mut() {
            let key = format!("{KEYRING_SERVICE_NAME}:{acct}");
            map.insert(key, secret.expose_secret().to_string());
            return Ok(());
        }
        drop(lock);

        platform::set_password(acct, secret.expose_secret())
    }

    /// Stores the secret in the vault-specific keyring slot when `vault_id` is provided,
    /// and populates the default fallback slot if it is currently empty.
    pub fn set_with_fallback(
        vault_id: Option<&str>,
        secret: &SecretString,
    ) -> Result<(), KeyringError> {
        let trimmed = vault_id.map(str::trim).filter(|s| !s.is_empty());
        match trimmed {
            Some(vid) if vid != KEYRING_DEFAULT_USER => {
                Self::set_for_vault(vid, secret)?;
                if Self::get().ok().flatten().is_none() {
                    let _ = Self::set(secret);
                }
                Ok(())
            }
            _ => Self::set(secret),
        }
    }

    pub fn delete() -> Result<(), KeyringError> {
        Self::delete_account(None)
    }

    pub fn delete_for_vault(vault_id: &str) -> Result<(), KeyringError> {
        Self::delete_account(Some(vault_id))
    }

    pub fn delete_account(account: Option<&str>) -> Result<(), KeyringError> {
        let acct = Self::normalize_account(account);
        let mut lock = MOCK_KEYRING.lock().unwrap();
        Self::ensure_env_mock(&mut lock);
        if let Some(map) = lock.as_mut() {
            let key = format!("{KEYRING_SERVICE_NAME}:{acct}");
            map.remove(&key);
            return Ok(());
        }
        drop(lock);

        platform::delete_password(acct)
    }

    /// Removes all stored keyring entries matching `vault_ids` and the default fallback slot.
    pub fn delete_all(vault_ids: &[String]) -> Result<(), KeyringError> {
        let mut lock = MOCK_KEYRING.lock().unwrap();
        Self::ensure_env_mock(&mut lock);
        if let Some(map) = lock.as_mut() {
            let prefix = format!("{KEYRING_SERVICE_NAME}:");
            map.retain(|k, _| !k.starts_with(&prefix));
            return Ok(());
        }
        drop(lock);

        platform::delete_all_passwords(vault_ids)
    }

    /// Returns `true` if a passphrase exists in either the vault-specific slot or default slot.
    pub fn is_ready_for_vault(vault_id: Option<&str>) -> bool {
        if let Some(vid) = vault_id.map(str::trim).filter(|s| !s.is_empty())
            && Self::get_for_vault(vid).ok().flatten().is_some()
        {
            return true;
        }
        Self::get().ok().flatten().is_some()
    }
}

mod platform {
    use super::{KEYRING_DEFAULT_USER, KEYRING_SERVICE_NAME, KeyringError};

    #[cfg(target_os = "macos")]
    pub fn get_password(account: &str) -> Result<Option<String>, KeyringError> {
        let out = std::process::Command::new("/usr/bin/security")
            .args([
                "find-generic-password",
                "-s",
                KEYRING_SERVICE_NAME,
                "-a",
                account,
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
    pub fn set_password(account: &str, secret: &str) -> Result<(), KeyringError> {
        let out = std::process::Command::new("/usr/bin/security")
            .args([
                "add-generic-password",
                "-U",
                "-s",
                KEYRING_SERVICE_NAME,
                "-a",
                account,
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
    pub fn delete_password(account: &str) -> Result<(), KeyringError> {
        let _ = std::process::Command::new("/usr/bin/security")
            .args([
                "delete-generic-password",
                "-s",
                KEYRING_SERVICE_NAME,
                "-a",
                account,
            ])
            .output()
            .map_err(|e| KeyringError::BackendError(e.to_string()))?;
        Ok(())
    }

    #[cfg(target_os = "macos")]
    pub fn delete_all_passwords(vault_ids: &[String]) -> Result<(), KeyringError> {
        delete_password(KEYRING_DEFAULT_USER)?;
        for vid in vault_ids {
            let trimmed = vid.trim();
            if !trimmed.is_empty() && trimmed != KEYRING_DEFAULT_USER {
                delete_password(trimmed)?;
            }
        }
        loop {
            let out = std::process::Command::new("/usr/bin/security")
                .args(["delete-generic-password", "-s", KEYRING_SERVICE_NAME])
                .output()
                .map_err(|e| KeyringError::BackendError(e.to_string()))?;
            if !out.status.success() {
                break;
            }
        }
        Ok(())
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    pub fn get_password(account: &str) -> Result<Option<String>, KeyringError> {
        if std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_none() {
            return Ok(None);
        }
        let Ok(out) = std::process::Command::new("secret-tool")
            .args([
                "lookup",
                "service",
                KEYRING_SERVICE_NAME,
                "username",
                account,
            ])
            .output()
        else {
            return Ok(None);
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
    pub fn set_password(account: &str, secret: &str) -> Result<(), KeyringError> {
        use std::io::Write;
        use std::process::Stdio;
        if std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_none() {
            return Err(KeyringError::BackendError(
                "DBUS_SESSION_BUS_ADDRESS is not set".to_string(),
            ));
        }
        let label = if account == KEYRING_DEFAULT_USER {
            "--label=dotler".to_string()
        } else {
            format!("--label=dotler:{account}")
        };
        let mut child = std::process::Command::new("secret-tool")
            .args([
                "store",
                &label,
                "service",
                KEYRING_SERVICE_NAME,
                "username",
                account,
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
    pub fn delete_password(account: &str) -> Result<(), KeyringError> {
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
                account,
            ])
            .output()
            .map_err(|e| KeyringError::BackendError(format!("secret-tool unavailable: {e}")))?;
        Ok(())
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    pub fn delete_all_passwords(vault_ids: &[String]) -> Result<(), KeyringError> {
        delete_password(KEYRING_DEFAULT_USER)?;
        for vid in vault_ids {
            let trimmed = vid.trim();
            if !trimmed.is_empty() && trimmed != KEYRING_DEFAULT_USER {
                delete_password(trimmed)?;
            }
        }
        let _ = std::process::Command::new("secret-tool")
            .args(["clear", "service", KEYRING_SERVICE_NAME])
            .output()
            .map_err(|e| KeyringError::BackendError(format!("secret-tool unavailable: {e}")))?;
        Ok(())
    }

    #[cfg(target_os = "windows")]
    pub fn get_password(account: &str) -> Result<Option<String>, KeyringError> {
        win_cred::read(account)
    }

    #[cfg(target_os = "windows")]
    pub fn set_password(account: &str, secret: &str) -> Result<(), KeyringError> {
        win_cred::write(account, secret)
    }

    #[cfg(target_os = "windows")]
    pub fn delete_password(account: &str) -> Result<(), KeyringError> {
        win_cred::delete(account)
    }

    #[cfg(target_os = "windows")]
    pub fn delete_all_passwords(vault_ids: &[String]) -> Result<(), KeyringError> {
        win_cred::delete(KEYRING_DEFAULT_USER)?;
        for vid in vault_ids {
            let trimmed = vid.trim();
            if !trimmed.is_empty() && trimmed != KEYRING_DEFAULT_USER {
                win_cred::delete(trimmed)?;
            }
        }
        win_cred::delete_all_matching()
    }

    #[cfg(target_os = "windows")]
    mod win_cred {
        use super::{KEYRING_SERVICE_NAME, KeyringError};
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
            fn CredEnumerateW(
                filter: *const u16,
                flags: u32,
                count: *mut u32,
                credentials: *mut *mut *mut CredentialW,
            ) -> i32;
            fn CredFree(buffer: *mut c_void);
        }

        fn to_wide(s: &str) -> Vec<u16> {
            s.encode_utf16().chain(std::iter::once(0)).collect()
        }

        fn target_name(account: &str) -> Vec<u16> {
            to_wide(&format!("{account}.{KEYRING_SERVICE_NAME}"))
        }

        pub fn read(account: &str) -> Result<Option<String>, KeyringError> {
            let target = target_name(account);
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

        pub fn write(account: &str, secret: &str) -> Result<(), KeyringError> {
            let mut target = target_name(account);
            let mut user = to_wide(account);
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

        pub fn delete(account: &str) -> Result<(), KeyringError> {
            let target = target_name(account);
            unsafe {
                let _ = CredDeleteW(target.as_ptr(), CRED_TYPE_GENERIC, 0);
            }
            Ok(())
        }

        pub fn delete_all_matching() -> Result<(), KeyringError> {
            let filter = to_wide(&format!("*.{KEYRING_SERVICE_NAME}"));
            let mut count: u32 = 0;
            let mut creds: *mut *mut CredentialW = std::ptr::null_mut();
            let ok = unsafe { CredEnumerateW(filter.as_ptr(), 0, &mut count, &mut creds) };
            if ok == 0 || creds.is_null() {
                return Ok(());
            }
            unsafe {
                let slice = std::slice::from_raw_parts(creds, count as usize);
                for &cred_ptr in slice {
                    if !cred_ptr.is_null() {
                        let cred = &*cred_ptr;
                        if !cred.target_name.is_null() {
                            let _ = CredDeleteW(cred.target_name, CRED_TYPE_GENERIC, 0);
                        }
                    }
                }
                CredFree(creds.cast());
            }
            Ok(())
        }
    }
}

#[cfg(test)]
pub(crate) static MOCK_KEYRING_TEST_LOCK: Mutex<()> = Mutex::new(());

#[cfg(test)]
pub(crate) struct MockKeyringGuard<'a> {
    _lock: std::sync::MutexGuard<'a, ()>,
}

#[cfg(test)]
impl<'a> MockKeyringGuard<'a> {
    pub(crate) fn new() -> Self {
        let lock = MOCK_KEYRING_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        OsKeyring::enable_mock();
        OsKeyring::clear_mock();
        Self { _lock: lock }
    }
}

#[cfg(test)]
impl<'a> Drop for MockKeyringGuard<'a> {
    fn drop(&mut self) {
        OsKeyring::clear_mock();
        OsKeyring::disable_mock();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_keyring_headless_fallback_returns_none() {
        let _lock = MOCK_KEYRING_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        OsKeyring::disable_mock();
        assert!(OsKeyring::get().is_ok());
        assert!(OsKeyring::get_for_vault("vault-a").is_ok());
    }

    #[test]
    fn test_mock_keyring_multi_vault_isolation_and_delete_all() {
        let _guard = MockKeyringGuard::new();

        let pw_a = SecretString::new("vault-a-pass".to_string());
        let pw_b = SecretString::new("vault-b-pass".to_string());

        // Setting vault A populates vault-a and fills empty default slot
        OsKeyring::set_with_fallback(Some("vault-a"), &pw_a).unwrap();
        assert_eq!(
            OsKeyring::get_for_vault("vault-a").unwrap().unwrap().expose_secret(),
            "vault-a-pass"
        );
        assert_eq!(
            OsKeyring::get().unwrap().unwrap().expose_secret(),
            "vault-a-pass"
        );

        // Setting vault B populates vault-b without overwriting existing default slot
        OsKeyring::set_with_fallback(Some("vault-b"), &pw_b).unwrap();
        assert_eq!(
            OsKeyring::get_for_vault("vault-b").unwrap().unwrap().expose_secret(),
            "vault-b-pass"
        );
        assert_eq!(
            OsKeyring::get().unwrap().unwrap().expose_secret(),
            "vault-a-pass"
        );

        assert!(OsKeyring::is_ready_for_vault(Some("vault-a")));
        assert!(OsKeyring::is_ready_for_vault(Some("vault-b")));
        assert!(OsKeyring::is_ready_for_vault(Some("vault-unregistered")));

        // Delete only vault-a keeps vault-b and default intact
        OsKeyring::delete_for_vault("vault-a").unwrap();
        assert!(OsKeyring::get_for_vault("vault-a").unwrap().is_none());
        assert_eq!(
            OsKeyring::get_for_vault("vault-b").unwrap().unwrap().expose_secret(),
            "vault-b-pass"
        );

        // Delete all clears default and all vault slots
        OsKeyring::delete_all(&["vault-a".to_string(), "vault-b".to_string()]).unwrap();
        assert!(OsKeyring::get().unwrap().is_none());
        assert!(OsKeyring::get_for_vault("vault-b").unwrap().is_none());
        assert!(!OsKeyring::is_ready_for_vault(Some("vault-b")));
    }
}
