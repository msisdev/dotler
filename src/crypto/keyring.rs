use secrecy::{ExposeSecret, SecretString};
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

pub const KEYRING_SERVICE_NAME: &str = "dotler";
pub const KEYRING_DEFAULT_USER: &str = "default";
pub const PASSPHRASE_ENV_VAR: &str = "DOTLER_PASSPHRASE";

#[derive(Debug, thiserror::Error)]
pub enum KeyringError {
    #[error("Keyring backend error: {0}")]
    BackendError(String),

    #[error(
        "Passphrase required in non-interactive mode. Please register password using 'dotler key set' or export DOTLER_PASSPHRASE"
    )]
    PassphraseRequiredInNonInteractiveMode,

    #[error("Terminal prompt cancelled or unavailable")]
    PromptCancelled,

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
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
static MOCK_PROMPT_QUEUE: Mutex<VecDeque<String>> = Mutex::new(VecDeque::new());

pub struct OsKeyring;

impl OsKeyring {
    pub fn enable_mock() {
        let mut lock = MOCK_KEYRING.lock().unwrap();
        *lock = Some(HashMap::new());
    }

    pub fn disable_mock() {
        let mut lock = MOCK_KEYRING.lock().unwrap();
        *lock = None;
        Self::clear_mock_prompt_replies();
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
        MOCK_KEYRING.lock().unwrap().is_some()
    }

    pub fn get() -> Result<Option<SecretString>, KeyringError> {
        let lock = MOCK_KEYRING.lock().unwrap();
        if let Some(map) = lock.as_ref() {
            let key = format!("{}:{}", KEYRING_SERVICE_NAME, KEYRING_DEFAULT_USER);
            return Ok(map.get(&key).map(|v| SecretString::new(v.clone())));
        }
        drop(lock);

        let entry = match keyring::Entry::new(KEYRING_SERVICE_NAME, KEYRING_DEFAULT_USER) {
            Ok(e) => e,
            Err(_) => return Ok(None),
        };

        match entry.get_password() {
            Ok(p) => Ok(Some(SecretString::new(p))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(_) => {
                // Graceful fallback for headless environments when Secret Service daemon is unavailable
                Ok(None)
            }
        }
    }

    pub fn set(secret: &SecretString) -> Result<(), KeyringError> {
        let mut lock = MOCK_KEYRING.lock().unwrap();
        if let Some(map) = lock.as_mut() {
            let key = format!("{}:{}", KEYRING_SERVICE_NAME, KEYRING_DEFAULT_USER);
            map.insert(key, secret.expose_secret().to_string());
            return Ok(());
        }
        drop(lock);

        let entry = keyring::Entry::new(KEYRING_SERVICE_NAME, KEYRING_DEFAULT_USER)
            .map_err(|e| KeyringError::BackendError(e.to_string()))?;
        entry
            .set_password(secret.expose_secret())
            .map_err(|e| KeyringError::BackendError(e.to_string()))?;
        Ok(())
    }

    pub fn delete() -> Result<(), KeyringError> {
        let mut lock = MOCK_KEYRING.lock().unwrap();
        if let Some(map) = lock.as_mut() {
            let key = format!("{}:{}", KEYRING_SERVICE_NAME, KEYRING_DEFAULT_USER);
            map.remove(&key);
            return Ok(());
        }
        drop(lock);

        let entry = keyring::Entry::new(KEYRING_SERVICE_NAME, KEYRING_DEFAULT_USER)
            .map_err(|e| KeyringError::BackendError(e.to_string()))?;
        match entry.delete_credential() {
            Ok(_) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(KeyringError::BackendError(e.to_string())),
        }
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
