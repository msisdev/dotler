use crate::crypto::SecretString;
use crate::crypto::keyring::{KeyringError, OsKeyring, PASSPHRASE_ENV_VAR};

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

impl OsKeyring {
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

        let mut line = read_hidden_passphrase(prompt)?;
        let trimmed_len = line.trim_end_matches(['\r', '\n']).len();
        line.truncate(trimmed_len);
        if line.is_empty() {
            zeroize::Zeroize::zeroize(&mut line);
            Err(KeyringError::PromptCancelled)
        } else {
            Ok(ResolvedPassphrase {
                secret: SecretString::new(line),
                source: PassphraseSource::TerminalPrompt,
            })
        }
    }
}

fn handle_passphrase_key(
    buf: &mut String,
    key: crossterm::event::KeyEvent,
) -> crate::tui::confirm::PromptAction {
    use crate::tui::confirm::PromptAction;
    use crossterm::event::{KeyCode, KeyEventKind, KeyModifiers};

    if key.kind == KeyEventKind::Release {
        return PromptAction::Continue;
    }

    if key.code == KeyCode::Esc
        || (matches!(key.code, KeyCode::Char('c' | 'C' | 'd' | 'D'))
            && key.modifiers.contains(KeyModifiers::CONTROL))
    {
        return PromptAction::Cancel;
    }

    match key.code {
        KeyCode::Enter => PromptAction::Submit(!buf.is_empty()),
        KeyCode::Backspace => {
            buf.pop();
            PromptAction::Continue
        }
        KeyCode::Char(c) => {
            if !key.modifiers.contains(KeyModifiers::CONTROL)
                && !key.modifiers.contains(KeyModifiers::ALT)
            {
                buf.push(c);
            }
            PromptAction::Continue
        }
        _ => PromptAction::Continue,
    }
}

fn render_masked_passphrase_line(prompt: &str, buf: &str) -> String {
    let mask: String = std::iter::repeat_n('*', buf.chars().count()).collect();
    format!("{prompt}{mask}")
}

fn read_hidden_passphrase(prompt: &str) -> Result<String, KeyringError> {
    use crate::tui::confirm::{PromptAction, RawModeGuard};
    use crossterm::event::{self, Event};
    use crossterm::terminal::{Clear, ClearType};
    use std::io::{IsTerminal, Write};

    if !std::io::stdin().is_terminal() {
        return Err(KeyringError::PromptCancelled);
    }

    let mut stderr = std::io::stderr();
    let _guard = RawModeGuard::enter().map_err(|_| KeyringError::PromptCancelled)?;
    let mut buf = zeroize::Zeroizing::new(String::new());

    loop {
        let masked_line = render_masked_passphrase_line(prompt, &buf);
        write!(stderr, "\r{}{}", Clear(ClearType::CurrentLine), masked_line)
            .map_err(|_| KeyringError::PromptCancelled)?;
        stderr.flush().map_err(|_| KeyringError::PromptCancelled)?;

        let ev = match event::read() {
            Ok(ev) => ev,
            Err(_) => {
                let _ = stderr.write_all(b"\r\n");
                let _ = stderr.flush();
                return Err(KeyringError::PromptCancelled);
            }
        };

        if let Event::Key(key_event) = ev {
            match handle_passphrase_key(&mut buf, key_event) {
                PromptAction::Continue => continue,
                PromptAction::Submit(_) => {
                    let _ = stderr.write_all(b"\r\n");
                    let _ = stderr.flush();
                    return Ok(std::mem::take(&mut *buf));
                }
                PromptAction::Cancel => {
                    let _ = stderr.write_all(b"\r\n");
                    let _ = stderr.flush();
                    return Err(KeyringError::PromptCancelled);
                }
            }
        }
    }
}

/// Creates a lazy [`Resource`](crate::config::Resource) for resolving or storing the vault passphrase.
pub fn get_password(
    use_keyring: bool,
    hint: Option<String>,
    is_interactive: bool,
    stdin_passphrase: Option<String>,
) -> crate::config::Resource<SecretString, KeyringError> {
    crate::config::Resource::new(
        move || {
            if use_keyring && let Ok(Some(secret)) = OsKeyring::get() {
                return Ok(secret);
            }
            if let Some(ref pass) = stdin_passphrase {
                let trimmed = pass.trim_end_matches(['\r', '\n']);
                if !trimmed.is_empty() {
                    return Ok(SecretString::new(trimmed.to_string()));
                }
            }
            if let Ok(env_pass) = std::env::var(PASSPHRASE_ENV_VAR) {
                let trimmed = env_pass.trim_end_matches(['\r', '\n']);
                if !trimmed.is_empty() {
                    return Ok(SecretString::new(trimmed.to_string()));
                }
            }
            if !is_interactive {
                return Err(KeyringError::PassphraseRequiredInNonInteractiveMode);
            }
            let prompt = match hint.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                Some(h) => format!("Enter vault passphrase (hint: {h}): "),
                None => "Enter vault passphrase: ".to_string(),
            };
            Ok(OsKeyring::prompt_passphrase_with_message(&prompt)?.secret)
        },
        move |secret: &SecretString| {
            if use_keyring {
                OsKeyring::set(secret)
            } else {
                Ok(())
            }
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ExposeSecret;
    use crate::crypto::keyring::MockKeyringGuard;

    #[test]
    fn test_resolved_passphrase_debug_redacted() {
        let resolved = ResolvedPassphrase {
            secret: SecretString::new("super-secret-pw".to_string()),
            source: PassphraseSource::OsKeyring,
        };
        let debug_str = format!("{resolved:?}");
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains("super-secret-pw"));
    }

    #[test]
    fn test_passphrase_supply_tier1_keyring() {
        let _guard = MockKeyringGuard::new();
        OsKeyring::set(&SecretString::new("tier1-keyring-pw".to_string())).unwrap();

        let resolved = OsKeyring::resolve(false, Some("stdin-pw")).unwrap();
        assert_eq!(resolved.source, PassphraseSource::OsKeyring);
        assert_eq!(resolved.secret.expose_secret(), "tier1-keyring-pw");
    }

    #[test]
    fn test_passphrase_supply_tier2_stdin() {
        let _guard = MockKeyringGuard::new();
        let resolved = OsKeyring::resolve(false, Some("stdin-pw\n")).unwrap();
        assert_eq!(resolved.source, PassphraseSource::StdinPipe);
        assert_eq!(resolved.secret.expose_secret(), "stdin-pw");
    }

    #[test]
    fn test_passphrase_supply_tier2_env() {
        let _guard = MockKeyringGuard::new();
        unsafe { std::env::set_var(PASSPHRASE_ENV_VAR, "env-variable-pw\n"); }
        let resolved = OsKeyring::resolve(false, None).unwrap();
        assert_eq!(resolved.source, PassphraseSource::EnvVar);
        assert_eq!(resolved.secret.expose_secret(), "env-variable-pw");
        unsafe { std::env::remove_var(PASSPHRASE_ENV_VAR); }
    }

    #[test]
    fn test_passphrase_supply_tier3_non_interactive_blocked() {
        let _guard = MockKeyringGuard::new();
        unsafe { std::env::remove_var(PASSPHRASE_ENV_VAR); }
        let result = OsKeyring::resolve(false, None);
        assert!(matches!(result, Err(KeyringError::PassphraseRequiredInNonInteractiveMode)));
        if let Err(e) = result {
            assert_eq!(e.exit_code(), 4);
        }
    }

    #[test]
    fn test_passphrase_key_event_state_machine() {
        use crate::tui::confirm::PromptAction;
        use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};

        let mut buf = String::new();
        for ch in ['s', 'e', 'c', 'x'] {
            assert_eq!(
                handle_passphrase_key(&mut buf, KeyEvent::new(KeyCode::Char(ch), KeyModifiers::NONE)),
                PromptAction::Continue
            );
        }
        assert_eq!(
            handle_passphrase_key(
                &mut buf,
                KeyEvent {
                    code: KeyCode::Char('z'),
                    modifiers: KeyModifiers::NONE,
                    kind: KeyEventKind::Release,
                    state: KeyEventState::NONE,
                }
            ),
            PromptAction::Continue
        );
        assert_eq!(
            handle_passphrase_key(&mut buf, KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE)),
            PromptAction::Continue
        );
        for ch in ['r', 'e', 't', '한', '🔒'] {
            handle_passphrase_key(&mut buf, KeyEvent::new(KeyCode::Char(ch), KeyModifiers::NONE));
        }
        handle_passphrase_key(&mut buf, KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE));
        handle_passphrase_key(&mut buf, KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE));
        assert_eq!(
            handle_passphrase_key(&mut buf, KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)),
            PromptAction::Submit(true)
        );
        assert_eq!(buf, "secret");
        assert_eq!(
            render_masked_passphrase_line("Enter dotler vault passphrase: ", &buf),
            "Enter dotler vault passphrase: ******"
        );

        for cancel_event in [
            KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
            KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
            KeyEvent::new(KeyCode::Char('C'), KeyModifiers::CONTROL | KeyModifiers::SHIFT),
            KeyEvent::new(KeyCode::Char('d'), KeyModifiers::CONTROL),
            KeyEvent::new(KeyCode::Char('D'), KeyModifiers::CONTROL | KeyModifiers::SHIFT),
        ] {
            assert_eq!(handle_passphrase_key(&mut buf, cancel_event), PromptAction::Cancel);
        }
    }
}
