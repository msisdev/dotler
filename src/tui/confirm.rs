//! Inline placeholder confirmation widget with RAII Raw Mode guard.

use std::collections::VecDeque;
use std::io::{self, IsTerminal, Write};
use std::sync::Mutex;

use crossterm::cursor::MoveToColumn;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::style::{Color, ResetColor, SetForegroundColor};
use crossterm::terminal::{Clear, ClearType, disable_raw_mode, enable_raw_mode};

pub const DEFAULT_CONFIRM_TITLE: &str = "Do you want to proceed?";
pub const CONFIRM_PLACEHOLDER: &str = "yes";
pub const CONFIRM_CHAR_LIMIT: usize = 3;

static MOCK_CONFIRM_QUEUE: Mutex<VecDeque<String>> = Mutex::new(VecDeque::new());

/// Errors emitted while running the inline confirmation prompt.
#[derive(Debug)]
pub enum ConfirmError {
    NonTtyError,
    TerminalIoError(io::Error),
}

impl std::fmt::Display for ConfirmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonTtyError => write!(
                f,
                "Interactive confirmation prompt requires a TTY terminal (pass -y or --json in non-interactive mode)"
            ),
            Self::TerminalIoError(e) => write!(f, "Terminal I/O error: {e}"),
        }
    }
}

impl std::error::Error for ConfirmError {}

impl From<io::Error> for ConfirmError {
    fn from(e: io::Error) -> Self {
        Self::TerminalIoError(e)
    }
}

/// RAII guard that enables terminal Raw Mode on creation and unconditionally restores it on drop.
pub struct RawModeGuard {
    pub active: bool,
}

impl RawModeGuard {
    /// Enters terminal Raw Mode and returns a [`RawModeGuard`].
    pub fn enter() -> Result<Self, ConfirmError> {
        enable_raw_mode().map_err(ConfirmError::TerminalIoError)?;
        Ok(Self { active: true })
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        if self.active {
            let _ = disable_raw_mode();
        }
    }
}

/// State transition action after handling a single key event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptAction {
    Continue,
    Submit(bool),
    Cancel,
}

/// Pure state-machine model for the 3-character `"yes"` placeholder confirmation widget.
#[derive(Debug, Clone)]
pub struct ConfirmPrompt {
    pub title: String,
    pub placeholder: &'static str,
    pub buffer: String,
    pub char_limit: usize,
}

impl ConfirmPrompt {
    /// Creates a new confirmation prompt with the given title and default `"yes"` placeholder.
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            placeholder: CONFIRM_PLACEHOLDER,
            buffer: String::new(),
            char_limit: CONFIRM_CHAR_LIMIT,
        }
    }

    /// Enqueues a mock input line for deterministic testing without a physical TTY.
    pub fn push_mock_input(input: impl Into<String>) {
        MOCK_CONFIRM_QUEUE.lock().unwrap().push_back(input.into());
    }

    /// Clears all queued mock confirmation inputs.
    pub fn clear_mock_inputs() {
        MOCK_CONFIRM_QUEUE.lock().unwrap().clear();
    }

    /// Returns `true` if a mock input or `DOTLER_TEST_CONFIRM_INPUT` environment override is queued.
    pub fn has_mock_or_env_input() -> bool {
        !MOCK_CONFIRM_QUEUE.lock().unwrap().is_empty()
            || std::env::var("DOTLER_TEST_CONFIRM_INPUT").is_ok()
    }

    fn take_mock_input() -> Option<String> {
        MOCK_CONFIRM_QUEUE.lock().unwrap().pop_front()
    }

    /// Processes a single key event and returns the resulting [`PromptAction`].
    pub fn handle_key(&mut self, key: KeyEvent) -> PromptAction {
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
            KeyCode::Enter => PromptAction::Submit(self.buffer == self.placeholder),
            KeyCode::Backspace => {
                self.buffer.pop();
                PromptAction::Continue
            }
            KeyCode::Char(c) => {
                if !key.modifiers.contains(KeyModifiers::CONTROL)
                    && !key.modifiers.contains(KeyModifiers::ALT)
                    && self.buffer.chars().count() < self.char_limit
                {
                    self.buffer.push(c);
                }
                PromptAction::Continue
            }
            _ => PromptAction::Continue,
        }
    }

    /// Renders the current input line (gray `"yes"` placeholder when empty, or typed buffer)
    /// and returns `(rendered_string, cursor_column)`.
    pub fn render_input_line(&self) -> (String, usize) {
        if self.buffer.is_empty() {
            let styled = format!(
                "{}{}{}",
                SetForegroundColor(Color::AnsiValue(7)),
                self.placeholder,
                ResetColor,
            );
            (styled, 0)
        } else {
            (self.buffer.clone(), self.buffer.chars().count())
        }
    }

    /// Feeds a synthetic string of characters followed by Enter through the state machine.
    pub fn evaluate_str(&mut self, raw: &str) -> bool {
        for ch in raw.chars() {
            if ch == '\x1b' || ch == '\x03' {
                return false;
            }
            if ch == '\r' || ch == '\n' {
                break;
            }
            if ch == '\u{7f}' || ch == '\u{08}' {
                let _ = self.handle_key(KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE));
            } else {
                let _ = self.handle_key(KeyEvent::new(KeyCode::Char(ch), KeyModifiers::NONE));
            }
        }
        matches!(
            self.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)),
            PromptAction::Submit(true)
        )
    }
}

/// Runs the inline confirmation prompt writing to a custom writer.
pub fn confirm_proceed_to<W: Write>(writer: &mut W, title: &str) -> Result<bool, ConfirmError> {
    let mut prompt = ConfirmPrompt::new(title);

    if let Some(mock_str) = ConfirmPrompt::take_mock_input() {
        let (line_str, _) = prompt.render_input_line();
        write!(writer, "\n{}\n{}\n", prompt.title, line_str)?;
        writer.flush()?;
        return Ok(prompt.evaluate_str(&mock_str));
    }

    if let Ok(env_input) = std::env::var("DOTLER_TEST_CONFIRM_INPUT") {
        let (line_str, _) = prompt.render_input_line();
        write!(writer, "\n{}\n{}\n", prompt.title, line_str)?;
        writer.flush()?;
        return Ok(prompt.evaluate_str(&env_input));
    }

    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err(ConfirmError::NonTtyError);
    }

    write!(writer, "\n{}\n", prompt.title)?;
    writer.flush()?;

    let _guard = RawModeGuard::enter()?;

    loop {
        let (rendered, col) = prompt.render_input_line();
        write!(
            writer,
            "\r{}{}{}",
            Clear(ClearType::CurrentLine),
            rendered,
            MoveToColumn(col as u16)
        )?;
        writer.flush()?;

        let ev = event::read().map_err(ConfirmError::TerminalIoError)?;
        if let Event::Key(key_event) = ev {
            match prompt.handle_key(key_event) {
                PromptAction::Continue => continue,
                PromptAction::Submit(approved) => {
                    write!(writer, "\r\n")?;
                    writer.flush()?;
                    return Ok(approved);
                }
                PromptAction::Cancel => {
                    write!(writer, "\r\n")?;
                    writer.flush()?;
                    return Ok(false);
                }
            }
        }
    }
}

/// Runs the inline confirmation prompt on standard output.
pub fn confirm_proceed(title: &str) -> Result<bool, ConfirmError> {
    let mut stdout = io::stdout();
    confirm_proceed_to(&mut stdout, title)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_renders_when_empty_and_disappears_on_typing() {
        let mut prompt = ConfirmPrompt::new(DEFAULT_CONFIRM_TITLE);
        let (initial_line, initial_col) = prompt.render_input_line();
        assert!(initial_line.contains("yes"));
        assert!(initial_line.contains("\x1b["));
        assert_eq!(initial_col, 0);

        let action = prompt.handle_key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE));
        assert_eq!(action, PromptAction::Continue);
        let (typed_line, typed_col) = prompt.render_input_line();
        assert_eq!(typed_line, "y");
        assert_eq!(typed_col, 1);
    }

    #[test]
    fn char_limit_three_and_backspace_restores_placeholder() {
        let mut prompt = ConfirmPrompt::new(DEFAULT_CONFIRM_TITLE);
        for ch in ['y', 'e', 's', 'x'] {
            prompt.handle_key(KeyEvent::new(KeyCode::Char(ch), KeyModifiers::NONE));
        }
        assert_eq!(prompt.buffer, "yes");

        for _ in 0..3 {
            prompt.handle_key(KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE));
        }
        assert!(prompt.buffer.is_empty());
        let (line, col) = prompt.render_input_line();
        assert!(line.contains("yes"));
        assert_eq!(col, 0);
    }

    #[test]
    fn only_exact_yes_approves_while_empty_typo_esc_ctrl_c_cancel() {
        // Exact "yes" + Enter -> Submit(true)
        let mut p_yes = ConfirmPrompt::new(DEFAULT_CONFIRM_TITLE);
        for ch in ['y', 'e', 's'] {
            p_yes.handle_key(KeyEvent::new(KeyCode::Char(ch), KeyModifiers::NONE));
        }
        assert_eq!(
            p_yes.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)),
            PromptAction::Submit(true)
        );

        // Empty + Enter -> Submit(false)
        let mut p_empty = ConfirmPrompt::new(DEFAULT_CONFIRM_TITLE);
        assert_eq!(
            p_empty.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)),
            PromptAction::Submit(false)
        );

        // Partial "y" + Enter -> Submit(false)
        let mut p_partial = ConfirmPrompt::new(DEFAULT_CONFIRM_TITLE);
        p_partial.handle_key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE));
        assert_eq!(
            p_partial.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)),
            PromptAction::Submit(false)
        );

        // Esc -> Cancel
        let mut p_esc = ConfirmPrompt::new(DEFAULT_CONFIRM_TITLE);
        assert_eq!(
            p_esc.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)),
            PromptAction::Cancel
        );

        // Ctrl+C -> Cancel
        let mut p_ctrl_c = ConfirmPrompt::new(DEFAULT_CONFIRM_TITLE);
        assert_eq!(
            p_ctrl_c.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)),
            PromptAction::Cancel
        );
    }
}
