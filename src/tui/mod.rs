//! Inline terminal user interface (TUI) subsystem.
//!
//! Provides ANSI 16-color badge previews and summary footers (`preview`),
//! Raw Mode placeholder confirmation prompts (`confirm`), and two-line
//! `<progress>/<total>` file progress bars (`progress`).

pub mod confirm;
pub mod preview;
pub mod progress;

pub use confirm::{
    CONFIRM_CHAR_LIMIT, CONFIRM_PLACEHOLDER, ConfirmError, ConfirmPrompt, DEFAULT_CONFIRM_TITLE,
    PromptAction, RawModeGuard, confirm_proceed, confirm_proceed_to,
};
pub use preview::{
    ALL_OK_MESSAGE, BadgeOp, ICON_LEFT_BAR, ICON_RIGHT_BAR, PreviewArrow, PreviewCounts,
    PreviewItem, format_preview, render_footer, render_item, render_preview, render_preview_to,
};
pub use progress::{
    BAR_EMPTY_CHAR, BAR_FILLED_CHAR, DONE_LABEL, PROGRESS_BAR_WIDTH, ProgressReporter,
};
