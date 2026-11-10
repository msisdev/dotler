//! Inline badge preview and single-line summary footer renderer.

use std::io::{self, Write};
use std::path::PathBuf;

use crossterm::style::{Attribute, Color, ResetColor, SetAttribute, SetBackgroundColor, SetForegroundColor};

pub const ICON_LEFT_BAR: &str = "▐";
pub const ICON_RIGHT_BAR: &str = "▌";
pub const ALL_OK_MESSAGE: &str = "☀️ All files are ok.";

/// Three-column (`▐x▌`) status badge attached to an OS or repository path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BadgeOp {
    Okay,
    Skip,
    Create,
    Overwrite,
    Delete,
    Untrack,
}

impl BadgeOp {
    /// Returns the single lowercase character displayed in the center of the badge.
    pub fn symbol_char(&self) -> char {
        match self {
            Self::Okay => 'o',
            Self::Skip => 's',
            Self::Create => 'c',
            Self::Overwrite => 'w',
            Self::Delete => 'd',
            Self::Untrack => 'u',
        }
    }

    /// Returns the ANSI 16-color palette index for this badge.
    pub fn ansi_color_index(&self) -> u8 {
        match self {
            Self::Okay => 7,       // Gray
            Self::Skip => 12,      // Blue
            Self::Create => 10,    // Green
            Self::Overwrite => 11, // Yellow
            Self::Delete => 9,     // Red
            Self::Untrack => 13,   // Purple
        }
    }

    /// Returns the unstyled 3-column badge representation (e.g., `"▐w▌"`).
    pub fn plain_badge(&self) -> &'static str {
        match self {
            Self::Okay => "▐o▌",
            Self::Skip => "▐s▌",
            Self::Create => "▐c▌",
            Self::Overwrite => "▐w▌",
            Self::Delete => "▐d▌",
            Self::Untrack => "▐u▌",
        }
    }

    /// Renders the badge using ANSI 16-color half-blocks and inverted bold center character.
    pub fn render_styled(&self) -> String {
        let idx = self.ansi_color_index();
        let ch = self.symbol_char();
        format!(
            "{}{}{}{}{}{}{}{}{}{}",
            SetForegroundColor(Color::AnsiValue(idx)),
            ICON_LEFT_BAR,
            SetForegroundColor(Color::AnsiValue(0)),
            SetBackgroundColor(Color::AnsiValue(idx)),
            SetAttribute(Attribute::Bold),
            ch,
            ResetColor,
            SetForegroundColor(Color::AnsiValue(idx)),
            ICON_RIGHT_BAR,
            ResetColor,
        )
    }
}

/// Fixed 5-column direction and encryption/decryption arrow placed before the second-line badge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreviewArrow {
    PlainToRepo,
    EncryptToRepo,
    PlainToOs,
    DecryptToOs,
    DecryptInRepo,
}

impl PreviewArrow {
    /// Returns the exact 5-column string representation including trailing space.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PlainToRepo => "───▸ ",
            Self::EncryptToRepo => "──🔒 ",
            Self::PlainToOs => "◂─── ",
            Self::DecryptToOs => "🔑── ",
            Self::DecryptInRepo => "──🔑 ",
        }
    }
}

/// Single file preview model with group name, top-line OS path, and bottom-line repository path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreviewItem {
    pub group_name: String,
    pub os_path: PathBuf,
    pub os_op: BadgeOp,
    pub repo_path: PathBuf,
    pub repo_op: BadgeOp,
    pub arrow: PreviewArrow,
}

impl PreviewItem {
    /// Returns the primary operation of this item for summary counting.
    pub fn primary_op(&self) -> BadgeOp {
        for op in [self.os_op, self.repo_op] {
            if matches!(
                op,
                BadgeOp::Delete | BadgeOp::Overwrite | BadgeOp::Create | BadgeOp::Untrack | BadgeOp::Skip
            ) {
                return op;
            }
        }
        BadgeOp::Okay
    }

    /// Determines whether this item should be displayed in detail.
    ///
    /// In default mode (`view_all = false`), only `Overwrite` and `Delete` items are shown.
    pub fn is_visible(&self, view_all: bool) -> bool {
        if view_all {
            return true;
        }
        matches!(self.os_op, BadgeOp::Overwrite | BadgeOp::Delete)
            || matches!(self.repo_op, BadgeOp::Overwrite | BadgeOp::Delete)
    }
}

/// Aggregated file counts by operation across all preview items.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PreviewCounts {
    pub create: usize,
    pub overwrite: usize,
    pub delete: usize,
    pub untrack: usize,
    pub skip: usize,
    pub okay: usize,
}

impl PreviewCounts {
    /// Aggregates counts from a slice of [`PreviewItem`]s.
    pub fn from_items(items: &[PreviewItem]) -> Self {
        let mut counts = Self::default();
        for item in items {
            match item.primary_op() {
                BadgeOp::Create => counts.create += 1,
                BadgeOp::Overwrite => counts.overwrite += 1,
                BadgeOp::Delete => counts.delete += 1,
                BadgeOp::Untrack => counts.untrack += 1,
                BadgeOp::Skip => counts.skip += 1,
                BadgeOp::Okay => counts.okay += 1,
            }
        }
        counts
    }

    /// Returns the total number of mutating file operations (`create + overwrite + delete + untrack`).
    pub fn total_updates(&self) -> usize {
        self.create + self.overwrite + self.delete + self.untrack
    }
}

/// Formats a single [`PreviewItem`] as two indented lines (OS path on line 1, Repo path on line 2).
pub fn render_item(item: &PreviewItem) -> String {
    format!(
        "  {} {}\n  {}{} {}",
        item.os_op.render_styled(),
        item.os_path.display(),
        item.arrow.as_str(),
        item.repo_op.render_styled(),
        item.repo_path.display(),
    )
}

/// Formats the single-line inline summary footer displaying counts per badge operation.
pub fn render_footer(counts: &PreviewCounts) -> String {
    let mut styled_parts = vec![
        format!("{}create {}", BadgeOp::Create.render_styled(), counts.create),
        format!(
            "{}overwrite {}",
            BadgeOp::Overwrite.render_styled(),
            counts.overwrite
        ),
        format!("{}delete {}", BadgeOp::Delete.render_styled(), counts.delete),
    ];

    if counts.untrack > 0 {
        styled_parts.push(format!(
            "{}untrack {}",
            BadgeOp::Untrack.render_styled(),
            counts.untrack
        ));
    }
    if counts.skip > 0 {
        styled_parts.push(format!(
            "{}skip {}",
            BadgeOp::Skip.render_styled(),
            counts.skip
        ));
    }

    styled_parts.push(format!("{}okay {}", BadgeOp::Okay.render_styled(), counts.okay));

    styled_parts.join("   ")
}

/// Formats the entire inline preview and returns the formatted string along with [`PreviewCounts`].
pub fn format_preview(items: &[PreviewItem], view_all: bool) -> (String, PreviewCounts) {
    let counts = PreviewCounts::from_items(items);
    if counts.total_updates() == 0 {
        return (format!("{ALL_OK_MESSAGE}\n"), counts);
    }

    let mut group_order: Vec<String> = Vec::new();
    for item in items {
        if !item.is_visible(view_all) {
            continue;
        }
        if !group_order.contains(&item.group_name) {
            group_order.push(item.group_name.clone());
        }
    }

    let mut out = String::new();
    for group_name in &group_order {
        out.push_str(&format!("[{group_name}]\n"));
        for item in items
            .iter()
            .filter(|i| &i.group_name == group_name && i.is_visible(view_all))
        {
            out.push_str(&render_item(item));
            out.push('\n');
        }
        out.push('\n');
    }

    out.push_str(&render_footer(&counts));
    out.push('\n');

    (out, counts)
}

/// Writes the inline preview and summary footer to the given writer.
pub fn render_preview_to<W: Write>(
    writer: &mut W,
    items: &[PreviewItem],
    view_all: bool,
) -> io::Result<PreviewCounts> {
    let (formatted, counts) = format_preview(items, view_all);
    writer.write_all(formatted.as_bytes())?;
    writer.flush()?;
    Ok(counts)
}

/// Writes the inline preview and summary footer to standard output.
pub fn render_preview(items: &[PreviewItem], view_all: bool) -> io::Result<PreviewCounts> {
    let mut stdout = io::stdout();
    render_preview_to(&mut stdout, items, view_all)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strip_ansi(s: &str) -> String {
        let mut out = String::new();
        let mut chars = s.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\x1b' {
                if chars.peek() == Some(&'[') {
                    chars.next();
                    for ch in chars.by_ref() {
                        if ch.is_ascii_alphabetic() {
                            break;
                        }
                    }
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    #[test]
    fn group_headers_and_five_column_arrows_render_correctly() {
        let items = vec![
            PreviewItem {
                group_name: "nvim".to_string(),
                os_path: PathBuf::from("~/.config/nvim/init.lua"),
                os_op: BadgeOp::Okay,
                repo_path: PathBuf::from("~/dotfiles/nvim/init.lua"),
                repo_op: BadgeOp::Overwrite,
                arrow: PreviewArrow::PlainToRepo,
            },
            PreviewItem {
                group_name: "bash".to_string(),
                os_path: PathBuf::from("~/.bashrc"),
                os_op: BadgeOp::Okay,
                repo_path: PathBuf::from("~/dotfiles/bash/.bashrc.enc"),
                repo_op: BadgeOp::Overwrite,
                arrow: PreviewArrow::EncryptToRepo,
            },
            PreviewItem {
                group_name: "zsh".to_string(),
                os_path: PathBuf::from("~/.zshrc"),
                os_op: BadgeOp::Overwrite,
                repo_path: PathBuf::from("~/dotfiles/zsh/.zshrc.enc"),
                repo_op: BadgeOp::Okay,
                arrow: PreviewArrow::DecryptToOs,
            },
        ];

        let (raw, counts) = format_preview(&items, false);
        let plain = strip_ansi(&raw);

        assert_eq!(counts.overwrite, 3);
        assert!(plain.contains("[nvim]\n  ▐o▌ ~/.config/nvim/init.lua\n  ───▸ ▐w▌ ~/dotfiles/nvim/init.lua"));
        assert!(plain.contains("[bash]\n  ▐o▌ ~/.bashrc\n  ──🔒 ▐w▌ ~/dotfiles/bash/.bashrc.enc"));
        assert!(plain.contains("[zsh]\n  ▐w▌ ~/.zshrc\n  🔑── ▐o▌ ~/dotfiles/zsh/.zshrc.enc"));
    }

    #[test]
    fn default_mode_filters_to_overwrite_and_delete_and_omits_empty_groups() {
        let items = vec![
            PreviewItem {
                group_name: "git".to_string(),
                os_path: PathBuf::from("~/.gitconfig"),
                os_op: BadgeOp::Okay,
                repo_path: PathBuf::from("~/dotfiles/git/.gitconfig"),
                repo_op: BadgeOp::Create,
                arrow: PreviewArrow::PlainToRepo,
            },
            PreviewItem {
                group_name: "tmux".to_string(),
                os_path: PathBuf::from("~/.tmux.conf"),
                os_op: BadgeOp::Okay,
                repo_path: PathBuf::from("~/dotfiles/tmux/.tmux.conf"),
                repo_op: BadgeOp::Okay,
                arrow: PreviewArrow::PlainToRepo,
            },
            PreviewItem {
                group_name: "nvim".to_string(),
                os_path: PathBuf::from("~/.config/nvim/init.lua"),
                os_op: BadgeOp::Okay,
                repo_path: PathBuf::from("~/dotfiles/nvim/init.lua"),
                repo_op: BadgeOp::Overwrite,
                arrow: PreviewArrow::PlainToRepo,
            },
        ];

        let (raw, counts) = format_preview(&items, false);
        let plain = strip_ansi(&raw);

        assert_eq!(counts.create, 1);
        assert_eq!(counts.overwrite, 1);
        assert_eq!(counts.okay, 1);
        assert_eq!(counts.total_updates(), 2);

        assert!(!plain.contains("[git]"), "Create-only group must be omitted when view_all = false");
        assert!(!plain.contains("[tmux]"), "Okay-only group must be omitted when view_all = false");
        assert!(plain.contains("[nvim]"), "Overwrite group must be shown");
        assert!(plain.contains("▐c▌create 1   ▐w▌overwrite 1   ▐d▌delete 0   ▐o▌okay 1"));
    }

    #[test]
    fn create_only_renders_summary_footer_without_item_lines() {
        let items = vec![PreviewItem {
            group_name: "git".to_string(),
            os_path: PathBuf::from("~/.gitconfig"),
            os_op: BadgeOp::Okay,
            repo_path: PathBuf::from("~/dotfiles/git/.gitconfig"),
            repo_op: BadgeOp::Create,
            arrow: PreviewArrow::PlainToRepo,
        }];

        let (raw, counts) = format_preview(&items, false);
        let plain = strip_ansi(&raw);

        assert_eq!(counts.create, 1);
        assert_eq!(counts.overwrite, 0);
        assert!(counts.total_updates() > 0);
        assert!(!plain.contains("[git]"));
        assert!(!plain.contains("~/.gitconfig"));
        assert!(!plain.contains("╭"));
        assert_eq!(
            plain.trim(),
            "▐c▌create 1   ▐w▌overwrite 0   ▐d▌delete 0   ▐o▌okay 0"
        );
    }

    #[test]
    fn zero_updates_prints_all_ok_message_only() {
        let items = vec![PreviewItem {
            group_name: "git".to_string(),
            os_path: PathBuf::from("~/.gitconfig"),
            os_op: BadgeOp::Okay,
            repo_path: PathBuf::from("~/dotfiles/git/.gitconfig"),
            repo_op: BadgeOp::Okay,
            arrow: PreviewArrow::PlainToRepo,
        }];

        let (raw, counts) = format_preview(&items, false);
        assert_eq!(counts.total_updates(), 0);
        assert_eq!(raw.trim(), ALL_OK_MESSAGE);
    }
}
