//! Two-line synchronous inline file progress bar (`<progress>/<total>`).

use std::io::{self, Write};
use std::path::Path;

use crossterm::cursor::MoveUp;
use crossterm::style::{Attribute, Color, ResetColor, SetAttribute, SetForegroundColor};
use crossterm::terminal::{Clear, ClearType};

pub const PROGRESS_BAR_WIDTH: usize = 24;
pub const BAR_FILLED_CHAR: char = '█';
pub const BAR_EMPTY_CHAR: char = '░';
pub const DONE_LABEL: &str = "Done";

/// Synchronous two-line inline progress reporter without background threads or spinners.
#[derive(Debug, Clone)]
pub struct ProgressReporter {
    pub current: usize,
    pub total: usize,
    pub width: usize,
    pub interactive: bool,
    rendered_once: bool,
}

impl ProgressReporter {
    /// Creates a new [`ProgressReporter`] for `total` mutating file operations.
    pub fn new(total: usize, interactive: bool) -> Self {
        Self {
            current: 0,
            total,
            width: PROGRESS_BAR_WIDTH,
            interactive,
            rendered_once: false,
        }
    }

    /// Formats the proportional bar of width `self.width` using `█` and `░`.
    pub fn format_bar(&self, current: usize) -> String {
        let filled = (current.min(self.total) * self.width)
            .checked_div(self.total)
            .unwrap_or(self.width);
        let empty = self.width.saturating_sub(filled);

        let filled_str: String = std::iter::repeat_n(BAR_FILLED_CHAR, filled).collect();
        let empty_str: String = std::iter::repeat_n(BAR_EMPTY_CHAR, empty).collect();

        format!(
            "{}{}{}{}{}{}",
            SetForegroundColor(Color::AnsiValue(10)),
            filled_str,
            ResetColor,
            SetForegroundColor(Color::AnsiValue(7)),
            empty_str,
            ResetColor,
        )
    }

    /// Formats a byte count into a human-readable string (e.g., `"4.2 KB"`).
    pub fn format_bytes(bytes: u64) -> String {
        const KB: f64 = 1024.0;
        const MB: f64 = KB * 1024.0;
        if bytes as f64 >= MB {
            format!("{:.1} MB", bytes as f64 / MB)
        } else if bytes as f64 >= KB {
            format!("{:.1} KB", bytes as f64 / KB)
        } else {
            format!("{bytes} B")
        }
    }

    /// Formats the two-line progress output for the current file, truncating the relative path
    /// to `.../<filename>` if it would exceed `term_cols`.
    pub fn format_two_lines(
        &self,
        group_name: &str,
        group_base: &Path,
        rel_path: &str,
        bytes: Option<u64>,
        term_cols: usize,
    ) -> (String, String) {
        let bar = self.format_bar(self.current);
        let count_str = format!(
            "{}{}/{}{}",
            SetAttribute(Attribute::Bold),
            self.current,
            self.total,
            SetAttribute(Attribute::Reset),
        );
        let group_str = format!(
            "{}[{}]{} {}",
            SetForegroundColor(Color::AnsiValue(12)),
            group_name,
            ResetColor,
            group_base.display(),
        );
        let line1 = format!("{bar}  {count_str}  {group_str}");

        let size_suffix = bytes
            .map(|b| format!(" ({})", Self::format_bytes(b)))
            .unwrap_or_default();
        let candidate_plain = format!("  {rel_path}{size_suffix}");
        let display_rel = if term_cols > 0 && candidate_plain.chars().count() > term_cols {
            let file_name = Path::new(rel_path)
                .file_name()
                .map(|f| f.to_string_lossy().to_string())
                .unwrap_or_else(|| rel_path.to_string());
            format!(".../{file_name}")
        } else {
            rel_path.to_string()
        };

        let line2 = format!(
            "  {}{}{}{}",
            SetForegroundColor(Color::AnsiValue(7)),
            display_rel,
            size_suffix,
            ResetColor,
        );

        (line1, line2)
    }

    /// Formats the final completion line (`<bar>  <total>/<total>  Done`).
    pub fn format_done_line(&self) -> String {
        let bar = self.format_bar(self.total);
        let count_str = format!(
            "{}{}/{}{}",
            SetAttribute(Attribute::Bold),
            self.total,
            self.total,
            SetAttribute(Attribute::Reset),
        );
        format!("{bar}  {count_str}  {DONE_LABEL}")
    }

    /// Advances progress by 1 file and writes the two-line update to the given writer.
    pub fn inc_to<W: Write>(
        &mut self,
        writer: &mut W,
        group_name: &str,
        group_base: &Path,
        rel_path: &str,
        bytes: Option<u64>,
    ) -> io::Result<()> {
        self.current = (self.current + 1).min(self.total.max(1));
        if !self.interactive || self.total == 0 {
            return Ok(());
        }

        let term_cols = crossterm::terminal::size()
            .map(|(c, _)| c as usize)
            .unwrap_or(80);
        let (line1, line2) =
            self.format_two_lines(group_name, group_base, rel_path, bytes, term_cols);

        if self.rendered_once {
            write!(
                writer,
                "\r{}{}\r{}{}\n{}",
                Clear(ClearType::CurrentLine),
                MoveUp(1),
                Clear(ClearType::CurrentLine),
                line1,
                line2
            )?;
        } else {
            write!(writer, "{line1}\n{line2}")?;
            self.rendered_once = true;
        }
        writer.flush()
    }

    /// Advances progress by 1 file and updates standard output.
    pub fn inc(
        &mut self,
        group_name: &str,
        group_base: &Path,
        rel_path: &str,
        bytes: Option<u64>,
    ) -> io::Result<()> {
        let mut stdout = io::stdout();
        self.inc_to(&mut stdout, group_name, group_base, rel_path, bytes)
    }

    /// Completes the progress bar by clearing the second line and writing `<total>/<total>  Done\n`.
    pub fn finish_to<W: Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.current = self.total;
        if !self.interactive || self.total == 0 {
            return Ok(());
        }

        let done_line = self.format_done_line();
        if self.rendered_once {
            write!(
                writer,
                "\r{}{}\r{}{}\n",
                Clear(ClearType::CurrentLine),
                MoveUp(1),
                Clear(ClearType::CurrentLine),
                done_line
            )?;
        } else {
            writeln!(writer, "{done_line}")?;
        }
        writer.flush()
    }

    /// Completes the progress bar on standard output.
    pub fn finish(&mut self) -> io::Result<()> {
        let mut stdout = io::stdout();
        self.finish_to(&mut stdout)
    }
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
    fn two_line_format_and_long_relative_path_filename_fallback() {
        let mut rep = ProgressReporter::new(6, true);
        rep.current = 3;

        let (line1, line2) = rep.format_two_lines(
            "nvim",
            Path::new("~/.config/nvim"),
            "lua/plugins/telescope.lua",
            Some(4300),
            80,
        );
        let p1 = strip_ansi(&line1);
        let p2 = strip_ansi(&line2);

        assert_eq!(p1, "████████████░░░░░░░░░░░░  3/6  [nvim] ~/.config/nvim");
        assert_eq!(p2, "  lua/plugins/telescope.lua (4.2 KB)");
        assert!(!p1.contains('%'), "percentage must not be displayed");

        // Narrow terminal column limit triggers .../<filename> fallback
        let (_, narrow_line2) = rep.format_two_lines(
            "nvim",
            Path::new("~/.config/nvim"),
            "lua/plugins/deeply/nested/dir/telescope.lua",
            Some(4300),
            30,
        );
        let p2_narrow = strip_ansi(&narrow_line2);
        assert_eq!(p2_narrow, "  .../telescope.lua (4.2 KB)");
    }

    #[test]
    fn finish_renders_done_and_non_interactive_emits_zero_bytes() {
        let mut rep = ProgressReporter::new(6, true);
        let mut buf = Vec::new();
        for _ in 0..6 {
            rep.inc_to(
                &mut buf,
                "nvim",
                Path::new("~/.config/nvim"),
                "init.lua",
                None,
            )
            .unwrap();
        }
        rep.finish_to(&mut buf).unwrap();
        let plain = strip_ansi(&String::from_utf8(buf).unwrap());
        assert!(plain.contains("████████████████████████  6/6  Done"));

        // Non-interactive emits 0 bytes
        let mut silent_rep = ProgressReporter::new(6, false);
        let mut silent_buf = Vec::new();
        silent_rep
            .inc_to(
                &mut silent_buf,
                "nvim",
                Path::new("~/.config/nvim"),
                "init.lua",
                None,
            )
            .unwrap();
        silent_rep.finish_to(&mut silent_buf).unwrap();
        assert!(silent_buf.is_empty());
    }
}
