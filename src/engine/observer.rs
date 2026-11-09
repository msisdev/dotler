//! UI-independent command execution observer port and preview models.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::engine::EngineError;

/// Classification of the planned action on an OS or repository file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlanActionKind {
    Okay,
    Skip,
    Create,
    Overwrite,
    Delete,
    Untrack,
}

impl PlanActionKind {
    /// Returns `true` if this action represents a mutating update.
    pub fn is_update(&self) -> bool {
        matches!(
            self,
            Self::Create | Self::Overwrite | Self::Delete | Self::Untrack
        )
    }
}

/// Direction and cryptographic conversion kind for a planned file operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlanDirection {
    PlainToRepo,
    EncryptToRepo,
    PlainToOs,
    DecryptToOs,
    DecryptInRepo,
}

/// UI-independent preview entry produced by the 6 mutating dotfile commands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanPreviewEntry {
    pub group_name: String,
    pub os_path: PathBuf,
    pub os_action: PlanActionKind,
    pub repo_path: PathBuf,
    pub repo_action: PlanActionKind,
    pub direction: PlanDirection,
}

impl PlanPreviewEntry {
    /// Returns `true` if either the OS side or repository side is a mutating update.
    pub fn is_update(&self) -> bool {
        self.os_action.is_update() || self.repo_action.is_update()
    }
}

/// Port trait separating the synchronization engine from interactive terminal rendering.
pub trait CommandObserver {
    /// Renders or inspects the planned entries and returns `Ok(true)` if execution should proceed.
    fn confirm_plan(
        &mut self,
        entries: &[PlanPreviewEntry],
        dry_run: bool,
    ) -> Result<bool, EngineError>;

    /// Notifies the observer that a single file operation has completed.
    fn on_file_progress(
        &mut self,
        group_name: &str,
        group_base_path: &Path,
        relative_path: &str,
        file_size: Option<u64>,
    );

    /// Notifies the observer that all planned file operations have completed.
    fn finish_progress(&mut self);
}

/// Non-interactive observer used by `--json` CLI mode, MCP tool calls, and programmatic tests.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopObserver;

impl CommandObserver for NoopObserver {
    fn confirm_plan(
        &mut self,
        _entries: &[PlanPreviewEntry],
        dry_run: bool,
    ) -> Result<bool, EngineError> {
        Ok(!dry_run)
    }

    fn on_file_progress(
        &mut self,
        _group_name: &str,
        _group_base_path: &Path,
        _relative_path: &str,
        _file_size: Option<u64>,
    ) {
    }

    fn finish_progress(&mut self) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_observer_respects_dry_run_flag() {
        let mut obs = NoopObserver;
        assert!(!obs.confirm_plan(&[], true).unwrap());
        assert!(obs.confirm_plan(&[], false).unwrap());
    }

    #[test]
    fn plan_preview_entry_identifies_updates() {
        let ok_entry = PlanPreviewEntry {
            group_name: "nvim".to_string(),
            os_path: PathBuf::from("~/.config/nvim/init.lua"),
            os_action: PlanActionKind::Okay,
            repo_path: PathBuf::from("~/dotfiles/nvim/init.lua"),
            repo_action: PlanActionKind::Okay,
            direction: PlanDirection::PlainToRepo,
        };
        assert!(!ok_entry.is_update());

        for kind in [
            PlanActionKind::Create,
            PlanActionKind::Overwrite,
            PlanActionKind::Delete,
            PlanActionKind::Untrack,
        ] {
            let entry = PlanPreviewEntry {
                repo_action: kind,
                ..ok_entry.clone()
            };
            assert!(entry.is_update());
        }
    }
}
