//! Interactive CLI observer bridging `engine::observer::CommandObserver` with `tui::*`.

use std::io::Write;
use std::path::Path;

use serde::Serialize;

use crate::cli::output::{EXIT_SUCCESS, InlineRender, render_success_to};
use crate::engine::EngineError;
use crate::engine::observer::{
    CommandObserver, NoopObserver, PlanActionKind, PlanDirection, PlanPreviewEntry,
};
use crate::tui::confirm::{ConfirmError, ConfirmPrompt, DEFAULT_CONFIRM_TITLE, confirm_proceed_to};
use crate::tui::preview::{BadgeOp, PreviewArrow, PreviewItem, render_preview_to};
use crate::tui::progress::ProgressReporter;

/// Interactive terminal observer bridging `engine::observer::CommandObserver` with `tui::*`.
pub(crate) struct TuiObserver<'a, W: Write> {
    pub(crate) writer: &'a mut W,
    pub(crate) command_name: &'static str,
    pub(crate) view_all: bool,
    pub(crate) yes: bool,
    pub(crate) is_interactive: bool,
    pub(crate) approved: bool,
    pub(crate) progress: Option<ProgressReporter>,
}

impl<'a, W: Write> TuiObserver<'a, W> {
    pub(crate) fn new(
        writer: &'a mut W,
        command_name: &'static str,
        view_all: bool,
        yes: bool,
        is_interactive: bool,
    ) -> Self {
        Self {
            writer,
            command_name,
            view_all,
            yes,
            is_interactive,
            approved: false,
            progress: None,
        }
    }
}

pub(crate) fn map_badge(kind: PlanActionKind) -> BadgeOp {
    match kind {
        PlanActionKind::Okay => BadgeOp::Okay,
        PlanActionKind::Skip => BadgeOp::Skip,
        PlanActionKind::Create => BadgeOp::Create,
        PlanActionKind::Overwrite => BadgeOp::Overwrite,
        PlanActionKind::Delete => BadgeOp::Delete,
        PlanActionKind::Untrack => BadgeOp::Untrack,
    }
}

pub(crate) fn map_arrow(dir: PlanDirection) -> PreviewArrow {
    match dir {
        PlanDirection::PlainToRepo => PreviewArrow::PlainToRepo,
        PlanDirection::EncryptToRepo => PreviewArrow::EncryptToRepo,
        PlanDirection::PlainToOs => PreviewArrow::PlainToOs,
        PlanDirection::DecryptToOs => PreviewArrow::DecryptToOs,
        PlanDirection::DecryptInRepo => PreviewArrow::DecryptInRepo,
    }
}

impl<W: Write> CommandObserver for TuiObserver<'_, W> {
    fn confirm_plan(
        &mut self,
        entries: &[PlanPreviewEntry],
        dry_run: bool,
    ) -> Result<bool, EngineError> {
        let items: Vec<PreviewItem> = entries
            .iter()
            .map(|e| PreviewItem {
                group_name: e.group_name.clone(),
                os_path: e.os_path.clone(),
                os_op: map_badge(e.os_action),
                repo_path: e.repo_path.clone(),
                repo_op: map_badge(e.repo_action),
                arrow: map_arrow(e.direction),
            })
            .collect();

        let counts = render_preview_to(self.writer, &items, self.view_all)?;
        let total_updates = counts.total_updates();
        if total_updates == 0 || dry_run {
            return Ok(false);
        }

        if self.yes {
            self.approved = true;
            self.progress = Some(ProgressReporter::new(total_updates, true));
            return Ok(true);
        }

        if !self.is_interactive && !ConfirmPrompt::has_mock_or_env_input() {
            return Err(EngineError::NonInteractiveConfirmationRequired {
                command: self.command_name.to_string(),
            });
        }

        let approved = match confirm_proceed_to(self.writer, DEFAULT_CONFIRM_TITLE) {
            Ok(val) => val,
            Err(ConfirmError::NonTtyError) => {
                return Err(EngineError::NonInteractiveConfirmationRequired {
                    command: self.command_name.to_string(),
                });
            }
            Err(ConfirmError::TerminalIoError(e)) => return Err(EngineError::Io(e)),
        };

        if approved {
            self.approved = true;
            self.progress = Some(ProgressReporter::new(total_updates, true));
        }

        Ok(approved)
    }

    fn on_file_progress(
        &mut self,
        group_name: &str,
        group_base_path: &Path,
        relative_path: &str,
        file_size: Option<u64>,
    ) {
        if let Some(ref mut prog) = self.progress {
            let _ = prog.inc_to(
                self.writer,
                group_name,
                group_base_path,
                relative_path,
                file_size,
            );
        }
    }

    fn finish_progress(&mut self) {
        if let Some(ref mut prog) = self.progress {
            let _ = prog.finish_to(self.writer);
        }
    }
}

/// Runs an engine workflow with either a silent `NoopObserver` (JSON) or `TuiObserver` (interactive).
#[allow(clippy::too_many_arguments)]
pub(crate) fn execute_with_observer<W, R, O, F>(
    stdout: &mut W,
    command_name: &'static str,
    json_mode: bool,
    view_all: bool,
    yes: bool,
    is_interactive: bool,
    op: F,
    to_render: impl FnOnce(R) -> O,
) -> Result<i32, EngineError>
where
    W: Write,
    O: Serialize + InlineRender,
    F: FnOnce(&mut dyn CommandObserver) -> Result<R, EngineError>,
{
    if json_mode {
        let mut obs = NoopObserver;
        let report = op(&mut obs)?;
        return Ok(render_success_to(stdout, command_name, &to_render(report), true));
    }

    let mut obs = TuiObserver::new(stdout, command_name, view_all, yes, is_interactive);
    let report = op(&mut obs)?;
    let approved = obs.approved;
    if approved {
        render_success_to(stdout, command_name, &to_render(report), false);
    }
    Ok(EXIT_SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn observer_dry_run_never_approves_or_mutates() {
        let mut out = Vec::new();
        let mut obs = TuiObserver::new(&mut out, "import", false, true, true);
        let entry = PlanPreviewEntry {
            group_name: "shell".to_string(),
            os_path: PathBuf::from("/tmp/.bashrc"),
            os_action: PlanActionKind::Okay,
            repo_path: PathBuf::from("/tmp/repo/.bashrc"),
            repo_action: PlanActionKind::Create,
            direction: PlanDirection::PlainToRepo,
        };
        assert!(!obs.confirm_plan(&[entry], true).unwrap());
        assert!(!obs.approved);
        assert_eq!(map_badge(PlanActionKind::Create), BadgeOp::Create);
        assert_eq!(map_arrow(PlanDirection::DecryptToOs), PreviewArrow::DecryptToOs);
    }
}
