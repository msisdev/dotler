//! Dotfile deployment (`export`) engine from repository to OS paths.

use std::fs;

use crate::config::repo::{is_symlink, render_home_template, validate_os_target_path};
use crate::config::state::{DotlerLockGuard, write_file_safe};
use crate::core::context::CoreContext;
use crate::core::vault_loader::{
    has_encrypted_repo_files, has_encrypted_rules, unlock_vault_if_needed,
};
use crate::crypto::ExposeSecret;
use crate::crypto::vault::EncryptedFile;
use crate::engine::EngineError;
use crate::engine::check::{FileActionPlan, FileSyncStatus};
use crate::engine::observer::{
    CommandObserver, NoopObserver, PlanActionKind, PlanDirection, PlanPreviewEntry,
};
use crate::engine::sync::{SyncEngine, SyncReport, collect_group_plans};

struct PreparedExport<'p> {
    plan: &'p FileActionPlan,
    plaintext_bytes: Vec<u8>,
    repo_hash: String,
    can_skip: bool,
}

impl<'a> SyncEngine<'a> {
    /// Deploys repository dotfiles to the OS filesystem using [`NoopObserver`].
    pub fn export_files(
        &self,
        plans: &[FileActionPlan],
        lock: &DotlerLockGuard,
        force: bool,
        dry_run: bool,
    ) -> Result<SyncReport, EngineError> {
        let mut obs = NoopObserver;
        self.export_files_with_observer(plans, lock, force, dry_run, &mut obs)
    }

    /// Deploys repository dotfiles to the OS filesystem with a [`CommandObserver`].
    pub fn export_files_with_observer(
        &self,
        plans: &[FileActionPlan],
        _lock: &DotlerLockGuard,
        force: bool,
        dry_run: bool,
        observer: &mut dyn CommandObserver,
    ) -> Result<SyncReport, EngineError> {
        let home_dir = self.effective_home_dir();
        let mut prepared: Vec<PreparedExport> = Vec::new();
        let mut preview_entries: Vec<PlanPreviewEntry> = Vec::new();

        for plan in plans {
            if is_symlink(&plan.repo_file_path) {
                return Err(EngineError::HardBlockedPath {
                    path: plan.repo_file_path.clone(),
                    reason: "symbolic links are prohibited inside a dotler repository".to_string(),
                });
            }
            if plan.status == FileSyncStatus::EncryptionMismatch {
                return Err(encryption_mismatch_err(plan));
            }
            if !plan.repo_file_path.is_file() {
                continue;
            }

            validate_os_target_path(&plan.target_os_path, &home_dir)?;
            let raw_plain_bytes = read_repo_plaintext(self, plan)?;
            let plaintext_bytes = if plan.is_template {
                render_home_template(&raw_plain_bytes, &home_dir, &plan.relative_path)?
            } else {
                raw_plain_bytes
            };
            let repo_hash = blake3::hash(&plaintext_bytes).to_hex().to_string();

            let target_is_symlink = is_symlink(&plan.target_os_path);
            let can_skip = check_export_target_conflict(plan, &repo_hash, target_is_symlink, force)?;

            let os_action = if can_skip {
                PlanActionKind::Okay
            } else if plan.target_os_path.is_file() || target_is_symlink {
                PlanActionKind::Overwrite
            } else {
                PlanActionKind::Create
            };
            let direction = if plan.is_encrypted {
                PlanDirection::DecryptToOs
            } else {
                PlanDirection::PlainToOs
            };

            preview_entries.push(PlanPreviewEntry {
                group_name: plan.group_name.clone(),
                os_path: plan.target_os_path.clone(),
                os_action,
                repo_path: plan.repo_file_path.clone(),
                repo_action: PlanActionKind::Okay,
                direction,
            });
            prepared.push(PreparedExport {
                plan,
                plaintext_bytes,
                repo_hash,
                can_skip,
            });
        }

        let has_updates = preview_entries.iter().any(|e| e.is_update());
        let approved = observer.confirm_plan(&preview_entries, dry_run)?;
        if dry_run {
            let mut sim = SyncReport::default();
            for item in &prepared {
                if item.can_skip {
                    sim.skipped += 1;
                } else {
                    sim.processed += 1;
                }
            }
            return Ok(sim);
        }
        if has_updates && !approved {
            return Ok(SyncReport::default());
        }

        let mut report = SyncReport::default();
        for item in prepared {
            let plan = item.plan;
            if item.can_skip {
                self.record_synced_file(plan, item.repo_hash)?;
                report.skipped += 1;
                continue;
            }
            let file_size = item.plaintext_bytes.len() as u64;
            write_file_safe(&plan.target_os_path, &item.plaintext_bytes)?;
            self.record_synced_file(plan, item.repo_hash)?;

            report.processed += 1;
            let group_base = self.group_base_for(&plan.group_name);
            observer.on_file_progress(&plan.group_name, &group_base, &plan.relative_path, Some(file_size));
        }

        if has_updates {
            observer.finish_progress();
        }
        Ok(report)
    }
}

fn read_repo_plaintext(engine: &SyncEngine, plan: &FileActionPlan) -> Result<Vec<u8>, EngineError> {
    if !plan.is_encrypted {
        return Ok(fs::read(&plan.repo_file_path)?);
    }
    let vault_key = engine.vault_key.ok_or_else(|| EngineError::VaultLocked {
        reason: "encrypted files detected but no vault key was provided".into(),
    })?;
    let raw_enc = fs::read(&plan.repo_file_path)?;
    let enc_file = EncryptedFile::from_bytes(&raw_enc)?;
    Ok(vault_key.decrypt_file(&enc_file)?.expose_secret().clone())
}

fn check_export_target_conflict(
    plan: &FileActionPlan,
    repo_hash: &str,
    target_is_symlink: bool,
    force: bool,
) -> Result<bool, EngineError> {
    if !plan.target_os_path.is_file() {
        return Ok(false);
    }
    let os_bytes = fs::read(&plan.target_os_path)?;
    let os_hash = blake3::hash(&os_bytes).to_hex().to_string();
    if os_hash == repo_hash && !target_is_symlink {
        return Ok(true);
    }
    if os_hash != repo_hash
        && !force
        && (plan.status == FileSyncStatus::ModifiedLocally
            || plan.status == FileSyncStatus::Conflict
            || (plan.db_hash.is_some() && plan.db_hash.as_deref() != Some(&os_hash)))
    {
        return Err(EngineError::SyncConflict {
            path: plan.target_os_path.clone(),
            reason: "target file was modified locally and does not match repository. Use --force to overwrite."
                .to_string(),
        });
    }
    Ok(false)
}

fn encryption_mismatch_err(plan: &FileActionPlan) -> EngineError {
    EngineError::EncryptionMismatch {
        path: plan.repo_file_path.clone(),
        reason: format!(
            "Repository file '{}' format conflicts with encryption rule in dotler.toml. Run 'dotler tidy' to reconcile format.",
            plan.relative_path
        ),
    }
}

/// Unified `export` command entry point shared by CLI (`dotler export`) and MCP (`dotler_export`).
pub fn run_export(
    ctx: &CoreContext,
    groups: &[String],
    force: bool,
    dry_run: bool,
    lock: &DotlerLockGuard,
    observer: &mut dyn CommandObserver,
) -> Result<SyncReport, EngineError> {
    let local_cfg = ctx.local_config.get()?;
    let resolved = ctx.resolve_repo()?;
    let state_db = ctx.state_db.get()?;

    let needs_vault = has_encrypted_rules(&resolved.repo_config)
        || has_encrypted_repo_files(&resolved.repo_path, &resolved.repo_config);
    let vault_key = unlock_vault_if_needed(
        &resolved.repo_config,
        local_cfg.use_keyring,
        ctx.is_interactive,
        needs_vault,
    )?;

    let sync_engine = SyncEngine::new(
        &resolved.label,
        &resolved.repo_path,
        &resolved.repo_config,
        state_db,
        resolved.devices,
        resolved.os_info,
        vault_key.as_ref(),
    );

    let plans = collect_group_plans(&sync_engine, groups, lock)?;
    for p in &plans {
        if p.status == FileSyncStatus::EncryptionMismatch {
            return Err(encryption_mismatch_err(p));
        }
    }

    sync_engine.export_files_with_observer(&plans, lock, force, dry_run, observer)
}

pub fn export_files(
    engine: &SyncEngine,
    plans: &[FileActionPlan],
    lock: &DotlerLockGuard,
    force: bool,
    dry_run: bool,
) -> Result<SyncReport, EngineError> {
    engine.export_files(plans, lock, force, dry_run)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::repo::{OsInfo, RepoConfig};
    use crate::config::state::{DotlerLock, StateDb};
    use std::time::Duration;

    #[test]
    fn export_dry_run_and_conflict_guard_behave_deterministically() {
        let tmp = tempfile::tempdir().unwrap();
        let home_dir = tmp.path().join("home");
        let repo_dir = tmp.path().join("repo");
        fs::create_dir_all(&home_dir).unwrap();
        fs::create_dir_all(repo_dir.join("shell")).unwrap();
        fs::write(repo_dir.join("shell/.bashrc"), b"repo v1\n").unwrap();

        let repo_cfg = RepoConfig::parse("[shell]\nos-nux = \"~\"\nos-mac = \"~\"\nfiles = \".bashrc\"\n").unwrap();
        let state_db = StateDb::open(&tmp.path().join("state.db")).unwrap();
        let lock = DotlerLock::new(tmp.path().join("dotler.lock"))
            .acquire(Duration::from_millis(500), Duration::from_millis(10))
            .unwrap();
        let engine = SyncEngine::new("main", &repo_dir, &repo_cfg, &state_db, vec![], OsInfo::detect(), None)
            .with_home_dir(&home_dir);

        let plans = engine.plan(None, &lock).unwrap();
        let dry = export_files(&engine, &plans, &lock, false, true).unwrap();
        assert_eq!(dry.processed, 1);
        assert!(!home_dir.join(".bashrc").exists());

        fs::write(home_dir.join(".bashrc"), b"local edit\n").unwrap();
        let plans_conflict = engine.plan(None, &lock).unwrap();
        let err = export_files(&engine, &plans_conflict, &lock, false, false).unwrap_err();
        assert_eq!(err.error_code(), "LOCAL_EDIT_CONFLICT");
    }
}
