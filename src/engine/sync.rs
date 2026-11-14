//! Local dotfile collection (`import`) and synchronization engine facade.

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::config::local::expand_tilde;
use crate::config::repo::{
    OsInfo, RepoConfig, is_symlink, resolve_group_target_path, unrender_home_template,
    validate_os_target_path,
};
pub use crate::config::state::{ATOMIC_REPLACE_RETRIES, TMP_FILE_PREFIX, write_file_safe};
use crate::config::state::{DotlerLockGuard, StateDb, SyncedFileRecord};
use crate::core::context::CoreContext;
use crate::core::vault_loader::{has_encrypted_rules, unlock_vault_if_needed};
use crate::crypto::ExposeSecret;
use crate::crypto::vault::{EncryptedFile, VaultKey};
use crate::engine::EngineError;
pub use crate::engine::check::{FileActionPlan, FileSyncStatus, plan};
pub use crate::engine::export::{export_files, run_export};
use crate::engine::observer::{
    CommandObserver, NoopObserver, PlanActionKind, PlanDirection, PlanPreviewEntry,
};
pub use crate::engine::tidy::{TidyOrphanPolicy, TidyReport, tidy, tidy_groups};

/// Summary report returned by `import` and `export` operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SyncReport {
    pub processed: usize,
    pub skipped: usize,
    pub conflicts: Vec<PathBuf>,
}

/// Execution context for synchronizing a single repository.
pub struct SyncEngine<'a> {
    pub repo_label: String,
    pub repo_dir: PathBuf,
    pub repo_config: &'a RepoConfig,
    pub state_db: &'a StateDb,
    pub devices: Vec<String>,
    pub os_info: OsInfo,
    pub vault_key: Option<&'a VaultKey>,
    pub home_dir: Option<PathBuf>,
}

struct PreparedImport<'p> {
    plan: &'p FileActionPlan,
    repo_payload_bytes: Vec<u8>,
    os_hash: String,
    file_size: u64,
    can_skip: bool,
}

impl<'a> SyncEngine<'a> {
    pub fn new(
        repo_label: impl Into<String>,
        repo_dir: impl Into<PathBuf>,
        repo_config: &'a RepoConfig,
        state_db: &'a StateDb,
        devices: Vec<String>,
        os_info: OsInfo,
        vault_key: Option<&'a VaultKey>,
    ) -> Self {
        Self {
            repo_label: repo_label.into(),
            repo_dir: repo_dir.into(),
            repo_config,
            state_db,
            devices,
            os_info,
            vault_key,
            home_dir: None,
        }
    }

    pub fn with_home_dir(mut self, home: impl Into<PathBuf>) -> Self {
        self.home_dir = Some(home.into());
        self
    }

    pub(crate) fn effective_home_dir(&self) -> PathBuf {
        if let Some(ref home) = self.home_dir {
            home.clone()
        } else {
            expand_tilde("~")
        }
    }

    pub(crate) fn expand_target_base(&self, base_str: &str) -> PathBuf {
        if let Some(ref home) = self.home_dir {
            if base_str == "~" {
                home.clone()
            } else if let Some(stripped) = base_str.strip_prefix("~/") {
                home.join(stripped)
            } else {
                PathBuf::from(base_str)
            }
        } else {
            expand_tilde(base_str)
        }
    }

    pub(crate) fn group_base_for(&self, group_name: &str) -> PathBuf {
        self.repo_config
            .groups
            .get(group_name)
            .and_then(|g| resolve_group_target_path(g, &self.devices, &self.os_info))
            .map(|s| self.expand_target_base(&s))
            .unwrap_or_else(|| self.effective_home_dir())
    }

    pub(crate) fn record_synced_file(
        &self,
        plan: &FileActionPlan,
        file_hash: String,
    ) -> Result<(), EngineError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        self.state_db.upsert_synced_file(&SyncedFileRecord {
            target_path: plan.target_os_path.to_string_lossy().to_string(),
            repo_label: self.repo_label.clone(),
            group_name: plan.group_name.clone(),
            relative_path: plan.relative_path.clone(),
            file_hash,
            updated_at: now,
        })?;
        Ok(())
    }

    /// 3-Way Hash Reconciliation (`plan`).
    pub fn plan(
        &self,
        group_filter: Option<&str>,
        lock: &DotlerLockGuard,
    ) -> Result<Vec<FileActionPlan>, EngineError> {
        crate::engine::check::plan(self, group_filter, lock)
    }

    /// Collects OS dotfiles into the repository using [`NoopObserver`].
    pub fn import_files(
        &self,
        plans: &[FileActionPlan],
        lock: &DotlerLockGuard,
        dry_run: bool,
    ) -> Result<SyncReport, EngineError> {
        let mut obs = NoopObserver;
        self.import_files_with_observer(plans, lock, dry_run, &mut obs)
    }

    /// Collects OS dotfiles into the repository with a [`CommandObserver`].
    pub fn import_files_with_observer(
        &self,
        plans: &[FileActionPlan],
        _lock: &DotlerLockGuard,
        dry_run: bool,
        observer: &mut dyn CommandObserver,
    ) -> Result<SyncReport, EngineError> {
        let home_dir = self.effective_home_dir();
        let mut prepared: Vec<PreparedImport> = Vec::new();
        let mut preview_entries: Vec<PlanPreviewEntry> = Vec::new();

        for plan in plans {
            if is_symlink(&plan.repo_file_path) {
                return Err(EngineError::HardBlockedPath {
                    path: plan.repo_file_path.clone(),
                    reason: "symbolic links are prohibited inside a dotler repository".to_string(),
                });
            }
            validate_os_target_path(&plan.target_os_path, &home_dir)?;
            if is_symlink(&plan.target_os_path) && !plan.target_os_path.is_file() {
                return Err(EngineError::HardBlockedPath {
                    path: plan.target_os_path.clone(),
                    reason: "broken symbolic link at OS target path cannot be imported".to_string(),
                });
            }
            if !plan.target_os_path.is_file() {
                continue;
            }

            let os_bytes = fs::read(&plan.target_os_path)?;
            let file_size = os_bytes.len() as u64;
            let os_hash = blake3::hash(&os_bytes).to_hex().to_string();
            let repo_payload_bytes = if plan.is_template {
                unrender_home_template(&os_bytes, &home_dir, &plan.relative_path)?
            } else {
                os_bytes
            };
            let repo_payload_hash = blake3::hash(&repo_payload_bytes).to_hex().to_string();
            let can_skip = can_skip_import(self, plan, &os_hash, &repo_payload_hash)?;

            let repo_action = if can_skip {
                PlanActionKind::Okay
            } else if plan.repo_file_path.is_file()
                || plan.repo_file_path.with_extension("").is_file()
                || PathBuf::from(format!("{}.enc", plan.repo_file_path.display())).is_file()
            {
                PlanActionKind::Overwrite
            } else {
                PlanActionKind::Create
            };
            let direction = if plan.is_encrypted {
                PlanDirection::EncryptToRepo
            } else {
                PlanDirection::PlainToRepo
            };

            preview_entries.push(PlanPreviewEntry {
                group_name: plan.group_name.clone(),
                os_path: plan.target_os_path.clone(),
                os_action: PlanActionKind::Okay,
                repo_path: plan.repo_file_path.clone(),
                repo_action,
                direction,
            });
            prepared.push(PreparedImport {
                plan,
                repo_payload_bytes,
                os_hash,
                file_size,
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
                self.record_synced_file(plan, item.os_hash)?;
                report.skipped += 1;
                continue;
            }
            write_import_payload(self, plan, &item.repo_payload_bytes)?;
            self.record_synced_file(plan, item.os_hash)?;

            report.processed += 1;
            let group_base = self.group_base_for(&plan.group_name);
            observer.on_file_progress(
                &plan.group_name,
                &group_base,
                &plan.relative_path,
                Some(item.file_size),
            );
        }

        if has_updates {
            observer.finish_progress();
        }
        Ok(report)
    }

    /// Integrated Tidy (`tidy`) for an optional single group filter.
    pub fn tidy(
        &self,
        group_filter: Option<&str>,
        lock: &DotlerLockGuard,
        policy: TidyOrphanPolicy,
        dry_run: bool,
    ) -> Result<TidyReport, EngineError> {
        crate::engine::tidy::tidy(self, group_filter, lock, policy, dry_run)
    }

    /// Integrated Tidy (`tidy`) supporting zero, one, or multiple group filters.
    pub fn tidy_groups(
        &self,
        group_filters: &[String],
        lock: &DotlerLockGuard,
        policy: TidyOrphanPolicy,
        dry_run: bool,
    ) -> Result<TidyReport, EngineError> {
        crate::engine::tidy::tidy_groups(self, group_filters, lock, policy, dry_run)
    }
}

fn can_skip_import(
    engine: &SyncEngine,
    plan: &FileActionPlan,
    os_hash: &str,
    repo_payload_hash: &str,
) -> Result<bool, EngineError> {
    if plan.is_encrypted {
        let vault_key = engine.vault_key.ok_or_else(|| EngineError::VaultLocked {
            reason: "encrypted files detected but no vault key was provided".into(),
        })?;
        if !plan.repo_file_path.is_file() {
            return Ok(false);
        }
        if plan.db_hash.as_deref() == Some(os_hash) {
            return Ok(true);
        }
        if let Ok(enc_bytes) = fs::read(&plan.repo_file_path)
            && let Ok(enc_file) = EncryptedFile::from_bytes(&enc_bytes)
            && let Ok(decrypted) = vault_key.decrypt_file(&enc_file)
        {
            return Ok(blake3::hash(decrypted.expose_secret()).to_hex().to_string() == repo_payload_hash);
        }
        return Ok(false);
    }

    if plan.repo_file_path.is_file()
        && let Ok(existing_bytes) = fs::read(&plan.repo_file_path)
    {
        return Ok(blake3::hash(&existing_bytes).to_hex().to_string() == repo_payload_hash);
    }
    Ok(false)
}

fn write_import_payload(
    engine: &SyncEngine,
    plan: &FileActionPlan,
    repo_payload_bytes: &[u8],
) -> Result<(), EngineError> {
    if plan.is_encrypted {
        let vault_key = engine.vault_key.ok_or_else(|| EngineError::VaultLocked {
            reason: "encrypted files detected but no vault key was provided".into(),
        })?;
        let enc = vault_key.encrypt_file(repo_payload_bytes)?;
        write_file_safe(&plan.repo_file_path, &enc.to_bytes())?;
        let plain_counterpart = plan.repo_file_path.with_extension("");
        if plain_counterpart.is_file() {
            let _ = fs::remove_file(plain_counterpart);
        }
    } else {
        write_file_safe(&plan.repo_file_path, repo_payload_bytes)?;
        let enc_counterpart = PathBuf::from(format!("{}.enc", plan.repo_file_path.display()));
        if enc_counterpart.is_file() {
            let _ = fs::remove_file(enc_counterpart);
        }
    }
    Ok(())
}

pub(crate) fn collect_group_plans(
    engine: &SyncEngine,
    groups: &[String],
    lock: &DotlerLockGuard,
) -> Result<Vec<FileActionPlan>, EngineError> {
    if groups.is_empty() {
        return plan(engine, None, lock);
    }
    let mut plans = Vec::new();
    for g in groups {
        plans.append(&mut plan(engine, Some(g), lock)?);
    }
    Ok(plans)
}

/// Unified `import` command entry point shared by CLI (`dotler import`) and MCP (`dotler_import`).
pub fn run_import(
    ctx: &CoreContext,
    groups: &[String],
    _force: bool,
    dry_run: bool,
    lock: &DotlerLockGuard,
    observer: &mut dyn CommandObserver,
) -> Result<SyncReport, EngineError> {
    let local_cfg = ctx.local_config.get()?;
    let resolved = ctx.resolve_repo()?;
    let state_db = ctx.state_db.get()?;

    let needs_vault = has_encrypted_rules(&resolved.repo_config);
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
    sync_engine.import_files_with_observer(&plans, lock, dry_run, observer)
}

pub fn import_files(
    engine: &SyncEngine,
    plans: &[FileActionPlan],
    lock: &DotlerLockGuard,
    dry_run: bool,
) -> Result<SyncReport, EngineError> {
    engine.import_files(plans, lock, dry_run)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::state::DotlerLock;
    use std::path::Path;
    use std::time::Duration;

    struct RejectObserver;
    impl CommandObserver for RejectObserver {
        fn confirm_plan(&mut self, _: &[PlanPreviewEntry], _: bool) -> Result<bool, EngineError> {
            Ok(false)
        }
        fn on_file_progress(&mut self, _: &str, _: &Path, _: &str, _: Option<u64>) {}
        fn finish_progress(&mut self) {}
    }

    #[test]
    fn observer_cancellation_guarantees_zero_disk_mutation() {
        let tmp = tempfile::tempdir().unwrap();
        let home_dir = tmp.path().join("home");
        let repo_dir = tmp.path().join("repo");
        fs::create_dir_all(&home_dir).unwrap();
        fs::create_dir_all(repo_dir.join("shell")).unwrap();

        fs::write(home_dir.join(".bashrc"), b"local content\n").unwrap();
        fs::write(repo_dir.join("shell/.bashrc"), b"repo content\n").unwrap();

        let toml = "[shell]\nos-nux = \"~\"\nos-mac = \"~\"\nfiles = \".bashrc\"\n";
        let repo_cfg = RepoConfig::parse(toml).unwrap();
        let state_db = StateDb::open(&tmp.path().join("state.db")).unwrap();
        let lock = DotlerLock::new(tmp.path().join("dotler.lock"))
            .acquire(Duration::from_millis(500), Duration::from_millis(10))
            .unwrap();

        let engine = SyncEngine::new(
            "main",
            &repo_dir,
            &repo_cfg,
            &state_db,
            vec![],
            OsInfo::detect(),
            None,
        )
        .with_home_dir(&home_dir);

        let plans = engine.plan(None, &lock).unwrap();
        let mut obs = RejectObserver;

        let imp_rep = engine
            .import_files_with_observer(&plans, &lock, false, &mut obs)
            .unwrap();
        assert_eq!(imp_rep.processed, 0);
        assert_eq!(fs::read(repo_dir.join("shell/.bashrc")).unwrap(), b"repo content\n");

        let exp_rep = engine
            .export_files_with_observer(&plans, &lock, true, false, &mut obs)
            .unwrap();
        assert_eq!(exp_rep.processed, 0);
        assert_eq!(fs::read(home_dir.join(".bashrc")).unwrap(), b"local content\n");
    }
}
