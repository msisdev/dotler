//! Local dotfile collection (`import`) and synchronization engine facade.

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::config::local::expand_tilde;
use crate::config::repo::{
    OsInfo, RepoConfig, group_repo_dir, is_cwd_group_path, is_home_group_path, is_symlink,
    prune_empty_parent_dirs, unrender_home_template, validate_os_target_path_with_home,
    validate_repo_target_disjointness,
};
pub use crate::config::state::{ATOMIC_REPLACE_RETRIES, TMP_FILE_PREFIX, write_file_safe};
use crate::config::state::{DotlerLockGuard, StateDb, SyncedFileRecord};
use crate::core::context::CoreContext;
use crate::core::vault_loader::{has_encrypted_rules, unlock_vault_if_needed};
use crate::crypto::ExposeSecret;
use crate::crypto::vault::{
    CONTENT_ENC_SUFFIX, EncryptedFile, FULL_ENC_SUFFIX, FullEncryptedFile,
    LEGACY_CONTENT_ENC_SUFFIX, LEGACY_FULL_ENC_SUFFIX, VaultKey, is_legacy_dotler_archive_bytes,
};
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
    pub cwd: Option<PathBuf>,
}

struct PreparedImport<'p> {
    plan: &'p FileActionPlan,
    op: PreparedImportOp,
}

enum PreparedImportOp {
    Write {
        repo_payload_bytes: Vec<u8>,
        os_hash: String,
        file_size: u64,
        can_skip: bool,
    },
    PruneDeleted {
        repo_paths_to_remove: Vec<PathBuf>,
    },
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
            cwd: None,
        }
    }

    pub fn with_home_dir(mut self, home: impl Into<PathBuf>) -> Self {
        self.home_dir = Some(home.into());
        self
    }

    pub fn with_cwd(mut self, cwd: impl Into<PathBuf>) -> Self {
        self.cwd = Some(cwd.into());
        self
    }

    pub(crate) fn effective_home_dir(&self) -> PathBuf {
        if let Some(ref home) = self.home_dir {
            home.clone()
        } else {
            expand_tilde("~")
        }
    }

    pub(crate) fn effective_cwd(&self) -> Result<PathBuf, EngineError> {
        match &self.cwd {
            Some(cwd) => Ok(cwd.clone()),
            None => Ok(std::env::current_dir()?),
        }
    }

    pub(crate) fn expand_target_base_checked(
        &self,
        base_str: &str,
    ) -> Result<(PathBuf, PathBuf), EngineError> {
        if is_home_group_path(base_str) {
            let home = self.effective_home_dir();
            let rel = base_str.strip_prefix("~/").unwrap_or("").trim_matches('/');
            let target = if rel.is_empty() {
                home.clone()
            } else {
                home.join(rel)
            };
            return Ok((target, home));
        }

        if is_cwd_group_path(base_str) {
            let cwd = self.effective_cwd()?;
            let mut rel = base_str
                .strip_prefix('.')
                .unwrap_or(base_str)
                .trim_start_matches('/');
            while let Some(next) = rel.strip_prefix("./") {
                rel = next.trim_start_matches('/');
            }
            let rel = rel.trim_end_matches('/');
            let target = if rel.is_empty() || rel == "." {
                cwd.clone()
            } else {
                cwd.join(rel)
            };
            return Ok((target, cwd));
        }

        Ok((PathBuf::from(base_str), self.effective_home_dir()))
    }

    pub(crate) fn expand_target_base(&self, base_str: &str) -> PathBuf {
        self.expand_target_base_checked(base_str)
            .map(|(target, _)| target)
            .unwrap_or_else(|_| PathBuf::from(base_str))
    }

    pub(crate) fn boundary_for_group(&self, group_name: &str) -> Result<PathBuf, EngineError> {
        if let Some(base_str) =
            self.repo_config
                .resolve_target_path(group_name, &self.devices, &self.os_info)
        {
            let (_, boundary) = self.expand_target_base_checked(&base_str)?;
            return Ok(boundary);
        }
        Ok(self.effective_home_dir())
    }

    pub(crate) fn group_base_for(&self, group_name: &str) -> PathBuf {
        self.repo_config
            .resolve_target_path(group_name, &self.devices, &self.os_info)
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
        lock: &DotlerLockGuard,
        dry_run: bool,
        observer: &mut dyn CommandObserver,
    ) -> Result<SyncReport, EngineError> {
        self.import_files_with_options(plans, lock, false, dry_run, observer)
    }

    /// Collects OS dotfiles into the repository with explicit `force` and [`CommandObserver`].
    pub fn import_files_with_options(
        &self,
        plans: &[FileActionPlan],
        _lock: &DotlerLockGuard,
        force: bool,
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
            let group_boundary = self.boundary_for_group(&plan.group_name)?;
            validate_os_target_path_with_home(&plan.target_os_path, &group_boundary, &home_dir)?;
            validate_repo_target_disjointness(
                &self.repo_dir,
                self.repo_config.groups.keys().map(String::as_str),
                &plan.target_os_path,
            )?;
            if is_symlink(&plan.target_os_path) && !plan.target_os_path.is_file() {
                return Err(EngineError::HardBlockedPath {
                    path: plan.target_os_path.clone(),
                    reason: "broken symbolic link at OS target path cannot be imported".to_string(),
                });
            }
            if !plan.target_os_path.is_file() {
                if !plan.target_os_path.exists()
                    && !is_symlink(&plan.target_os_path)
                    && plan.status == FileSyncStatus::MissingLocally
                    && plan.db_hash.is_some()
                {
                    let counterparts = all_repo_paths_for_plan(self, plan);
                    let mut repo_paths_to_remove = Vec::new();
                    for candidate in
                        std::iter::once(&plan.repo_file_path).chain(counterparts.iter())
                    {
                        if is_symlink(candidate) {
                            return Err(EngineError::HardBlockedPath {
                                path: candidate.clone(),
                                reason: "symbolic links are prohibited inside a dotler repository"
                                    .to_string(),
                            });
                        }
                        if candidate.is_file() && !repo_paths_to_remove.contains(candidate) {
                            repo_paths_to_remove.push(candidate.clone());
                        }
                    }
                    if !repo_paths_to_remove.is_empty() {
                        let direction = if plan.is_encrypted {
                            PlanDirection::EncryptToRepo
                        } else {
                            PlanDirection::PlainToRepo
                        };
                        preview_entries.push(PlanPreviewEntry {
                            group_name: plan.group_name.clone(),
                            os_path: plan.target_os_path.clone(),
                            os_action: PlanActionKind::Okay,
                            repo_path: repo_paths_to_remove[0].clone(),
                            repo_action: PlanActionKind::Delete,
                            direction,
                        });
                    }
                    prepared.push(PreparedImport {
                        plan,
                        op: PreparedImportOp::PruneDeleted {
                            repo_paths_to_remove,
                        },
                    });
                }
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
            let can_skip = can_skip_import(self, plan, &os_hash, &repo_payload_hash, force)?;
            let counterparts = all_repo_paths_for_plan(self, plan);

            let repo_action = if can_skip {
                PlanActionKind::Okay
            } else if plan.repo_file_path.is_file() || counterparts.iter().any(|p| p.is_file()) {
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
                op: PreparedImportOp::Write {
                    repo_payload_bytes,
                    os_hash,
                    file_size,
                    can_skip,
                },
            });
        }

        let has_updates = preview_entries.iter().any(|e| e.is_update());
        let approved = observer.confirm_plan(&preview_entries, dry_run)?;
        if dry_run {
            let mut sim = SyncReport::default();
            for item in &prepared {
                match &item.op {
                    PreparedImportOp::Write { can_skip: true, .. } => sim.skipped += 1,
                    PreparedImportOp::Write {
                        can_skip: false, ..
                    } => sim.processed += 1,
                    PreparedImportOp::PruneDeleted {
                        repo_paths_to_remove,
                    } if !repo_paths_to_remove.is_empty() => sim.processed += 1,
                    PreparedImportOp::PruneDeleted { .. } => {}
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
            match item.op {
                PreparedImportOp::Write {
                    repo_payload_bytes,
                    os_hash,
                    file_size,
                    can_skip,
                } => {
                    if can_skip {
                        self.record_synced_file(plan, os_hash)?;
                        report.skipped += 1;
                        continue;
                    }
                    write_import_payload(self, plan, &repo_payload_bytes)?;
                    self.record_synced_file(plan, os_hash)?;

                    report.processed += 1;
                    let group_base = self.group_base_for(&plan.group_name);
                    observer.on_file_progress(
                        &plan.group_name,
                        &group_base,
                        &plan.relative_path,
                        Some(file_size),
                    );
                }
                PreparedImportOp::PruneDeleted {
                    repo_paths_to_remove,
                } => {
                    let has_repo_files = !repo_paths_to_remove.is_empty();
                    let g_repo_dir = group_repo_dir(&self.repo_dir, &plan.group_name);
                    for repo_path in &repo_paths_to_remove {
                        if repo_path.is_file() {
                            fs::remove_file(repo_path)?;
                        }
                        prune_empty_parent_dirs(repo_path, &g_repo_dir);
                    }
                    self.state_db
                        .remove_synced_file(&plan.target_os_path.to_string_lossy())?;

                    if has_repo_files {
                        report.processed += 1;
                        let group_base = self.group_base_for(&plan.group_name);
                        observer.on_file_progress(
                            &plan.group_name,
                            &group_base,
                            &plan.relative_path,
                            None,
                        );
                    }
                }
            }
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

fn all_repo_paths_for_plan(engine: &SyncEngine, plan: &FileActionPlan) -> Vec<PathBuf> {
    let g_repo_dir = group_repo_dir(&engine.repo_dir, &plan.group_name);
    let mut paths = vec![
        g_repo_dir.join(&plan.relative_path),
        g_repo_dir.join(format!("{}{CONTENT_ENC_SUFFIX}", plan.relative_path)),
    ];
    let expected_vid = engine
        .repo_config
        .vault
        .as_ref()
        .map(|v| v.vault_id.as_str());
    let legacy_enc = g_repo_dir.join(format!("{}{LEGACY_CONTENT_ENC_SUFFIX}", plan.relative_path));
    if legacy_enc != plan.repo_file_path
        && legacy_enc.is_file()
        && fs::read(&legacy_enc)
            .map(|b| is_legacy_dotler_archive_bytes(&b, expected_vid))
            .unwrap_or(false)
    {
        paths.push(legacy_enc);
    }
    if let Some(key) = engine.vault_key {
        let fenc_name = key.derive_full_enc_filename(&plan.relative_path);
        paths.push(g_repo_dir.join(&fenc_name));
        if let Some(stem) = fenc_name.strip_suffix(FULL_ENC_SUFFIX) {
            let legacy_fenc = g_repo_dir.join(format!("{stem}{LEGACY_FULL_ENC_SUFFIX}"));
            if legacy_fenc.is_file()
                && fs::read(&legacy_fenc)
                    .map(|b| is_legacy_dotler_archive_bytes(&b, expected_vid))
                    .unwrap_or(false)
            {
                paths.push(legacy_fenc);
            }
        }
    }
    paths
}

fn can_skip_import(
    engine: &SyncEngine,
    plan: &FileActionPlan,
    os_hash: &str,
    repo_payload_hash: &str,
    force: bool,
) -> Result<bool, EngineError> {
    if plan.is_encrypted {
        let vault_key = engine.vault_key.ok_or_else(|| EngineError::VaultLocked {
            reason: "encrypted files detected but no vault key was provided".into(),
        })?;
        if force || !plan.repo_file_path.is_file() {
            return Ok(false);
        }
        if plan.db_hash.as_deref() == Some(os_hash) {
            return Ok(true);
        }
        if plan.is_full_encrypted {
            if let Some(fname) = plan.repo_file_path.file_name().and_then(|s| s.to_str())
                && let Ok(fenc_bytes) = fs::read(&plan.repo_file_path)
                && let Ok(fenc_file) = FullEncryptedFile::from_bytes(&fenc_bytes)
                && let Ok((dec_rel, decrypted)) = vault_key.decrypt_full_file(fname, &fenc_file)
                && dec_rel == plan.relative_path
            {
                return Ok(blake3::hash(decrypted.expose_secret()).to_hex().to_string()
                    == repo_payload_hash);
            }
            return Ok(false);
        }
        if let Ok(enc_bytes) = fs::read(&plan.repo_file_path)
            && let Ok(enc_file) = EncryptedFile::from_bytes(&enc_bytes)
            && let Ok(decrypted) = vault_key.decrypt_file(&enc_file)
        {
            return Ok(
                blake3::hash(decrypted.expose_secret()).to_hex().to_string() == repo_payload_hash
            );
        }
        return Ok(false);
    }

    if force {
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
    let counterparts = all_repo_paths_for_plan(engine, plan);
    if plan.is_full_encrypted {
        let vault_key = engine.vault_key.ok_or_else(|| EngineError::VaultLocked {
            reason: "encrypted files detected but no vault key was provided".into(),
        })?;
        let (_, fenc) = vault_key.encrypt_full_file(&plan.relative_path, repo_payload_bytes)?;
        write_file_safe(&plan.repo_file_path, &fenc.to_bytes())?;
    } else if plan.is_encrypted {
        let vault_key = engine.vault_key.ok_or_else(|| EngineError::VaultLocked {
            reason: "encrypted files detected but no vault key was provided".into(),
        })?;
        let enc = vault_key.encrypt_file(repo_payload_bytes)?;
        write_file_safe(&plan.repo_file_path, &enc.to_bytes())?;
    } else {
        write_file_safe(&plan.repo_file_path, repo_payload_bytes)?;
    }

    let g_repo_dir = group_repo_dir(&engine.repo_dir, &plan.group_name);
    for other in counterparts {
        if other != plan.repo_file_path && other.is_file() {
            let _ = fs::remove_file(&other);
            prune_empty_parent_dirs(&other, &g_repo_dir);
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
    for g in groups {
        if !engine
            .repo_config
            .groups
            .keys()
            .any(|k| crate::config::repo::group_matches_filter(k, g))
        {
            return Err(EngineError::GroupNotFound {
                group: g.clone(),
                available: engine.repo_config.groups.keys().cloned().collect(),
            });
        }
    }
    let all = plan(engine, None, lock)?;
    Ok(all
        .into_iter()
        .filter(|p| {
            groups
                .iter()
                .any(|f| crate::config::repo::group_matches_filter(&p.group_name, f))
        })
        .collect())
}

/// Unified `import` command entry point shared by CLI (`dotler import`) and MCP (`dotler_import`).
pub fn run_import(
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

    let needs_vault = has_encrypted_rules(&resolved.repo_config);
    let vault_key = unlock_vault_if_needed(
        &resolved.repo_config,
        local_cfg.use_keyring,
        ctx.is_interactive,
        needs_vault,
    )?;

    let mut sync_engine = SyncEngine::new(
        &resolved.label,
        &resolved.repo_path,
        &resolved.repo_config,
        state_db,
        resolved.devices,
        resolved.os_info,
        vault_key.as_ref(),
    );
    if let Some(ref cwd) = ctx.cwd_override {
        sync_engine = sync_engine.with_cwd(cwd);
    }

    let plans = collect_group_plans(&sync_engine, groups, lock)?;
    sync_engine.import_files_with_options(&plans, lock, force, dry_run, observer)
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
        assert_eq!(
            fs::read(repo_dir.join("shell/.bashrc")).unwrap(),
            b"repo content\n"
        );

        let exp_rep = engine
            .export_files_with_observer(&plans, &lock, true, false, &mut obs)
            .unwrap();
        assert_eq!(exp_rep.processed, 0);
        assert_eq!(
            fs::read(home_dir.join(".bashrc")).unwrap(),
            b"local content\n"
        );
    }

    struct CaptureApproveObserver {
        entries: Vec<PlanPreviewEntry>,
    }
    impl CommandObserver for CaptureApproveObserver {
        fn confirm_plan(
            &mut self,
            entries: &[PlanPreviewEntry],
            _dry_run: bool,
        ) -> Result<bool, EngineError> {
            self.entries = entries.to_vec();
            Ok(true)
        }
        fn on_file_progress(&mut self, _: &str, _: &Path, _: &str, _: Option<u64>) {}
        fn finish_progress(&mut self) {}
    }

    #[test]
    fn import_prunes_locally_deleted_files_and_preserves_unexported_remote_files() {
        let tmp = tempfile::tempdir().unwrap();
        let home_dir = tmp.path().join("home");
        let repo_dir = tmp.path().join("repo");
        let notes_dir = home_dir.join(".config").join("notes");
        fs::create_dir_all(notes_dir.join("sub")).unwrap();
        fs::create_dir_all(repo_dir.join("notes")).unwrap();

        fs::write(notes_dir.join("keep.md"), b"keep\n").unwrap();
        fs::write(notes_dir.join("sub/old.md"), b"old\n").unwrap();

        let toml = "[notes]\nos-nux = \"~/.config/notes\"\nos-mac = \"~/.config/notes\"\nos-win = \"~/.config/notes\"\nos-bsd = \"~/.config/notes\"\nfiles = \"*\"\n";
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

        // Initial import populates repo and state.db.
        let initial_plans = engine.plan(None, &lock).unwrap();
        let initial_rep = engine.import_files(&initial_plans, &lock, false).unwrap();
        assert_eq!(initial_rep.processed, 2);

        // Locally rename sub/old.md -> sub/new.md, and add un-exported remote file in repo.
        fs::remove_file(notes_dir.join("sub/old.md")).unwrap();
        fs::write(notes_dir.join("sub/new.md"), b"new\n").unwrap();
        fs::write(repo_dir.join("notes/remote.md"), b"from another device\n").unwrap();

        let plans = engine.plan(None, &lock).unwrap();

        // Dry-run and observer rejection must not mutate repo or state.db.
        let dry_rep = engine.import_files(&plans, &lock, true).unwrap();
        assert_eq!(dry_rep.processed, 2);
        assert_eq!(dry_rep.skipped, 1);
        assert!(repo_dir.join("notes/sub/old.md").is_file());
        assert!(
            state_db
                .get_synced_file(&notes_dir.join("sub/old.md").to_string_lossy())
                .unwrap()
                .is_some()
        );

        let mut reject_obs = RejectObserver;
        let rej_rep = engine
            .import_files_with_observer(&plans, &lock, false, &mut reject_obs)
            .unwrap();
        assert_eq!(rej_rep.processed, 0);
        assert!(repo_dir.join("notes/sub/old.md").is_file());

        // Approved import collects sub/new.md, prunes sub/old.md + DB record, preserves remote.md.
        let mut cap_obs = CaptureApproveObserver {
            entries: Vec::new(),
        };
        let imp_rep = engine
            .import_files_with_observer(&plans, &lock, false, &mut cap_obs)
            .unwrap();
        assert_eq!(imp_rep.processed, 2);
        assert_eq!(imp_rep.skipped, 1);

        let delete_entry = cap_obs
            .entries
            .iter()
            .find(|e| e.repo_path == repo_dir.join("notes/sub/old.md"))
            .expect("preview must include delete entry for locally deleted file");
        assert_eq!(delete_entry.repo_action, PlanActionKind::Delete);

        assert!(!repo_dir.join("notes/sub/old.md").exists());
        assert!(repo_dir.join("notes/sub/new.md").is_file());
        assert!(repo_dir.join("notes/remote.md").is_file());
        assert!(
            state_db
                .get_synced_file(&notes_dir.join("sub/old.md").to_string_lossy())
                .unwrap()
                .is_none()
        );

        // Subsequent export deploys remote.md and never resurrects sub/old.md.
        let exp_plans = engine.plan(None, &lock).unwrap();
        let exp_rep = engine
            .export_files(&exp_plans, &lock, false, false)
            .unwrap();
        assert_eq!(exp_rep.processed, 1);
        assert!(notes_dir.join("remote.md").is_file());
        assert!(!notes_dir.join("sub/old.md").exists());
    }

    #[test]
    fn import_force_and_corrupted_or_foreign_enc_reencrypt_even_when_db_hash_matches() {
        let tmp = tempfile::tempdir().unwrap();
        let home_dir = tmp.path().join("home");
        let repo_dir = tmp.path().join("repo");
        fs::create_dir_all(&home_dir).unwrap();
        fs::create_dir_all(repo_dir.join("sec")).unwrap();

        let pass_a = crate::crypto::SecretString::new("vault-a-pass-111".to_string());
        let pass_b = crate::crypto::SecretString::new("vault-b-pass-222".to_string());
        let (vcfg_a, vkey_a, _) = crate::crypto::vault::init_vault(&pass_a).unwrap();
        let (_, vkey_b, _) = crate::crypto::vault::init_vault(&pass_b).unwrap();

        let toml = format!(
            "vault_id = \"{}\"\npassword_slot = \"{}\"\nrecovery_slot = \"{}\"\n\n[sec]\nos-nux = \"~\"\nos-mac = \"~\"\nos-win = \"~\"\nos-bsd = \"~\"\nfiles = \"secret.env enc\"\n",
            vcfg_a.vault_id, vcfg_a.password_slot, vcfg_a.recovery_slot
        );
        let repo_cfg = RepoConfig::parse(&toml).unwrap();
        let state_db = StateDb::open(&tmp.path().join("state.db")).unwrap();
        let lock = DotlerLock::new(tmp.path().join("dotler.lock"))
            .acquire(Duration::from_millis(500), Duration::from_millis(10))
            .unwrap();

        let secret_bytes = b"TOKEN=super_secret\n";
        fs::write(home_dir.join("secret.env"), secret_bytes).unwrap();

        let engine = SyncEngine::new(
            "main",
            &repo_dir,
            &repo_cfg,
            &state_db,
            vec![],
            OsInfo::detect(),
            Some(&vkey_a),
        )
        .with_home_dir(&home_dir);

        // 1. Initial import succeeds and records db_hash
        let plans1 = engine.plan(None, &lock).unwrap();
        let rep1 = engine.import_files(&plans1, &lock, false).unwrap();
        assert_eq!(rep1.processed, 1);

        // 2. Normal import skips unchanged file
        let plans2 = engine.plan(None, &lock).unwrap();
        let rep2 = engine.import_files(&plans2, &lock, false).unwrap();
        assert_eq!(rep2.skipped, 1);
        assert_eq!(rep2.processed, 0);

        // 3. `force = true` forces re-encryption even with identical db_hash
        let before_bytes = fs::read(repo_dir.join("sec/secret.env.dotler.enc")).unwrap();
        let mut obs = NoopObserver;
        let rep_force = engine
            .import_files_with_options(&plans2, &lock, true, false, &mut obs)
            .unwrap();
        assert_eq!(rep_force.processed, 1);
        assert_eq!(rep_force.skipped, 0);
        let after_force_bytes = fs::read(repo_dir.join("sec/secret.env.dotler.enc")).unwrap();
        assert_ne!(before_bytes, after_force_bytes);

        // 4. Replace repo .dotler.enc with foreign-vault ciphertext while db_hash still matches OS file:
        //    normal import preserves O(1) db_hash bypass, while `--force` re-encrypts under vkey_a.
        let foreign_enc = vkey_b.encrypt_file(secret_bytes).unwrap().to_bytes();
        fs::write(repo_dir.join("sec/secret.env.dotler.enc"), &foreign_enc).unwrap();
        let plans_foreign = engine.plan(None, &lock).unwrap();
        let rep_foreign_normal = engine.import_files(&plans_foreign, &lock, false).unwrap();
        assert_eq!(rep_foreign_normal.skipped, 1);
        assert_eq!(rep_foreign_normal.processed, 0);
        let rep_foreign_force = engine
            .import_files_with_options(&plans_foreign, &lock, true, false, &mut obs)
            .unwrap();
        assert_eq!(rep_foreign_force.processed, 1);
        let healed_foreign = EncryptedFile::from_bytes(
            &fs::read(repo_dir.join("sec/secret.env.dotler.enc")).unwrap(),
        )
        .unwrap();
        assert_eq!(healed_foreign.vault_id, vkey_a.vault_id_bytes());

        // 5. Corrupt repo .dotler.enc header while db_hash matches OS file:
        //    `--force` restores a valid .dotler.enc archive decryptable under vkey_a.
        fs::write(repo_dir.join("sec/secret.env.dotler.enc"), b"corrupt-data").unwrap();
        let plans_corrupt = engine.plan(None, &lock).unwrap();
        let rep_corrupt = engine
            .import_files_with_options(&plans_corrupt, &lock, true, false, &mut obs)
            .unwrap();
        assert_eq!(rep_corrupt.processed, 1);
        let healed_corrupt = EncryptedFile::from_bytes(
            &fs::read(repo_dir.join("sec/secret.env.dotler.enc")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            vkey_a
                .decrypt_file(&healed_corrupt)
                .unwrap()
                .expose_secret(),
            secret_bytes
        );
    }

    #[test]
    fn import_preview_does_not_misclassify_multi_dot_filename_overwrite() {
        let tmp = tempfile::tempdir().unwrap();
        let home_dir = tmp.path().join("home");
        let repo_dir = tmp.path().join("repo");
        fs::create_dir_all(&home_dir).unwrap();
        fs::create_dir_all(repo_dir.join("app")).unwrap();

        // Unrelated file `config` exists in repo, while `config.toml` does not.
        fs::write(repo_dir.join("app/config"), b"unrelated\n").unwrap();
        fs::write(home_dir.join("config.toml"), b"key = 1\n").unwrap();

        let toml = "[app]\nos-nux = \"~\"\nos-mac = \"~\"\nos-win = \"~\"\nos-bsd = \"~\"\nfiles = \"config.toml\"\n";
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
        let mut cap_obs = CaptureApproveObserver {
            entries: Vec::new(),
        };
        engine
            .import_files_with_observer(&plans, &lock, false, &mut cap_obs)
            .unwrap();
        assert_eq!(cap_obs.entries.len(), 1);
        assert_eq!(cap_obs.entries[0].repo_action, PlanActionKind::Create);
    }

    #[test]
    fn in_project_cwd_import_and_export_roundtrip_with_content_and_full_encryption() {
        let tmp = tempfile::tempdir().unwrap();
        let home_dir = tmp.path().join("home");
        let project_dir = tmp.path().join("my-app");
        fs::create_dir_all(&home_dir).unwrap();
        fs::create_dir_all(project_dir.join("private")).unwrap();

        let pass = crate::crypto::SecretString::new("project-local-enc-pass".to_string());
        let (vcfg, vkey, _) = crate::crypto::vault::init_vault(&pass).unwrap();
        let toml = format!(
            "vault_id = \"{}\"\npassword_slot = \"{}\"\nrecovery_slot = \"{}\"\n\n[secrets]\nos-nux = \".\"\nos-mac = \".\"\nos-win = \".\"\nos-bsd = \".\"\nfiles = \"\"\"\n.env enc\nprivate/* enc=full\n\"\"\"\n",
            vcfg.vault_id, vcfg.password_slot, vcfg.recovery_slot
        );
        fs::write(project_dir.join("dotler.toml"), &toml).unwrap();
        fs::write(project_dir.join(".env"), b"DB_PASS=secret123\n").unwrap();
        fs::write(project_dir.join("private/api.key"), b"KEY_XYZ\n").unwrap();

        let repo_cfg = RepoConfig::parse(&toml).unwrap();
        let state_db = StateDb::open(&tmp.path().join("state.db")).unwrap();
        let lock = DotlerLock::new(tmp.path().join("dotler.lock"))
            .acquire(Duration::from_millis(500), Duration::from_millis(10))
            .unwrap();

        let engine = SyncEngine::new(
            "my-app",
            &project_dir,
            &repo_cfg,
            &state_db,
            vec![],
            OsInfo::detect(),
            Some(&vkey),
        )
        .with_home_dir(&home_dir)
        .with_cwd(&project_dir);

        let plans = engine.plan(None, &lock).unwrap();
        assert_eq!(plans.len(), 2);
        let imp = engine.import_files(&plans, &lock, false).unwrap();
        assert_eq!(imp.processed, 2);
        assert!(project_dir.join("secrets/.env.dotler.enc").is_file());
        let expected_fenc = project_dir
            .join("secrets")
            .join(vkey.derive_full_enc_filename("private/api.key"));
        assert!(expected_fenc.is_file());

        // Remove local plaintext files and restore them cleanly via export.
        fs::remove_file(project_dir.join(".env")).unwrap();
        fs::remove_file(project_dir.join("private/api.key")).unwrap();
        fs::remove_dir(project_dir.join("private")).unwrap();

        let export_plans = engine.plan(None, &lock).unwrap();
        let exp = engine
            .export_files(&export_plans, &lock, false, false)
            .unwrap();
        assert_eq!(exp.processed, 2);
        assert_eq!(
            fs::read(project_dir.join(".env")).unwrap(),
            b"DB_PASS=secret123\n"
        );
        assert_eq!(
            fs::read(project_dir.join("private/api.key")).unwrap(),
            b"KEY_XYZ\n"
        );
        assert_eq!(
            fs::read_to_string(project_dir.join("dotler.toml")).unwrap(),
            toml
        );
    }
}
