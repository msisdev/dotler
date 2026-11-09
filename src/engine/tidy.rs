//! Repository in-place format reconciliation (`foo` <-> `foo.enc`) and orphan cleanup (`tidy`).

use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::config::local::{WalkDir, expand_tilde};
use crate::config::repo::{
    SelectionMode, evaluate_selection, is_symlink, parse_selection_rules,
    resolve_group_target_path, validate_dir_no_symlinks,
};
use crate::config::state::{DotlerLockGuard, TMP_FILE_PREFIX, write_file_safe};
use crate::core::context::CoreContext;
use crate::core::vault_loader::{
    has_encrypted_repo_files, has_encrypted_rules, unlock_vault_if_needed,
};
use crate::crypto::ExposeSecret;
use crate::crypto::vault::EncryptedFile;
use crate::engine::EngineError;
use crate::engine::check::{FileSyncStatus, plan};
use crate::engine::observer::{
    CommandObserver, NoopObserver, PlanActionKind, PlanDirection, PlanPreviewEntry,
};
use crate::engine::sync::SyncEngine;

/// Policy governing how `dotler tidy` handles orphaned files on the OS filesystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum TidyOrphanPolicy {
    #[default]
    KeepOnOs,
    PurgeFromOs,
}

/// Summary report returned by `tidy` operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TidyReport {
    pub encrypted_in_repo: usize,
    pub decrypted_in_repo: usize,
    pub removed_from_repo: usize,
    pub removed_os_orphans: Vec<PathBuf>,
    pub untracked_kept_orphans: Vec<PathBuf>,
}

enum PlannedRepoTidyOp {
    Encrypt {
        group_name: String,
        group_base: PathBuf,
        rel_path: String,
        plain_path: PathBuf,
        enc_path: PathBuf,
    },
    Decrypt {
        group_name: String,
        group_base: PathBuf,
        rel_path: String,
        enc_path: PathBuf,
        plain_path: PathBuf,
    },
    RemoveExcluded {
        group_name: String,
        group_base: PathBuf,
        rel_path: String,
        repo_path: PathBuf,
    },
}

struct PlannedOrphanOp {
    group_name: String,
    group_base: PathBuf,
    rel_path: String,
    orphan_path_str: String,
    orphan_path: PathBuf,
}

/// Unified `tidy` command entry point shared by CLI (`dotler tidy`) and MCP (`dotler_tidy`).
pub fn run_tidy(
    ctx: &CoreContext,
    groups: &[String],
    policy: TidyOrphanPolicy,
    dry_run: bool,
    lock: &DotlerLockGuard,
    observer: &mut dyn CommandObserver,
) -> Result<TidyReport, EngineError> {
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

    tidy_groups_with_observer(&sync_engine, groups, lock, policy, dry_run, observer)
}

/// Runs repository format reconciliation and orphan cleanup with a [`CommandObserver`].
pub fn tidy_groups_with_observer(
    engine: &SyncEngine,
    group_filters: &[String],
    lock: &DotlerLockGuard,
    policy: TidyOrphanPolicy,
    dry_run: bool,
    observer: &mut dyn CommandObserver,
) -> Result<TidyReport, EngineError> {
    let all_synced = engine.state_db.list_synced_files(Some(&engine.repo_label))?;

    for filter in group_filters {
        let exists_in_repo = engine.repo_config.groups.contains_key(filter);
        let exists_in_db = all_synced.iter().any(|r| &r.group_name == filter);
        if !exists_in_repo && !exists_in_db {
            return Err(EngineError::GroupNotFound {
                group: filter.clone(),
                available: engine.repo_config.groups.keys().cloned().collect(),
            });
        }
    }

    let mut preview_entries: Vec<PlanPreviewEntry> = Vec::new();
    let mut repo_ops: Vec<PlannedRepoTidyOp> = Vec::new();

    // 1. Scan repository groups for in-repo format reconciliation
    for (group_name, group_cfg) in &engine.repo_config.groups {
        if !group_filters.is_empty() && !group_filters.iter().any(|f| f == group_name) {
            continue;
        }

        let group_repo_dir = engine.repo_dir.join(group_name);
        validate_dir_no_symlinks(&group_repo_dir)?;
        if !group_repo_dir.is_dir() {
            continue;
        }

        let group_base = resolve_group_target_path(group_cfg, &engine.devices, &engine.os_info)
            .map(|s| engine.expand_target_base(&s))
            .unwrap_or_else(|| expand_tilde("~"));

        let rules = parse_selection_rules(&group_cfg.files)?;

        for entry in WalkDir::new(&group_repo_dir)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if !entry.file_type().is_file() {
                continue;
            }
            let file_name = entry.file_name().to_string_lossy();
            if file_name.starts_with(TMP_FILE_PREFIX) {
                continue;
            }

            let path = entry.path();
            let rel = match path.strip_prefix(&group_repo_dir) {
                Ok(r) => r,
                Err(_) => continue,
            };
            let rel_str = rel.to_string_lossy().to_string();
            let is_enc_ext = rel_str.ends_with(".enc");
            let clean_rel = if is_enc_ext {
                rel_str.strip_suffix(".enc").unwrap()
            } else {
                &rel_str
            };

            let os_path = group_base.join(clean_rel);
            let mode = evaluate_selection(&rules, clean_rel);
            match mode {
                Some(SelectionMode::EncryptedInclude) => {
                    if !is_enc_ext {
                        if engine.vault_key.is_none() {
                            return Err(EngineError::VaultLocked {
                                reason: "vault key required for tidy in-repo encryption".into(),
                            });
                        }
                        let target_enc = group_repo_dir.join(format!("{clean_rel}.enc"));
                        preview_entries.push(PlanPreviewEntry {
                            group_name: group_name.clone(),
                            os_path,
                            os_action: PlanActionKind::Okay,
                            repo_path: target_enc.clone(),
                            repo_action: PlanActionKind::Overwrite,
                            direction: PlanDirection::EncryptToRepo,
                        });
                        repo_ops.push(PlannedRepoTidyOp::Encrypt {
                            group_name: group_name.clone(),
                            group_base: group_base.clone(),
                            rel_path: clean_rel.to_string(),
                            plain_path: path.to_path_buf(),
                            enc_path: target_enc,
                        });
                    } else {
                        preview_entries.push(PlanPreviewEntry {
                            group_name: group_name.clone(),
                            os_path,
                            os_action: PlanActionKind::Okay,
                            repo_path: path.to_path_buf(),
                            repo_action: PlanActionKind::Okay,
                            direction: PlanDirection::EncryptToRepo,
                        });
                    }
                }
                Some(SelectionMode::PlaintextInclude) => {
                    if is_enc_ext {
                        if engine.vault_key.is_none() {
                            return Err(EngineError::VaultLocked {
                                reason: "vault key required for tidy in-repo decryption".into(),
                            });
                        }
                        let target_plain = group_repo_dir.join(clean_rel);
                        preview_entries.push(PlanPreviewEntry {
                            group_name: group_name.clone(),
                            os_path,
                            os_action: PlanActionKind::Okay,
                            repo_path: target_plain.clone(),
                            repo_action: PlanActionKind::Overwrite,
                            direction: PlanDirection::DecryptInRepo,
                        });
                        repo_ops.push(PlannedRepoTidyOp::Decrypt {
                            group_name: group_name.clone(),
                            group_base: group_base.clone(),
                            rel_path: clean_rel.to_string(),
                            enc_path: path.to_path_buf(),
                            plain_path: target_plain,
                        });
                    } else {
                        preview_entries.push(PlanPreviewEntry {
                            group_name: group_name.clone(),
                            os_path,
                            os_action: PlanActionKind::Okay,
                            repo_path: path.to_path_buf(),
                            repo_action: PlanActionKind::Okay,
                            direction: PlanDirection::PlainToRepo,
                        });
                    }
                }
                Some(SelectionMode::Exclude) | None => {
                    preview_entries.push(PlanPreviewEntry {
                        group_name: group_name.clone(),
                        os_path,
                        os_action: PlanActionKind::Okay,
                        repo_path: path.to_path_buf(),
                        repo_action: PlanActionKind::Delete,
                        direction: PlanDirection::PlainToRepo,
                    });
                    repo_ops.push(PlannedRepoTidyOp::RemoveExcluded {
                        group_name: group_name.clone(),
                        group_base: group_base.clone(),
                        rel_path: rel_str,
                        repo_path: path.to_path_buf(),
                    });
                }
            }
        }
    }

    // 2. Plan orphan cleanup from `synced_files`
    let mut plans = Vec::new();
    if group_filters.is_empty() {
        plans = plan(engine, None, lock)?;
    } else {
        for g in group_filters {
            if engine.repo_config.groups.contains_key(g) {
                let mut p = plan(engine, Some(g.as_str()), lock)?;
                plans.append(&mut p);
            }
        }
    }

    let active_target_paths: HashSet<String> = plans
        .iter()
        .filter(|p| p.status != FileSyncStatus::Orphaned)
        .map(|p| p.target_os_path.to_string_lossy().to_string())
        .collect();

    let mut orphan_ops: Vec<PlannedOrphanOp> = Vec::new();
    for rec in all_synced {
        if !group_filters.is_empty() && !group_filters.iter().any(|g| g == &rec.group_name) {
            continue;
        }
        if active_target_paths.contains(&rec.target_path) {
            continue;
        }
        let orphan_path = PathBuf::from(&rec.target_path);
        let group_base = orphan_path
            .parent()
            .map(PathBuf::from)
            .unwrap_or_else(|| expand_tilde("~"));
        let repo_path = engine
            .repo_dir
            .join(&rec.group_name)
            .join(&rec.relative_path);
        let os_action = match policy {
            TidyOrphanPolicy::PurgeFromOs => PlanActionKind::Delete,
            TidyOrphanPolicy::KeepOnOs => PlanActionKind::Untrack,
        };
        preview_entries.push(PlanPreviewEntry {
            group_name: rec.group_name.clone(),
            os_path: orphan_path.clone(),
            os_action,
            repo_path,
            repo_action: PlanActionKind::Okay,
            direction: PlanDirection::PlainToOs,
        });
        orphan_ops.push(PlannedOrphanOp {
            group_name: rec.group_name,
            group_base,
            rel_path: rec.relative_path,
            orphan_path_str: rec.target_path,
            orphan_path,
        });
    }

    let approved = observer.confirm_plan(&preview_entries, dry_run)?;

    if dry_run {
        let mut sim = TidyReport::default();
        for op in &repo_ops {
            match op {
                PlannedRepoTidyOp::Encrypt { .. } => sim.encrypted_in_repo += 1,
                PlannedRepoTidyOp::Decrypt { .. } => sim.decrypted_in_repo += 1,
                PlannedRepoTidyOp::RemoveExcluded { .. } => sim.removed_from_repo += 1,
            }
        }
        for op in orphan_ops {
            match policy {
                TidyOrphanPolicy::PurgeFromOs => sim.removed_os_orphans.push(op.orphan_path),
                TidyOrphanPolicy::KeepOnOs => sim.untracked_kept_orphans.push(op.orphan_path),
            }
        }
        return Ok(sim);
    }

    if !approved {
        return Ok(TidyReport::default());
    }

    let mut report = TidyReport::default();

    for op in repo_ops {
        match op {
            PlannedRepoTidyOp::Encrypt {
                group_name,
                group_base,
                rel_path,
                plain_path,
                enc_path,
            } => {
                let vault_key = engine.vault_key.ok_or_else(|| EngineError::VaultLocked {
                    reason: "vault key required for tidy in-repo encryption".into(),
                })?;
                let plaintext = fs::read(&plain_path)?;
                let len = plaintext.len() as u64;
                let enc = vault_key.encrypt_file(&plaintext)?;
                write_file_safe(&enc_path, &enc.to_bytes())?;
                let _ = fs::remove_file(&plain_path);
                report.encrypted_in_repo += 1;
                observer.on_file_progress(&group_name, &group_base, &rel_path, Some(len));
            }
            PlannedRepoTidyOp::Decrypt {
                group_name,
                group_base,
                rel_path,
                enc_path,
                plain_path,
            } => {
                let vault_key = engine.vault_key.ok_or_else(|| EngineError::VaultLocked {
                    reason: "vault key required for tidy in-repo decryption".into(),
                })?;
                let raw_enc = fs::read(&enc_path)?;
                let enc = EncryptedFile::from_bytes(&raw_enc)?;
                let decrypted = vault_key.decrypt_file(&enc)?;
                let len = decrypted.expose_secret().len() as u64;
                write_file_safe(&plain_path, decrypted.expose_secret())?;
                let _ = fs::remove_file(&enc_path);
                report.decrypted_in_repo += 1;
                observer.on_file_progress(&group_name, &group_base, &rel_path, Some(len));
            }
            PlannedRepoTidyOp::RemoveExcluded {
                group_name,
                group_base,
                rel_path,
                repo_path,
            } => {
                let _ = fs::remove_file(&repo_path);
                report.removed_from_repo += 1;
                observer.on_file_progress(&group_name, &group_base, &rel_path, None);
            }
        }
    }

    for op in orphan_ops {
        match policy {
            TidyOrphanPolicy::PurgeFromOs => {
                if op.orphan_path.is_file() || is_symlink(&op.orphan_path) {
                    let _ = fs::remove_file(&op.orphan_path);
                }
                let _ = engine.state_db.remove_synced_file(&op.orphan_path_str);
                report.removed_os_orphans.push(op.orphan_path);
                observer.on_file_progress(&op.group_name, &op.group_base, &op.rel_path, None);
            }
            TidyOrphanPolicy::KeepOnOs => {
                let _ = engine.state_db.remove_synced_file(&op.orphan_path_str);
                report.untracked_kept_orphans.push(op.orphan_path);
                observer.on_file_progress(&op.group_name, &op.group_base, &op.rel_path, None);
            }
        }
    }

    if report.encrypted_in_repo > 0
        || report.decrypted_in_repo > 0
        || report.removed_from_repo > 0
        || !report.removed_os_orphans.is_empty()
        || !report.untracked_kept_orphans.is_empty()
    {
        observer.finish_progress();
    }
    Ok(report)
}

/// Runs `tidy` for an optional single group filter using [`NoopObserver`].
pub fn tidy(
    engine: &SyncEngine,
    group_filter: Option<&str>,
    lock: &DotlerLockGuard,
    policy: TidyOrphanPolicy,
    dry_run: bool,
) -> Result<TidyReport, EngineError> {
    let filters: Vec<String> = group_filter.into_iter().map(str::to_string).collect();
    tidy_groups(engine, &filters, lock, policy, dry_run)
}

/// Runs `tidy` for zero, one, or multiple group filters using [`NoopObserver`].
pub fn tidy_groups(
    engine: &SyncEngine,
    group_filters: &[String],
    lock: &DotlerLockGuard,
    policy: TidyOrphanPolicy,
    dry_run: bool,
) -> Result<TidyReport, EngineError> {
    let mut obs = NoopObserver;
    tidy_groups_with_observer(engine, group_filters, lock, policy, dry_run, &mut obs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::repo::{OsInfo, RepoConfig};
    use crate::config::state::{DotlerLock, StateDb, SyncedFileRecord};
    use crate::crypto::SecretString;
    use crate::crypto::vault::init_vault;
    use std::time::Duration;

    #[test]
    fn tidy_converts_plain_and_enc_in_repo_and_removes_stale_copies() {
        let tmp = tempfile::tempdir().unwrap();
        let home_dir = tmp.path().join("home");
        let repo_dir = tmp.path().join("repo");
        fs::create_dir_all(&home_dir).unwrap();
        fs::create_dir_all(repo_dir.join("sec")).unwrap();

        let pass = SecretString::new("tidy-vault-pass".to_string());
        let (vcfg, vkey, _) = init_vault(&pass).unwrap();

        // Plain file in repo when rule requires encrypt
        fs::write(repo_dir.join("sec/secret.txt"), b"top-secret").unwrap();
        let toml = format!(
            "[sec]\nos-nux = \"~\"\nos-mac = \"~\"\nfiles = \"secret.txt encrypt\"\n\n[vault]\nvault_id = \"{}\"\npassword_slot = \"{}\"\nrecovery_slot = \"{}\"\n",
            vcfg.vault_id, vcfg.password_slot, vcfg.recovery_slot
        );
        let repo_cfg = RepoConfig::parse(&toml).unwrap();
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
            Some(&vkey),
        )
        .with_home_dir(&home_dir);

        let rep = tidy(&engine, None, &lock, TidyOrphanPolicy::KeepOnOs, false).unwrap();
        assert_eq!(rep.encrypted_in_repo, 1);
        assert!(!repo_dir.join("sec/secret.txt").exists());
        assert!(repo_dir.join("sec/secret.txt.enc").is_file());
    }

    #[test]
    fn tidy_keep_on_os_vs_purge_from_os() {
        let tmp = tempfile::tempdir().unwrap();
        let home_dir = tmp.path().join("home");
        let repo_dir = tmp.path().join("repo");
        fs::create_dir_all(&home_dir).unwrap();
        fs::create_dir_all(&repo_dir).unwrap();

        let orphan_file = home_dir.join("orphan.conf");
        fs::write(&orphan_file, b"keep me").unwrap();

        let toml = "[shell]\nos-nux = \"~\"\nos-mac = \"~\"\nfiles = \"!*\"\n";
        let repo_cfg = RepoConfig::parse(toml).unwrap();
        let state_db = StateDb::open(&tmp.path().join("state.db")).unwrap();
        let lock = DotlerLock::new(tmp.path().join("dotler.lock"))
            .acquire(Duration::from_millis(500), Duration::from_millis(10))
            .unwrap();

        state_db
            .upsert_synced_file(&SyncedFileRecord {
                target_path: orphan_file.to_string_lossy().to_string(),
                repo_label: "main".to_string(),
                group_name: "shell".to_string(),
                relative_path: "orphan.conf".to_string(),
                file_hash: "00".to_string(),
                updated_at: 1,
            })
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

        // KeepOnOs keeps file on disk and removes DB entry
        let rep_keep = tidy(&engine, None, &lock, TidyOrphanPolicy::KeepOnOs, false).unwrap();
        assert_eq!(rep_keep.untracked_kept_orphans.len(), 1);
        assert!(orphan_file.is_file());
        assert!(state_db.list_synced_files(None).unwrap().is_empty());

        // Re-insert and test PurgeFromOs
        state_db
            .upsert_synced_file(&SyncedFileRecord {
                target_path: orphan_file.to_string_lossy().to_string(),
                repo_label: "main".to_string(),
                group_name: "shell".to_string(),
                relative_path: "orphan.conf".to_string(),
                file_hash: "00".to_string(),
                updated_at: 2,
            })
            .unwrap();

        let rep_purge = tidy(&engine, None, &lock, TidyOrphanPolicy::PurgeFromOs, false).unwrap();
        assert_eq!(rep_purge.removed_os_orphans.len(), 1);
        assert!(!orphan_file.exists());
    }
}
