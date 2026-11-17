//! Repository in-place format reconciliation (`foo` <-> `foo.enc`) and orphan cleanup (`tidy`).

use std::collections::HashSet;
use std::fs;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::local::WalkDir;
use crate::config::repo::{
    evaluate_selection, is_symlink, parse_selection_rules, prune_empty_parent_dirs,
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

struct PlannedRepoTidyOp {
    group_name: String,
    group_base: PathBuf,
    rel_path: String,
    kind: RepoTidyKind,
}

enum RepoTidyKind {
    Encrypt {
        plain_path: PathBuf,
        enc_path: PathBuf,
    },
    Decrypt {
        enc_path: PathBuf,
        plain_path: PathBuf,
    },
    RemoveExcluded {
        repo_path: PathBuf,
    },
    RemoveDeleted {
        repo_path: PathBuf,
        target_path_str: String,
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
    let all_synced = engine
        .state_db
        .list_synced_files(Some(&engine.repo_label))?;

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
    let synced_keys: HashSet<(String, String)> = all_synced
        .iter()
        .map(|r| (r.group_name.clone(), r.target_path.clone()))
        .collect();
    let mut pruned_repo_targets: HashSet<String> = HashSet::new();

    // 1. Scan repository groups for in-repo format reconciliation and locally deleted files
    for (group_name, group_cfg) in &engine.repo_config.groups {
        if !group_filters.is_empty() && !group_filters.iter().any(|f| f == group_name) {
            continue;
        }

        let group_repo_dir = engine.repo_dir.join(group_name);
        validate_dir_no_symlinks(&group_repo_dir)?;
        if !group_repo_dir.is_dir() {
            continue;
        }

        let resolved_target_base =
            resolve_group_target_path(group_cfg, &engine.devices, &engine.os_info)
                .map(|s| engine.expand_target_base(&s));
        let group_base = resolved_target_base
            .clone()
            .unwrap_or_else(|| engine.effective_home_dir());

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
            let os_path_str = os_path.to_string_lossy().to_string();
            let mode = evaluate_selection(&rules, clean_rel);
            if mode.is_some_and(|m| m.is_included())
                && resolved_target_base.is_some()
                && !os_path.exists()
                && !is_symlink(&os_path)
                && synced_keys.contains(&(group_name.clone(), os_path_str.clone()))
            {
                let direction = if is_enc_ext {
                    PlanDirection::EncryptToRepo
                } else {
                    PlanDirection::PlainToRepo
                };
                push_repo_preview(
                    &mut preview_entries,
                    group_name,
                    os_path,
                    path,
                    PlanActionKind::Delete,
                    direction,
                );
                repo_ops.push(PlannedRepoTidyOp {
                    group_name: group_name.clone(),
                    group_base: group_base.clone(),
                    rel_path: rel_str,
                    kind: RepoTidyKind::RemoveDeleted {
                        repo_path: path.to_path_buf(),
                        target_path_str: os_path_str.clone(),
                    },
                });
                pruned_repo_targets.insert(os_path_str);
                continue;
            }

            match mode {
                Some(m) if m.is_encrypted() => {
                    if !is_enc_ext {
                        require_vault(engine, "encryption")?;
                        let enc_path = group_repo_dir.join(format!("{clean_rel}.enc"));
                        push_repo_preview(
                            &mut preview_entries,
                            group_name,
                            os_path,
                            &enc_path,
                            PlanActionKind::Overwrite,
                            PlanDirection::EncryptToRepo,
                        );
                        repo_ops.push(PlannedRepoTidyOp {
                            group_name: group_name.clone(),
                            group_base: group_base.clone(),
                            rel_path: clean_rel.to_string(),
                            kind: RepoTidyKind::Encrypt {
                                plain_path: path.to_path_buf(),
                                enc_path,
                            },
                        });
                    } else {
                        push_repo_preview(
                            &mut preview_entries,
                            group_name,
                            os_path,
                            path,
                            PlanActionKind::Okay,
                            PlanDirection::EncryptToRepo,
                        );
                    }
                }
                Some(m) if m.is_included() => {
                    if is_enc_ext {
                        require_vault(engine, "decryption")?;
                        let plain_path = group_repo_dir.join(clean_rel);
                        push_repo_preview(
                            &mut preview_entries,
                            group_name,
                            os_path,
                            &plain_path,
                            PlanActionKind::Overwrite,
                            PlanDirection::DecryptInRepo,
                        );
                        repo_ops.push(PlannedRepoTidyOp {
                            group_name: group_name.clone(),
                            group_base: group_base.clone(),
                            rel_path: clean_rel.to_string(),
                            kind: RepoTidyKind::Decrypt {
                                enc_path: path.to_path_buf(),
                                plain_path,
                            },
                        });
                    } else {
                        push_repo_preview(
                            &mut preview_entries,
                            group_name,
                            os_path,
                            path,
                            PlanActionKind::Okay,
                            PlanDirection::PlainToRepo,
                        );
                    }
                }
                _ => {
                    push_repo_preview(
                        &mut preview_entries,
                        group_name,
                        os_path,
                        path,
                        PlanActionKind::Delete,
                        PlanDirection::PlainToRepo,
                    );
                    repo_ops.push(PlannedRepoTidyOp {
                        group_name: group_name.clone(),
                        group_base: group_base.clone(),
                        rel_path: rel_str,
                        kind: RepoTidyKind::RemoveExcluded {
                            repo_path: path.to_path_buf(),
                        },
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
                plans.append(&mut plan(engine, Some(g.as_str()), lock)?);
            }
        }
    }

    let active_target_paths: HashSet<String> = plans
        .iter()
        .filter(|p| {
            p.status != FileSyncStatus::Orphaned
                && !(p.status == FileSyncStatus::MissingLocally && !p.repo_file_path.is_file())
        })
        .map(|p| p.target_os_path.to_string_lossy().to_string())
        .collect();

    let mut orphan_ops: Vec<PlannedOrphanOp> = Vec::new();
    for rec in all_synced {
        if !group_filters.is_empty() && !group_filters.iter().any(|g| g == &rec.group_name) {
            continue;
        }
        if pruned_repo_targets.contains(&rec.target_path)
            || active_target_paths.contains(&rec.target_path)
        {
            continue;
        }
        let orphan_path = PathBuf::from(&rec.target_path);
        let group_base =
            resolve_orphan_group_base(engine, &rec.group_name, &rec.relative_path, &orphan_path);
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
        return Ok(summarize_tidy_dry_run(&repo_ops, orphan_ops, policy));
    }
    if !approved {
        return Ok(TidyReport::default());
    }

    let mut report = TidyReport::default();
    for op in repo_ops {
        let len = execute_repo_tidy_op(engine, &op.group_name, &op.kind, &mut report)?;
        observer.on_file_progress(&op.group_name, &op.group_base, &op.rel_path, len);
    }
    for op in orphan_ops {
        if policy == TidyOrphanPolicy::PurgeFromOs {
            if op.orphan_path.is_file() || is_symlink(&op.orphan_path) {
                let _ = fs::remove_file(&op.orphan_path);
            }
            prune_empty_parent_dirs(&op.orphan_path, &op.group_base);
            report.removed_os_orphans.push(op.orphan_path);
        } else {
            report.untracked_kept_orphans.push(op.orphan_path);
        }
        let _ = engine.state_db.remove_synced_file(&op.orphan_path_str);
        observer.on_file_progress(&op.group_name, &op.group_base, &op.rel_path, None);
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

fn require_vault<'a>(
    engine: &SyncEngine<'a>,
    op: &str,
) -> Result<&'a crate::crypto::vault::VaultKey, EngineError> {
    engine.vault_key.ok_or_else(|| EngineError::VaultLocked {
        reason: format!("vault key required for tidy in-repo {op}"),
    })
}

fn push_repo_preview(
    entries: &mut Vec<PlanPreviewEntry>,
    group_name: &str,
    os_path: PathBuf,
    repo_path: &std::path::Path,
    repo_action: PlanActionKind,
    direction: PlanDirection,
) {
    entries.push(PlanPreviewEntry {
        group_name: group_name.to_string(),
        os_path,
        os_action: PlanActionKind::Okay,
        repo_path: repo_path.to_path_buf(),
        repo_action,
        direction,
    });
}

fn summarize_tidy_dry_run(
    repo_ops: &[PlannedRepoTidyOp],
    orphan_ops: Vec<PlannedOrphanOp>,
    policy: TidyOrphanPolicy,
) -> TidyReport {
    let mut sim = TidyReport::default();
    for op in repo_ops {
        match op.kind {
            RepoTidyKind::Encrypt { .. } => sim.encrypted_in_repo += 1,
            RepoTidyKind::Decrypt { .. } => sim.decrypted_in_repo += 1,
            RepoTidyKind::RemoveExcluded { .. } | RepoTidyKind::RemoveDeleted { .. } => {
                sim.removed_from_repo += 1
            }
        }
    }
    for op in orphan_ops {
        if policy == TidyOrphanPolicy::PurgeFromOs {
            sim.removed_os_orphans.push(op.orphan_path);
        } else {
            sim.untracked_kept_orphans.push(op.orphan_path);
        }
    }
    sim
}

fn resolve_orphan_group_base(
    engine: &SyncEngine,
    group_name: &str,
    relative_path: &str,
    orphan_path: &Path,
) -> PathBuf {
    if let Some(group_cfg) = engine.repo_config.groups.get(group_name)
        && let Some(base_str) =
            resolve_group_target_path(group_cfg, &engine.devices, &engine.os_info)
    {
        let cfg_base = engine.expand_target_base(&base_str);
        if orphan_path.starts_with(&cfg_base) {
            return cfg_base;
        }
    }

    let rel_comps: Vec<_> = Path::new(relative_path)
        .components()
        .filter(|c| matches!(c, Component::Normal(_)))
        .collect();
    if !rel_comps.is_empty() {
        let mut base = orphan_path.to_path_buf();
        let mut matched = true;
        for comp in rel_comps.into_iter().rev() {
            if base.file_name() == Some(comp.as_os_str()) {
                base.pop();
            } else {
                matched = false;
                break;
            }
        }
        if matched && !base.as_os_str().is_empty() {
            let home = engine.effective_home_dir();
            if base.starts_with(&home) {
                return base;
            }
            return home;
        }
    }

    engine.group_base_for(group_name)
}

fn execute_repo_tidy_op(
    engine: &SyncEngine,
    group_name: &str,
    kind: &RepoTidyKind,
    report: &mut TidyReport,
) -> Result<Option<u64>, EngineError> {
    match kind {
        RepoTidyKind::Encrypt {
            plain_path,
            enc_path,
        } => {
            let vault_key = require_vault(engine, "encryption")?;
            let plaintext = fs::read(plain_path)?;
            let len = plaintext.len() as u64;
            let enc = vault_key.encrypt_file(&plaintext)?;
            write_file_safe(enc_path, &enc.to_bytes())?;
            let _ = fs::remove_file(plain_path);
            report.encrypted_in_repo += 1;
            Ok(Some(len))
        }
        RepoTidyKind::Decrypt {
            enc_path,
            plain_path,
        } => {
            let vault_key = require_vault(engine, "decryption")?;
            let raw_enc = fs::read(enc_path)?;
            let enc = EncryptedFile::from_bytes(&raw_enc)?;
            let decrypted = vault_key.decrypt_file(&enc)?;
            let len = decrypted.expose_secret().len() as u64;
            write_file_safe(plain_path, decrypted.expose_secret())?;
            let _ = fs::remove_file(enc_path);
            report.decrypted_in_repo += 1;
            Ok(Some(len))
        }
        RepoTidyKind::RemoveExcluded { repo_path } => {
            let _ = fs::remove_file(repo_path);
            let group_repo_dir = engine.repo_dir.join(group_name);
            prune_empty_parent_dirs(repo_path, &group_repo_dir);
            report.removed_from_repo += 1;
            Ok(None)
        }
        RepoTidyKind::RemoveDeleted {
            repo_path,
            target_path_str,
        } => {
            if repo_path.is_file() {
                fs::remove_file(repo_path)?;
            }
            let group_repo_dir = engine.repo_dir.join(group_name);
            prune_empty_parent_dirs(repo_path, &group_repo_dir);
            engine.state_db.remove_synced_file(target_path_str)?;
            report.removed_from_repo += 1;
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::repo::{OsInfo, RepoConfig};
    use crate::config::state::{DotlerLock, StateDb, SyncedFileRecord};
    use crate::crypto::{SecretString, VaultKey, init_vault};
    use std::time::Duration;

    struct TidyTestEnv {
        _tmp: tempfile::TempDir,
        home_dir: PathBuf,
        repo_dir: PathBuf,
        state_db: StateDb,
        lock: DotlerLockGuard,
    }

    impl TidyTestEnv {
        fn new() -> Self {
            let tmp = tempfile::tempdir().unwrap();
            let home_dir = tmp.path().join("home");
            let repo_dir = tmp.path().join("repo");
            fs::create_dir_all(&home_dir).unwrap();
            fs::create_dir_all(&repo_dir).unwrap();
            let state_db = StateDb::open(&tmp.path().join("state.db")).unwrap();
            let lock = DotlerLock::new(tmp.path().join("dotler.lock"))
                .acquire(Duration::from_millis(500), Duration::from_millis(10))
                .unwrap();
            Self {
                _tmp: tmp,
                home_dir,
                repo_dir,
                state_db,
                lock,
            }
        }

        fn run(&self, toml: &str, vkey: Option<&VaultKey>, policy: TidyOrphanPolicy) -> TidyReport {
            let repo_cfg = RepoConfig::parse(toml).unwrap();
            let engine = SyncEngine::new(
                "main",
                &self.repo_dir,
                &repo_cfg,
                &self.state_db,
                vec![],
                OsInfo::detect(),
                vkey,
            )
            .with_home_dir(&self.home_dir);
            tidy(&engine, None, &self.lock, policy, false).unwrap()
        }

        fn record_orphan(&self, path: &Path, updated_at: i64) {
            self.state_db
                .upsert_synced_file(&SyncedFileRecord {
                    target_path: path.to_string_lossy().to_string(),
                    repo_label: "main".to_string(),
                    group_name: "shell".to_string(),
                    relative_path: "orphan.conf".to_string(),
                    file_hash: "00".to_string(),
                    updated_at,
                })
                .unwrap();
        }
    }

    #[test]
    fn tidy_converts_plain_and_enc_in_repo_and_removes_stale_copies() {
        let env = TidyTestEnv::new();
        fs::create_dir_all(env.repo_dir.join("sec")).unwrap();

        let pass = SecretString::new("tidy-vault-pass".to_string());
        let (vcfg, vkey, _) = init_vault(&pass).unwrap();
        fs::write(env.repo_dir.join("sec/secret.txt"), b"top-secret").unwrap();

        let toml = format!(
            "vault_id = \"{}\"\npassword_slot = \"{}\"\nrecovery_slot = \"{}\"\n\n[sec]\nos-nux = \"~\"\nos-mac = \"~\"\nfiles = \"secret.txt enc\"\n",
            vcfg.vault_id, vcfg.password_slot, vcfg.recovery_slot
        );
        let rep = env.run(&toml, Some(&vkey), TidyOrphanPolicy::KeepOnOs);
        assert_eq!(rep.encrypted_in_repo, 1);
        assert!(!env.repo_dir.join("sec/secret.txt").exists());
        assert!(env.repo_dir.join("sec/secret.txt.enc").is_file());
    }

    #[test]
    fn tidy_keep_on_os_vs_purge_from_os() {
        let env = TidyTestEnv::new();
        let orphan_file = env.home_dir.join("orphan.conf");
        fs::write(&orphan_file, b"keep me").unwrap();

        let toml = "[shell]\nos-nux = \"~\"\nos-mac = \"~\"\nfiles = \"!*\"\n";
        env.record_orphan(&orphan_file, 1);
        let rep_keep = env.run(toml, None, TidyOrphanPolicy::KeepOnOs);
        assert_eq!(rep_keep.untracked_kept_orphans.len(), 1);
        assert!(orphan_file.is_file());
        assert!(env.state_db.list_synced_files(None).unwrap().is_empty());

        env.record_orphan(&orphan_file, 2);
        let rep_purge = env.run(toml, None, TidyOrphanPolicy::PurgeFromOs);
        assert_eq!(rep_purge.removed_os_orphans.len(), 1);
        assert!(!orphan_file.exists());
    }

    #[test]
    fn tidy_prunes_empty_subdirectories_in_repo_and_os_preserving_group_roots() {
        let env = TidyTestEnv::new();
        let active_repo = env.repo_dir.join("nvim/init.lua");
        let excluded_repo = env.repo_dir.join("nvim/lua/plugins/unused/init.lua");
        fs::create_dir_all(excluded_repo.parent().unwrap()).unwrap();
        fs::write(&active_repo, b"-- init\n").unwrap();
        fs::write(&excluded_repo, b"-- unused\n").unwrap();

        let os_base = env.home_dir.join(".config/nvim");
        let orphan_os = os_base.join("lua/legacy/old.lua");
        fs::create_dir_all(orphan_os.parent().unwrap()).unwrap();
        fs::write(&orphan_os, b"-- old\n").unwrap();

        let toml = "[nvim]\nos-nux = \"~/.config/nvim\"\nos-mac = \"~/.config/nvim\"\nos-win = \"~/.config/nvim\"\nos-bsd = \"~/.config/nvim\"\nfiles = \"!*\\ninit.lua\"\n";

        env.state_db
            .upsert_synced_file(&SyncedFileRecord {
                target_path: orphan_os.to_string_lossy().to_string(),
                repo_label: "main".to_string(),
                group_name: "nvim".to_string(),
                relative_path: "lua/legacy/old.lua".to_string(),
                file_hash: "00".to_string(),
                updated_at: 1,
            })
            .unwrap();

        let rep_keep = env.run(toml, None, TidyOrphanPolicy::KeepOnOs);
        assert_eq!(rep_keep.removed_from_repo, 1);
        assert_eq!(rep_keep.untracked_kept_orphans.len(), 1);
        assert!(!excluded_repo.exists());
        assert!(!env.repo_dir.join("nvim/lua").exists());
        assert!(env.repo_dir.join("nvim").is_dir());
        assert!(active_repo.is_file());
        assert!(orphan_os.is_file());

        env.state_db
            .upsert_synced_file(&SyncedFileRecord {
                target_path: orphan_os.to_string_lossy().to_string(),
                repo_label: "main".to_string(),
                group_name: "nvim".to_string(),
                relative_path: "lua/legacy/old.lua".to_string(),
                file_hash: "00".to_string(),
                updated_at: 2,
            })
            .unwrap();

        let rep_purge = env.run(toml, None, TidyOrphanPolicy::PurgeFromOs);
        assert_eq!(rep_purge.removed_os_orphans.len(), 1);
        assert!(!orphan_os.exists());
        assert!(!os_base.join("lua/legacy").exists());
        assert!(!os_base.join("lua").exists());
        assert!(os_base.is_dir());
    }

    struct RejectTidyObserver;
    impl CommandObserver for RejectTidyObserver {
        fn confirm_plan(&mut self, _: &[PlanPreviewEntry], _: bool) -> Result<bool, EngineError> {
            Ok(false)
        }
        fn on_file_progress(&mut self, _: &str, _: &Path, _: &str, _: Option<u64>) {}
        fn finish_progress(&mut self) {}
    }

    #[test]
    fn tidy_prunes_locally_deleted_repo_files_and_preserves_unexported_files() {
        let env = TidyTestEnv::new();
        let notes_os = env.home_dir.join(".config/notes");
        fs::create_dir_all(&notes_os).unwrap();
        fs::write(notes_os.join("keep.md"), b"keep\n").unwrap();

        let keep_repo = env.repo_dir.join("notes/keep.md");
        let deleted_repo = env.repo_dir.join("notes/nested/deleted.md");
        let remote_repo = env.repo_dir.join("notes/remote.md");
        fs::create_dir_all(deleted_repo.parent().unwrap()).unwrap();
        fs::write(&keep_repo, b"keep\n").unwrap();
        fs::write(&deleted_repo, b"deleted\n").unwrap();
        fs::write(&remote_repo, b"unexported\n").unwrap();

        let pass = SecretString::new("tidy-deleted-enc-pass".to_string());
        let (vcfg, vkey, _) = init_vault(&pass).unwrap();
        let sec_os = env.home_dir.join(".config/sec");
        fs::create_dir_all(&sec_os).unwrap();
        let enc_repo = env.repo_dir.join("sec/old.key.enc");
        fs::create_dir_all(enc_repo.parent().unwrap()).unwrap();
        let enc_bytes = vkey.encrypt_file(b"secret").unwrap().to_bytes();
        fs::write(&enc_repo, &enc_bytes).unwrap();

        // Record keep.md, nested/deleted.md, and old.key as previously synced; leave remote.md unrecorded.
        for (target, group, rel) in [
            (notes_os.join("keep.md"), "notes", "keep.md"),
            (
                notes_os.join("nested/deleted.md"),
                "notes",
                "nested/deleted.md",
            ),
            (sec_os.join("old.key"), "sec", "old.key"),
        ] {
            env.state_db
                .upsert_synced_file(&SyncedFileRecord {
                    target_path: target.to_string_lossy().to_string(),
                    repo_label: "main".to_string(),
                    group_name: group.to_string(),
                    relative_path: rel.to_string(),
                    file_hash: "aa".to_string(),
                    updated_at: 10,
                })
                .unwrap();
        }

        let toml = format!(
            "vault_id = \"{}\"\npassword_slot = \"{}\"\nrecovery_slot = \"{}\"\n\n[notes]\nos-nux = \"~/.config/notes\"\nos-mac = \"~/.config/notes\"\nos-win = \"~/.config/notes\"\nos-bsd = \"~/.config/notes\"\nfiles = \"*\"\n\n[sec]\nos-nux = \"~/.config/sec\"\nos-mac = \"~/.config/sec\"\nos-win = \"~/.config/sec\"\nos-bsd = \"~/.config/sec\"\nfiles = \"* enc\"\n",
            vcfg.vault_id, vcfg.password_slot, vcfg.recovery_slot
        );
        let repo_cfg = RepoConfig::parse(&toml).unwrap();
        let engine = SyncEngine::new(
            "main",
            &env.repo_dir,
            &repo_cfg,
            &env.state_db,
            vec![],
            OsInfo::detect(),
            None,
        )
        .with_home_dir(&env.home_dir);

        // Dry-run and cancellation must preserve all repo files and DB records.
        let dry_rep = engine
            .tidy(None, &env.lock, TidyOrphanPolicy::KeepOnOs, true)
            .unwrap();
        assert_eq!(dry_rep.removed_from_repo, 2);
        assert!(deleted_repo.is_file());
        assert!(enc_repo.is_file());

        let mut rej_obs = RejectTidyObserver;
        let rej_rep = tidy_groups_with_observer(
            &engine,
            &[],
            &env.lock,
            TidyOrphanPolicy::KeepOnOs,
            false,
            &mut rej_obs,
        )
        .unwrap();
        assert_eq!(rej_rep.removed_from_repo, 0);
        assert!(deleted_repo.is_file());
        assert!(enc_repo.is_file());

        // Real tidy removes locally deleted plain and .enc copies, prunes empty subdirs,
        // clears synced_files records, and preserves un-exported remote.md.
        let rep = engine
            .tidy(None, &env.lock, TidyOrphanPolicy::KeepOnOs, false)
            .unwrap();
        assert_eq!(rep.removed_from_repo, 2);
        assert!(rep.untracked_kept_orphans.is_empty());
        assert!(rep.removed_os_orphans.is_empty());

        assert!(!deleted_repo.exists());
        assert!(!env.repo_dir.join("notes/nested").exists());
        assert!(!enc_repo.exists());
        assert!(env.repo_dir.join("sec").is_dir());
        assert!(keep_repo.is_file());
        assert!(remote_repo.is_file());

        assert!(
            env.state_db
                .get_synced_file(&notes_os.join("nested/deleted.md").to_string_lossy())
                .unwrap()
                .is_none()
        );
        assert!(
            env.state_db
                .get_synced_file(&sec_os.join("old.key").to_string_lossy())
                .unwrap()
                .is_none()
        );
        assert!(
            env.state_db
                .get_synced_file(&notes_os.join("keep.md").to_string_lossy())
                .unwrap()
                .is_some()
        );
    }
}
