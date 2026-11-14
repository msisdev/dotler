//! WAL-backed remote installation (`git install`) and atomic rollback (`git uninstall`).

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::local::{WalkDir, expand_tilde};
use crate::config::repo::{
    OsInfo, SelectionMode, evaluate_selection, is_symlink, parse_selection_rules,
    render_home_template, resolve_group_target_path, validate_os_dir_path, validate_os_target_path,
    validate_path_security,
};
use crate::config::state::{
    BACKUPS_DIR_PATH, DotlerLockGuard, InstalledFileRecord, StateDb, write_file_safe,
};
use crate::core::context::CoreContext;
use crate::engine::EngineError;
use crate::engine::git_transport::{GitRunner, TempDirGuard};
use crate::engine::observer::{
    CommandObserver, NoopObserver, PlanActionKind, PlanDirection, PlanPreviewEntry,
};
use crate::engine::remote::{RemoteRepoUrl, discover_manifests_in_tree, parse_url};

pub const BACKUPS_DIR_NAME: &str = "backups";

/// CLI/engine target path override for a remote group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathOverride {
    pub group_name: String,
    pub custom_path: PathBuf,
}

/// Summary report returned by `git install`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallReport {
    pub installed_files: Vec<PathBuf>,
    pub backed_up_files: Vec<PathBuf>,
}

/// Summary report returned by `git uninstall`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UninstallReport {
    pub removed_files: Vec<PathBuf>,
    pub restored_backups: Vec<PathBuf>,
}

struct PlannedInstallFile {
    group_name: String,
    target_base: PathBuf,
    source_path: PathBuf,
    clean_rel: String,
    target_file_path: PathBuf,
    file_content: Vec<u8>,
}

/// Installs remote repository dotfiles directly to OS paths using [`NoopObserver`].
#[allow(clippy::too_many_arguments)]
pub fn install_remote(
    url: &RemoteRepoUrl,
    groups: &[String],
    path_override: Option<&Path>,
    branch: Option<&str>,
    devices: &[String],
    state: &StateDb,
    lock: &DotlerLockGuard,
) -> Result<InstallReport, EngineError> {
    let mut noop = NoopObserver;
    install_remote_with_observer(
        url,
        groups,
        path_override,
        branch,
        devices,
        state,
        lock,
        false,
        &mut noop,
    )
}

/// Installs remote repository dotfiles via Write-Ahead Logging and per-file backups.
#[allow(clippy::too_many_arguments)]
pub fn install_remote_with_observer(
    url: &RemoteRepoUrl,
    groups: &[String],
    path_override: Option<&Path>,
    branch: Option<&str>,
    devices: &[String],
    state: &StateDb,
    _lock: &DotlerLockGuard,
    dry_run: bool,
    observer: &mut dyn CommandObserver,
) -> Result<InstallReport, EngineError> {
    let temp_dir = TempDirGuard::new().map_err(EngineError::Io)?;
    GitRunner::clone_shallow(&url.clone_url, branch, temp_dir.path())?;
    let discovered = discover_manifests_in_tree(temp_dir.path(), url.subpath.as_deref(), &url.raw)?;
    let primary = &discovered[0];
    let repo_config = &primary.config;
    let manifest_dir = &primary.manifest_dir;

    let target_groups: Vec<String> = if groups.is_empty() {
        repo_config.groups.keys().cloned().collect()
    } else {
        for g in groups {
            if !repo_config.groups.contains_key(g) {
                return Err(EngineError::GroupNotFound {
                    group: g.clone(),
                    available: repo_config.groups.keys().cloned().collect(),
                });
            }
        }
        groups.to_vec()
    };

    let os_info = OsInfo::detect();
    let home = resolve_home_for_state(state);
    let mut planned = Vec::new();
    let mut preview_entries = Vec::new();

    for g_name in &target_groups {
        let group = &repo_config.groups[g_name];
        let target_base = resolve_install_target_base(
            g_name,
            group,
            path_override,
            devices,
            &os_info,
            &home,
            &repo_config.groups,
        )?;
        validate_os_dir_path(&target_base, &home)?;

        let group_dir = manifest_dir.join(g_name);
        if !group_dir.is_dir() {
            continue;
        }
        let rules = parse_selection_rules(&group.files).unwrap_or_default();

        for entry in WalkDir::new(&group_dir).min_depth(1) {
            let entry = entry?;
            if entry.file_type().is_symlink() || is_symlink(entry.path()) {
                return Err(EngineError::HardBlockedPath {
                    path: entry.path().to_path_buf(),
                    reason: "symbolic links are prohibited inside a dotler repository".to_string(),
                });
            }
            if entry.file_type().is_dir() {
                continue;
            }
            let rel_path_str = entry
                .path()
                .strip_prefix(&group_dir)
                .unwrap()
                .to_string_lossy()
                .to_string();
            let is_enc = rel_path_str.ends_with(".enc");
            let clean_rel = rel_path_str
                .strip_suffix(".enc")
                .map(str::to_string)
                .unwrap_or_else(|| rel_path_str.clone());

            let mode = evaluate_selection(&rules, &clean_rel)
                .or_else(|| evaluate_selection(&rules, &rel_path_str));
            if !rules.is_empty() && matches!(mode, None | Some(SelectionMode::Exclude)) {
                continue;
            }

            let target_file_path = target_base.join(&clean_rel);
            validate_os_target_path(&target_file_path, &home)?;

            let raw_content = fs::read(entry.path())?;
            let is_template = mode.is_some_and(|m| m.is_template());
            let file_content = if is_template && !is_enc {
                render_home_template(&raw_content, &home, &clean_rel)?
            } else {
                raw_content
            };

            let os_action = if target_file_path.is_file() {
                PlanActionKind::Overwrite
            } else {
                PlanActionKind::Create
            };

            preview_entries.push(PlanPreviewEntry {
                group_name: g_name.clone(),
                os_path: target_file_path.clone(),
                os_action,
                repo_path: PathBuf::from(format!("{}/{}/{}", url.raw, g_name, rel_path_str)),
                repo_action: PlanActionKind::Okay,
                direction: if is_enc {
                    PlanDirection::DecryptToOs
                } else {
                    PlanDirection::PlainToOs
                },
            });

            planned.push(PlannedInstallFile {
                group_name: g_name.clone(),
                target_base: target_base.clone(),
                source_path: entry.path().to_path_buf(),
                clean_rel,
                target_file_path,
                file_content,
            });
        }
    }

    let approved = observer.confirm_plan(&preview_entries, dry_run)?;
    if dry_run {
        return Ok(InstallReport {
            installed_files: planned.into_iter().map(|p| p.target_file_path).collect(),
            backed_up_files: Vec::new(),
        });
    }
    if !approved {
        return Ok(InstallReport {
            installed_files: Vec::new(),
            backed_up_files: Vec::new(),
        });
    }

    execute_install_wal(planned, url, state, observer)
}

fn resolve_install_target_base(
    group_name: &str,
    group: &crate::config::repo::GroupConfig,
    path_override: Option<&Path>,
    devices: &[String],
    os_info: &OsInfo,
    home: &Path,
    all_groups: &std::collections::BTreeMap<String, crate::config::repo::GroupConfig>,
) -> Result<PathBuf, EngineError> {
    if let Some(override_path) = path_override {
        let path_str = override_path.to_string_lossy();
        let check_path = if path_str == "~" || path_str.starts_with("~/") {
            path_str.to_string()
        } else if override_path == home {
            "~".to_string()
        } else if let Ok(rel) = override_path.strip_prefix(home) {
            format!("~/{}", rel.to_string_lossy().trim_start_matches('/'))
        } else {
            path_str.to_string()
        };
        validate_path_security(&check_path)?;
        return Ok(expand_with_home(&path_str, home, override_path));
    }

    let path_str = resolve_group_target_path(group, devices, os_info).ok_or_else(|| {
        EngineError::GroupNotFound {
            group: group_name.to_string(),
            available: all_groups.keys().cloned().collect(),
        }
    })?;
    validate_path_security(&path_str)?;
    Ok(expand_with_home(&path_str, home, Path::new(&path_str)))
}

fn expand_with_home(raw: &str, home: &Path, fallback: &Path) -> PathBuf {
    if raw == "~" {
        home.to_path_buf()
    } else if let Some(stripped) = raw.strip_prefix("~/") {
        home.join(stripped)
    } else {
        fallback.to_path_buf()
    }
}

fn execute_install_wal(
    planned: Vec<PlannedInstallFile>,
    url: &RemoteRepoUrl,
    state: &StateDb,
    observer: &mut dyn CommandObserver,
) -> Result<InstallReport, EngineError> {
    let mut installed_files = Vec::new();
    let mut backed_up_files = Vec::new();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let total = planned.len();

    for item in planned {
        let _ = &item.source_path;
        let target_str = item.target_file_path.to_string_lossy().to_string();

        let existing = state.get_installed_file(&target_str)?;
        let backup_path = if let Some(ref ext) = existing {
            ext.backup_path.clone()
        } else if item.target_file_path.is_file() {
            let bp = create_backup_file(&item.target_file_path, &item.clean_rel, timestamp, state)?;
            backed_up_files.push(PathBuf::from(&bp));
            Some(bp)
        } else {
            None
        };

        let file_content = item.file_content;
        let hash = blake3::hash(&file_content).to_hex().to_string();
        state.upsert_installed_file(&InstalledFileRecord {
            target_path: target_str,
            repo_url: url.clone_url.clone(),
            group_name: item.group_name.clone(),
            relative_path: item.clean_rel.clone(),
            file_hash: hash,
            updated_at: timestamp,
            backup_path,
        })?;

        write_file_safe(&item.target_file_path, &file_content)?;
        installed_files.push(item.target_file_path);

        observer.on_file_progress(
            &item.group_name,
            &item.target_base,
            &item.clean_rel,
            Some(file_content.len() as u64),
        );
    }

    if total > 0 {
        observer.finish_progress();
    }

    Ok(InstallReport {
        installed_files,
        backed_up_files,
    })
}

/// Uninstalls tracked `git install` deployments using [`NoopObserver`].
pub fn uninstall_remote(
    groups: &[String],
    state: &StateDb,
    lock: &DotlerLockGuard,
    dry_run: bool,
) -> Result<UninstallReport, EngineError> {
    let mut noop = NoopObserver;
    uninstall_remote_with_observer(groups, state, lock, dry_run, &mut noop)
}

/// Restores backups and removes `installed_files` records with an interactive [`CommandObserver`].
pub fn uninstall_remote_with_observer(
    groups: &[String],
    state: &StateDb,
    _lock: &DotlerLockGuard,
    dry_run: bool,
    observer: &mut dyn CommandObserver,
) -> Result<UninstallReport, EngineError> {
    let all_records = state.list_installed_files(None)?;
    let filtered_records: Vec<InstalledFileRecord> = if groups.is_empty() {
        all_records
    } else {
        all_records
            .into_iter()
            .filter(|r| groups.iter().any(|g| g == &r.group_name))
            .collect()
    };

    let preview_entries: Vec<PlanPreviewEntry> = filtered_records
        .iter()
        .map(|record| {
            let target = PathBuf::from(&record.target_path);
            let has_backup = record
                .backup_path
                .as_ref()
                .is_some_and(|bp| Path::new(bp).is_file());
            let (os_action, repo_path) = if has_backup {
                (
                    PlanActionKind::Overwrite,
                    PathBuf::from(record.backup_path.as_deref().unwrap_or("")),
                )
            } else {
                (
                    PlanActionKind::Delete,
                    PathBuf::from(format!(
                        "{}/{}/{}",
                        record.repo_url, record.group_name, record.relative_path
                    )),
                )
            };
            PlanPreviewEntry {
                group_name: record.group_name.clone(),
                os_path: target,
                os_action,
                repo_path,
                repo_action: PlanActionKind::Okay,
                direction: PlanDirection::PlainToOs,
            }
        })
        .collect();

    let approved = observer.confirm_plan(&preview_entries, dry_run)?;
    if !dry_run && !approved {
        return Ok(UninstallReport {
            removed_files: Vec::new(),
            restored_backups: Vec::new(),
        });
    }

    let mut removed_files = Vec::new();
    let mut restored_backups = Vec::new();
    let total = filtered_records.len();

    for record in filtered_records {
        let target = PathBuf::from(&record.target_path);
        let group_base = target.parent().unwrap_or(Path::new(".")).to_path_buf();
        let bp = record.backup_path.as_deref().map(PathBuf::from);
        if let Some(ref backup_path) = bp
            && backup_path.is_file()
        {
            if !dry_run {
                let backup_bytes = fs::read(backup_path)?;
                write_file_safe(&target, &backup_bytes)?;
                state.remove_installed_file(&record.target_path)?;
                let _ = fs::remove_file(backup_path);
                if let Some(p) = backup_path.parent() {
                    let _ = fs::remove_dir(p);
                }
            }
            restored_backups.push(target);
        } else {
            if !dry_run {
                if target.is_file() || is_symlink(&target) {
                    let _ = fs::remove_file(&target);
                }
                state.remove_installed_file(&record.target_path)?;
            }
            removed_files.push(target);
        }

        if !dry_run {
            observer.on_file_progress(&record.group_name, &group_base, &record.relative_path, None);
        }
    }

    if !dry_run && total > 0 {
        observer.finish_progress();
    }

    Ok(UninstallReport {
        removed_files,
        restored_backups,
    })
}

/// High-level entry point for `dotler git install` shared by CLI and MCP.
#[allow(clippy::too_many_arguments)]
pub fn run_git_install(
    ctx: &CoreContext,
    url_raw: &str,
    groups: &[String],
    path_override: Option<&Path>,
    branch: Option<&str>,
    lock: &DotlerLockGuard,
    dry_run: bool,
    observer: &mut dyn CommandObserver,
) -> Result<InstallReport, EngineError> {
    let url = parse_url(url_raw)?;
    let local_cfg = ctx.local_config.get()?;
    let devices = ctx.effective_devices(local_cfg);
    let state = ctx.state_db.get()?;
    install_remote_with_observer(
        &url,
        groups,
        path_override,
        branch,
        &devices,
        state,
        lock,
        dry_run,
        observer,
    )
}

/// High-level entry point for `dotler git uninstall` shared by CLI and MCP.
pub fn run_git_uninstall(
    ctx: &CoreContext,
    groups: &[String],
    lock: &DotlerLockGuard,
    dry_run: bool,
    observer: &mut dyn CommandObserver,
) -> Result<UninstallReport, EngineError> {
    let state = ctx.state_db.get()?;
    uninstall_remote_with_observer(groups, state, lock, dry_run, observer)
}

fn create_backup_file(
    source: &Path,
    rel: &str,
    timestamp: i64,
    state: &StateDb,
) -> Result<String, EngineError> {
    let backup_root = if let Some(dotler_dir) = state.path().parent() {
        dotler_dir
            .join(BACKUPS_DIR_NAME)
            .join(timestamp.to_string())
    } else {
        expand_tilde(BACKUPS_DIR_PATH).join(timestamp.to_string())
    };
    let dest = backup_root.join(rel);
    let source_bytes = fs::read(source)?;
    write_file_safe(&dest, &source_bytes)?;
    Ok(dest.to_string_lossy().to_string())
}

fn resolve_home_for_state(state: &StateDb) -> PathBuf {
    if let Some(home) = state
        .path()
        .parent()
        .filter(|d| d.file_name().and_then(|s| s.to_str()) == Some("dotler"))
        .and_then(|d| d.parent())
        .filter(|c| c.file_name().and_then(|s| s.to_str()) == Some(".config"))
        .and_then(|c| c.parent())
    {
        home.to_path_buf()
    } else {
        std::env::home_dir().unwrap_or_else(|| PathBuf::from("."))
    }
}
