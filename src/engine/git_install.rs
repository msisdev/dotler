//! WAL-backed remote installation (`git install`) and atomic rollback (`git uninstall`).

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::local::{WalkDir, expand_tilde, resolve_home_for_config_path};
use crate::config::repo::{
    OsInfo, SelectionMode, evaluate_selection, is_cwd_group_path, is_home_group_path, is_symlink,
    parse_selection_rules, prune_empty_parent_dirs, render_home_template,
    resolve_group_target_path, validate_os_dir_path_with_home, validate_os_target_path_with_home,
    validate_path_security, validate_rule_pattern,
};
use crate::config::state::{
    BACKUPS_DIR_PATH, DotlerLockGuard, InstalledFileRecord, StateDb, write_file_safe,
};
use crate::core::context::CoreContext;
use crate::core::vault_loader::unlock_vault_if_needed;
use crate::crypto::ExposeSecret;
use crate::crypto::vault::{
    EncryptedFile, FullEncryptedFile, VaultKey, is_content_enc_name, is_full_enc_name,
    strip_content_enc_suffix,
};
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
    lock: &DotlerLockGuard,
    dry_run: bool,
    observer: &mut dyn CommandObserver,
) -> Result<InstallReport, EngineError> {
    install_remote_with_options(
        url,
        groups,
        path_override,
        branch,
        devices,
        state,
        lock,
        dry_run,
        true,
        false,
        None,
        observer,
    )
}

/// Installs remote repository dotfiles with explicit keyring, interactivity, and vault key options.
#[allow(clippy::too_many_arguments)]
pub fn install_remote_with_options(
    url: &RemoteRepoUrl,
    groups: &[String],
    path_override: Option<&Path>,
    branch: Option<&str>,
    devices: &[String],
    state: &StateDb,
    lock: &DotlerLockGuard,
    dry_run: bool,
    use_keyring: bool,
    is_interactive: bool,
    vault_key_override: Option<&VaultKey>,
    observer: &mut dyn CommandObserver,
) -> Result<InstallReport, EngineError> {
    install_remote_with_cwd(
        url,
        groups,
        path_override,
        branch,
        devices,
        state,
        lock,
        dry_run,
        use_keyring,
        is_interactive,
        vault_key_override,
        None,
        observer,
    )
}

/// Installs remote repository dotfiles with explicit working directory resolution for `.`/`./...` paths.
#[allow(clippy::too_many_arguments)]
pub fn install_remote_with_cwd(
    url: &RemoteRepoUrl,
    groups: &[String],
    path_override: Option<&Path>,
    branch: Option<&str>,
    devices: &[String],
    state: &StateDb,
    _lock: &DotlerLockGuard,
    dry_run: bool,
    use_keyring: bool,
    is_interactive: bool,
    vault_key_override: Option<&VaultKey>,
    cwd_override: Option<&Path>,
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
    let home = resolve_home_for_config_path(state.path());
    let cwd = match cwd_override {
        Some(dir) => dir.to_path_buf(),
        None => std::env::current_dir()?,
    };
    let mut unlocked_vault_key: Option<VaultKey> = None;
    let mut planned = Vec::new();
    let mut preview_entries = Vec::new();

    for g_name in &target_groups {
        let group = &repo_config.groups[g_name];
        let (target_base, boundary_dir) = resolve_install_target_base(
            g_name,
            group,
            path_override,
            devices,
            &os_info,
            &home,
            &cwd,
            &repo_config.groups,
        )?;
        validate_os_dir_path_with_home(&target_base, &boundary_dir, &home)?;

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
            let raw_content = fs::read(entry.path())?;
            let is_fenc = is_full_enc_name(&rel_path_str);
            let is_enc = is_content_enc_name(&rel_path_str);

            let (clean_rel, mode, plaintext_bytes) = if is_fenc {
                let key = if let Some(override_key) = vault_key_override {
                    override_key
                } else {
                    if unlocked_vault_key.is_none() {
                        unlocked_vault_key =
                            unlock_vault_if_needed(repo_config, use_keyring, is_interactive, true)?;
                    }
                    unlocked_vault_key.as_ref().ok_or(EngineError::Config(
                        crate::config::ConfigError::MissingVaultConfig,
                    ))?
                };
                let fname = entry.file_name().to_string_lossy();
                let fenc_file = FullEncryptedFile::from_bytes(&raw_content)?;
                let (dec_rel, plain_sec) = key.decrypt_full_file(&fname, &fenc_file)?;
                validate_rule_pattern(&dec_rel)?;
                let mode = evaluate_selection(&rules, &dec_rel);
                if !rules.is_empty() && matches!(mode, None | Some(SelectionMode::Exclude)) {
                    continue;
                }
                if let Some(m) = mode
                    && !m.is_full_encrypted()
                {
                    return Err(EngineError::EncryptionMismatch {
                        path: entry.path().to_path_buf(),
                        reason: format!(
                            "Remote repository file '{rel_path_str}' (.dotler.fenc) conflicts with selection rule in dotler.toml."
                        ),
                    });
                }
                (dec_rel, mode, plain_sec.expose_secret().clone())
            } else {
                let clean_rel = strip_content_enc_suffix(&rel_path_str)
                    .map(str::to_string)
                    .unwrap_or_else(|| rel_path_str.clone());
                let mode = evaluate_selection(&rules, &clean_rel)
                    .or_else(|| evaluate_selection(&rules, &rel_path_str));
                if !rules.is_empty() && matches!(mode, None | Some(SelectionMode::Exclude)) {
                    continue;
                }
                if let Some(m) = mode {
                    let enc_conflict = (is_enc && m.is_included() && !m.is_content_encrypted())
                        || (!is_enc && m.is_encrypted());
                    if enc_conflict {
                        return Err(EngineError::EncryptionMismatch {
                            path: entry.path().to_path_buf(),
                            reason: format!(
                                "Remote repository file '{rel_path_str}' conflicts with encryption rule in dotler.toml."
                            ),
                        });
                    }
                }
                let plain = if is_enc {
                    let key = if let Some(override_key) = vault_key_override {
                        override_key
                    } else {
                        if unlocked_vault_key.is_none() {
                            unlocked_vault_key = unlock_vault_if_needed(
                                repo_config,
                                use_keyring,
                                is_interactive,
                                true,
                            )?;
                        }
                        unlocked_vault_key.as_ref().ok_or(EngineError::Config(
                            crate::config::ConfigError::MissingVaultConfig,
                        ))?
                    };
                    let enc_file = EncryptedFile::from_bytes(&raw_content)?;
                    key.decrypt_file(&enc_file)?.expose_secret().clone()
                } else {
                    raw_content
                };
                (clean_rel, mode, plain)
            };

            let target_file_path = target_base.join(&clean_rel);
            validate_os_target_path_with_home(&target_file_path, &boundary_dir, &home)?;

            let is_template = mode.is_some_and(|m| m.is_template());
            let file_content = if is_template {
                render_home_template(&plaintext_bytes, &home, &clean_rel)?
            } else {
                plaintext_bytes
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
                direction: if is_enc || is_fenc {
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

#[allow(clippy::too_many_arguments)]
fn resolve_install_target_base(
    group_name: &str,
    group: &crate::config::repo::GroupConfig,
    path_override: Option<&Path>,
    devices: &[String],
    os_info: &OsInfo,
    home: &Path,
    cwd: &Path,
    all_groups: &std::collections::BTreeMap<String, crate::config::repo::GroupConfig>,
) -> Result<(PathBuf, PathBuf), EngineError> {
    if let Some(override_path) = path_override {
        let path_str = override_path.to_string_lossy();
        if is_home_group_path(&path_str) {
            validate_path_security(&path_str)?;
            return Ok((
                expand_with_home(&path_str, home, override_path),
                home.to_path_buf(),
            ));
        }
        if is_cwd_group_path(&path_str) {
            validate_path_security(&path_str)?;
            return Ok((expand_with_cwd(&path_str, cwd), cwd.to_path_buf()));
        }
        if override_path == home {
            validate_path_security("~")?;
            return Ok((home.to_path_buf(), home.to_path_buf()));
        }
        if let Ok(rel) = override_path.strip_prefix(home) {
            let check_path = format!("~/{}", rel.to_string_lossy().trim_start_matches('/'));
            validate_path_security(&check_path)?;
            return Ok((override_path.to_path_buf(), home.to_path_buf()));
        }
        if override_path == cwd {
            validate_path_security(".")?;
            return Ok((cwd.to_path_buf(), cwd.to_path_buf()));
        }
        if let Ok(rel) = override_path.strip_prefix(cwd) {
            let check_path = format!("./{}", rel.to_string_lossy().trim_start_matches('/'));
            validate_path_security(&check_path)?;
            return Ok((override_path.to_path_buf(), cwd.to_path_buf()));
        }
        validate_path_security(&path_str)?;
        return Ok((
            expand_with_home(&path_str, home, override_path),
            home.to_path_buf(),
        ));
    }

    let path_str = resolve_group_target_path(group, devices, os_info).ok_or_else(|| {
        EngineError::GroupNotFound {
            group: group_name.to_string(),
            available: all_groups.keys().cloned().collect(),
        }
    })?;
    validate_path_security(&path_str)?;
    if is_cwd_group_path(&path_str) {
        return Ok((expand_with_cwd(&path_str, cwd), cwd.to_path_buf()));
    }
    Ok((
        expand_with_home(&path_str, home, Path::new(&path_str)),
        home.to_path_buf(),
    ))
}

fn expand_with_home(raw: &str, home: &Path, fallback: &Path) -> PathBuf {
    if raw == "~" {
        home.to_path_buf()
    } else if let Some(stripped) = raw.strip_prefix("~/") {
        let rel = stripped.trim_matches('/');
        if rel.is_empty() {
            home.to_path_buf()
        } else {
            home.join(rel)
        }
    } else {
        fallback.to_path_buf()
    }
}

fn expand_with_cwd(raw: &str, cwd: &Path) -> PathBuf {
    let mut rel = raw.strip_prefix('.').unwrap_or(raw).trim_start_matches('/');
    while let Some(next) = rel.strip_prefix("./") {
        rel = next.trim_start_matches('/');
    }
    let rel = rel.trim_end_matches('/');
    if rel.is_empty() || rel == "." {
        cwd.to_path_buf()
    } else {
        cwd.join(rel)
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
            let bp = create_backup_file(
                &item.target_file_path,
                &item.group_name,
                &item.clean_rel,
                timestamp,
                state,
            )?;
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
    let backups_root = if let Some(dotler_dir) = state.path().parent() {
        dotler_dir.join(BACKUPS_DIR_NAME)
    } else {
        expand_tilde(BACKUPS_DIR_PATH)
    };
    let home = resolve_home_for_config_path(state.path());

    for record in filtered_records {
        let target = PathBuf::from(&record.target_path);
        let group_base = resolve_installed_group_base(&target, &record.relative_path, &home);
        let bp = record.backup_path.as_deref().map(PathBuf::from);
        if let Some(ref backup_path) = bp
            && backup_path.is_file()
        {
            if !dry_run {
                let backup_bytes = fs::read(backup_path)?;
                write_file_safe(&target, &backup_bytes)?;
                state.remove_installed_file(&record.target_path)?;
                let _ = fs::remove_file(backup_path);
                prune_empty_parent_dirs(backup_path, &backups_root);
            }
            restored_backups.push(target);
        } else {
            if !dry_run {
                if target.is_file() || is_symlink(&target) {
                    let _ = fs::remove_file(&target);
                }
                prune_empty_parent_dirs(&target, &group_base);
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
    let effective_cwd = ctx.effective_cwd()?;
    install_remote_with_cwd(
        &url,
        groups,
        path_override,
        branch,
        &devices,
        state,
        lock,
        dry_run,
        local_cfg.use_keyring,
        ctx.is_interactive,
        None,
        Some(&effective_cwd),
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
    group_name: &str,
    rel: &str,
    timestamp: i64,
    state: &StateDb,
) -> Result<String, EngineError> {
    let backup_root = if let Some(dotler_dir) = state.path().parent() {
        dotler_dir
            .join(BACKUPS_DIR_NAME)
            .join(timestamp.to_string())
            .join(group_name)
    } else {
        expand_tilde(BACKUPS_DIR_PATH)
            .join(timestamp.to_string())
            .join(group_name)
    };
    let dest = backup_root.join(rel);
    let source_bytes = fs::read(source)?;
    write_file_safe(&dest, &source_bytes)?;
    Ok(dest.to_string_lossy().to_string())
}

fn resolve_installed_group_base(target: &Path, relative_path: &str, home: &Path) -> PathBuf {
    let rel_comps: Vec<_> = Path::new(relative_path)
        .components()
        .filter(|c| matches!(c, std::path::Component::Normal(_)))
        .collect();
    if !rel_comps.is_empty() {
        let mut base = target.to_path_buf();
        let mut matched = true;
        for comp in rel_comps.into_iter().rev() {
            if base.file_name() == Some(comp.as_os_str()) {
                base.pop();
            } else {
                matched = false;
                break;
            }
        }
        if matched && !base.as_os_str().is_empty() && base.parent().is_some() {
            return base;
        }
    }
    home.to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::state::DotlerLock;
    use crate::crypto::SecretString;
    use crate::crypto::vault::init_vault;
    use std::process::Command;
    use std::time::Duration;

    fn create_test_bare_repo(
        dotler_toml: &str,
        files: &[(&str, &[u8])],
    ) -> (tempfile::TempDir, RemoteRepoUrl) {
        let tmp = tempfile::tempdir().unwrap();
        let wt = tmp.path().join("wt");
        let bare = tmp.path().join("bare.git");
        fs::create_dir_all(&wt).unwrap();
        let run = |args: &[&str], dir: &Path| {
            let st = Command::new("git")
                .args(args)
                .current_dir(dir)
                .status()
                .unwrap();
            assert!(st.success(), "git {:?} failed", args);
        };
        run(&["init", "-b", "main"], &wt);
        run(&["config", "user.name", "Tester"], &wt);
        run(&["config", "user.email", "test@dotler.dev"], &wt);
        fs::write(wt.join("dotler.toml"), dotler_toml).unwrap();
        for (rel, body) in files {
            let p = wt.join(rel);
            if let Some(parent) = p.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(p, body).unwrap();
        }
        run(&["add", "."], &wt);
        run(&["commit", "-m", "seed"], &wt);
        run(
            &[
                "clone",
                "--bare",
                wt.to_str().unwrap(),
                bare.to_str().unwrap(),
            ],
            tmp.path(),
        );
        let url = parse_url(&format!("file://{}", bare.display())).unwrap();
        (tmp, url)
    }

    #[test]
    fn install_remote_decrypts_enc_and_enc_tmpl_and_rejects_locked_vault() {
        let _mock = crate::crypto::keyring::MockKeyringGuard::new();
        unsafe {
            std::env::remove_var(crate::crypto::keyring::PASSPHRASE_ENV_VAR);
        }

        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let dotler_dir = home.join(".config").join("dotler");
        fs::create_dir_all(&dotler_dir).unwrap();
        let state = StateDb::open(&dotler_dir.join("state.db")).unwrap();
        let lock = DotlerLock::new(dotler_dir.join("dotler.lock"))
            .acquire(Duration::from_millis(500), Duration::from_millis(10))
            .unwrap();

        let pass = SecretString::new("remote-install-pass-123".to_string());
        let (vcfg, vkey, _) = init_vault(&pass).unwrap();
        let enc_plain = vkey.encrypt_file(b"API_KEY=xyz\n").unwrap().to_bytes();
        let enc_tmpl = vkey
            .encrypt_file(b"HOME_DIR={{ $HOME }}/bin\n")
            .unwrap()
            .to_bytes();

        let remote_toml = format!(
            "vault_id = \"{}\"\npassword_slot = \"{}\"\nrecovery_slot = \"{}\"\n\n[sec]\nos-nux = \"~\"\nos-mac = \"~\"\nos-win = \"~\"\nos-bsd = \"~\"\nfiles = \"\"\"\n.env enc\n.path_env enc tmpl\n\"\"\"\n",
            vcfg.vault_id, vcfg.password_slot, vcfg.recovery_slot
        );
        let (_git_tmp, url) = create_test_bare_repo(
            &remote_toml,
            &[
                ("sec/.env.dotler.enc", &enc_plain),
                ("sec/.path_env.dotler.enc", &enc_tmpl),
            ],
        );

        // Non-interactive without keyring or passphrase must fail with VaultLocked
        let mut obs = NoopObserver;
        let locked_err = install_remote_with_options(
            &url,
            &["sec".to_string()],
            None,
            None,
            &[],
            &state,
            &lock,
            false,
            true,
            false,
            None,
            &mut obs,
        )
        .unwrap_err();
        assert_eq!(locked_err.exit_code(), 4);

        // With vault key unlocked (e.g. keyring), both `.enc` and `enc tmpl` deploy as plaintext
        crate::crypto::keyring::OsKeyring::set_for_vault(&vcfg.vault_id, &pass).unwrap();
        let rep =
            install_remote(&url, &["sec".to_string()], None, None, &[], &state, &lock).unwrap();
        assert_eq!(rep.installed_files.len(), 2);
        assert_eq!(fs::read(home.join(".env")).unwrap(), b"API_KEY=xyz\n");
        assert_eq!(
            fs::read_to_string(home.join(".path_env")).unwrap(),
            format!("HOME_DIR={}/bin\n", home.display())
        );
    }

    #[test]
    fn install_isolates_same_second_cross_group_backups_and_uninstall_prunes_empty_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let dotler_dir = home.join(".config").join("dotler");
        fs::create_dir_all(home.join(".config/app1")).unwrap();
        fs::create_dir_all(home.join(".config/app2")).unwrap();
        fs::create_dir_all(&dotler_dir).unwrap();
        fs::write(home.join(".config/app1/config.toml"), b"app1-original\n").unwrap();
        fs::write(home.join(".config/app2/config.toml"), b"app2-original\n").unwrap();

        let state = StateDb::open(&dotler_dir.join("state.db")).unwrap();
        let lock = DotlerLock::new(dotler_dir.join("dotler.lock"))
            .acquire(Duration::from_millis(500), Duration::from_millis(10))
            .unwrap();

        let remote_toml = r#"
[app1]
os-nux = "~/.config/app1"
os-mac = "~/.config/app1"
os-win = "~/.config/app1"
os-bsd = "~/.config/app1"
files = "config.toml"

[app2]
os-nux = "~/.config/app2"
os-mac = "~/.config/app2"
os-win = "~/.config/app2"
os-bsd = "~/.config/app2"
files = "config.toml"

[fresh]
os-nux = "~/.config/fresh"
os-mac = "~/.config/fresh"
os-win = "~/.config/fresh"
os-bsd = "~/.config/fresh"
files = "nested/new.conf"
"#;
        let (_git_tmp, url) = create_test_bare_repo(
            remote_toml,
            &[
                ("app1/config.toml", b"app1-remote\n"),
                ("app2/config.toml", b"app2-remote\n"),
                ("fresh/nested/new.conf", b"fresh-remote\n"),
            ],
        );

        let rep = install_remote(&url, &[], None, None, &[], &state, &lock).unwrap();
        assert_eq!(rep.installed_files.len(), 3);
        assert_eq!(rep.backed_up_files.len(), 2);
        assert_ne!(rep.backed_up_files[0], rep.backed_up_files[1]);

        let uninst = uninstall_remote(&[], &state, &lock, false).unwrap();
        assert_eq!(uninst.restored_backups.len(), 2);
        assert_eq!(uninst.removed_files.len(), 1);
        assert_eq!(
            fs::read(home.join(".config/app1/config.toml")).unwrap(),
            b"app1-original\n"
        );
        assert_eq!(
            fs::read(home.join(".config/app2/config.toml")).unwrap(),
            b"app2-original\n"
        );
        assert!(!home.join(".config/fresh/nested").exists());
        assert_eq!(
            fs::read_dir(dotler_dir.join(BACKUPS_DIR_NAME))
                .unwrap()
                .count(),
            0
        );
    }

    #[test]
    fn install_remote_and_uninstall_support_cwd_group_and_relative_path_override() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let dotler_dir = home.join(".config").join("dotler");
        let project_dir = tmp.path().join("project_outside_home");
        fs::create_dir_all(&dotler_dir).unwrap();
        fs::create_dir_all(project_dir.join("sub")).unwrap();
        fs::write(project_dir.join("sub/existing.env"), b"OLD_VAL=1\n").unwrap();

        let state = StateDb::open(&dotler_dir.join("state.db")).unwrap();
        let lock = DotlerLock::new(dotler_dir.join("dotler.lock"))
            .acquire(Duration::from_millis(500), Duration::from_millis(10))
            .unwrap();

        let remote_toml = r#"
[proj]
os-nux = "."
os-mac = "."
os-win = "."
os-bsd = "."
files = """
sub/existing.env
fresh/nested/new.env
"""
"#;
        let (_git_tmp, url) = create_test_bare_repo(
            remote_toml,
            &[
                ("proj/sub/existing.env", b"NEW_VAL=2\n"),
                ("proj/fresh/nested/new.env", b"FRESH=1\n"),
            ],
        );

        let mut obs = NoopObserver;
        let rep = install_remote_with_cwd(
            &url,
            &["proj".to_string()],
            None,
            None,
            &[],
            &state,
            &lock,
            false,
            false,
            false,
            None,
            Some(&project_dir),
            &mut obs,
        )
        .unwrap();
        assert_eq!(rep.installed_files.len(), 2);
        assert_eq!(
            fs::read(project_dir.join("sub/existing.env")).unwrap(),
            b"NEW_VAL=2\n"
        );
        assert_eq!(
            fs::read(project_dir.join("fresh/nested/new.env")).unwrap(),
            b"FRESH=1\n"
        );

        // Escaping cwd via `-p ./../escape` must be blocked with HardBlockedPath.
        let escape_err = install_remote_with_cwd(
            &url,
            &["proj".to_string()],
            Some(Path::new("./../escape")),
            None,
            &[],
            &state,
            &lock,
            false,
            false,
            false,
            None,
            Some(&project_dir),
            &mut obs,
        )
        .unwrap_err();
        assert_eq!(escape_err.exit_code(), 3);

        // Uninstall restores backed-up file, deletes fresh file, and prunes empty nested dirs up to `project_dir`.
        let uninst = uninstall_remote(&["proj".to_string()], &state, &lock, false).unwrap();
        assert_eq!(uninst.restored_backups.len(), 1);
        assert_eq!(uninst.removed_files.len(), 1);
        assert_eq!(
            fs::read(project_dir.join("sub/existing.env")).unwrap(),
            b"OLD_VAL=1\n"
        );
        assert!(!project_dir.join("fresh").exists());
        assert!(project_dir.is_dir());

        // Explicit `-p ./override_sub` deploys relative to `cwd`.
        let rep2 = install_remote_with_cwd(
            &url,
            &["proj".to_string()],
            Some(Path::new("./override_sub")),
            None,
            &[],
            &state,
            &lock,
            false,
            false,
            false,
            None,
            Some(&project_dir),
            &mut obs,
        )
        .unwrap();
        assert_eq!(rep2.installed_files.len(), 2);
        assert_eq!(
            fs::read(project_dir.join("override_sub/sub/existing.env")).unwrap(),
            b"NEW_VAL=2\n"
        );
    }
}
