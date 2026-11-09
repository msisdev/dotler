//! Workspace initialization, unified static/format validation, and 3-way status reconciliation.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::agent::briefing::scaffold_skill_md;
use crate::config::local::{WalkDir, expand_tilde};
use crate::config::repo::{
    SelectionMode, evaluate_selection, parse_selection_rules, resolve_group_target_path,
    validate_dir_no_symlinks, validate_os_dir_path, validate_os_target_path,
    validate_path_security,
};
use crate::config::state::{DotlerLockGuard, TMP_FILE_PREFIX, write_file_safe};
use crate::core::context::CoreContext;
use crate::core::vault_loader::{
    has_encrypted_repo_files, has_encrypted_rules, unlock_vault_if_needed,
};
use crate::crypto::ExposeSecret;
use crate::crypto::vault::EncryptedFile;
use crate::engine::EngineError;
use crate::engine::sync::SyncEngine;

/// 3-way synchronization status classification for an individual file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileSyncStatus {
    Synced,
    ModifiedLocally,
    ModifiedInRepo,
    Conflict,
    MissingLocally,
    MissingInRepo,
    EncryptionMismatch,
    Orphaned,
}

/// Planned action and 3-way hash state for a single dotfile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileActionPlan {
    pub repo_label: String,
    pub group_name: String,
    pub relative_path: String,
    pub target_os_path: PathBuf,
    pub repo_file_path: PathBuf,
    pub status: FileSyncStatus,
    pub is_encrypted: bool,
    pub os_hash: Option<String>,
    pub repo_hash: Option<String>,
    pub db_hash: Option<String>,
}

/// Result summary returned by [`run_check`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckReport {
    pub status: String,
    pub groups_checked: usize,
}

/// Parameters for [`run_init`].
#[derive(Debug, Clone, Default)]
pub struct InitParams {
    pub label: Option<String>,
    pub device: Option<String>,
    pub repo_path: Option<PathBuf>,
}

/// Result summary returned by [`run_init`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InitReport {
    pub label: String,
    pub device: String,
    pub repo_path: PathBuf,
    pub skill_path: PathBuf,
}

/// Scaffolds a new dotler repository (`dotler.toml` and `SKILL.md`) and registers it in `config.toml`.
pub fn run_init(
    ctx: &mut CoreContext,
    params: InitParams,
    _lock: &DotlerLockGuard,
) -> Result<InitReport, EngineError> {
    let repo_dir = match params.repo_path {
        Some(p) => p,
        None => std::env::current_dir()?,
    };

    fs::create_dir_all(&repo_dir)?;

    let dotler_toml_path = repo_dir.join("dotler.toml");
    if !dotler_toml_path.exists() {
        let initial_toml = r#"# [bash]
# # Priority 1: Custom device names (configured in ~/.config/dotler/config.toml `default_devices`)
# default = "~"
#
# # Priority 2: Specific OS / Linux distribution
# os-arch = "~"
# os-debian = "~"
# os-ubuntu = "~"
# os-fedora = "~"
# os-nixos = "~"
# os-alpine = "~"
# os-freebsd = "~"
# os-openbsd = "~"
#
# # Priority 3: OS family fallback
# os-nux = "~"
# os-mac = "~"
# os-win = "~"
# os-bsd = "~"
#
# files = """
# !*
# .bashrc encrypt
# .bashrc
# """
"#;
        write_file_safe(&dotler_toml_path, initial_toml.as_bytes())?;
    }

    let skill_path = scaffold_skill_md(&repo_dir)
        .map_err(|e| EngineError::Io(std::io::Error::other(e.to_string())))?;

    let mut local_cfg = ctx.local_config.get().cloned().unwrap_or_default();

    let label = params
        .label
        .or_else(|| ctx.repo_override.clone())
        .unwrap_or_else(|| {
            repo_dir
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "default".to_string())
        });

    let device = params
        .device
        .or_else(|| ctx.device_override.clone())
        .unwrap_or_else(|| "default".to_string());

    let home = std::env::home_dir().unwrap_or_else(|| PathBuf::from("~"));
    let repo_path_entry = if let Ok(rel) = repo_dir.strip_prefix(&home) {
        if rel.as_os_str().is_empty() {
            "~".to_string()
        } else {
            format!("~/{}", rel.display())
        }
    } else {
        format!(
            "~/{}",
            repo_dir
                .file_name()
                .map(|f| f.to_string_lossy())
                .unwrap_or_default()
        )
    };

    if local_cfg.default_repo.is_none() {
        local_cfg.default_repo = Some(label.clone());
    }
    local_cfg.repos.insert(label.clone(), repo_path_entry);

    if !local_cfg.default_devices.contains(&device) {
        local_cfg.default_devices.push(device.clone());
    }

    ctx.local_config.set(local_cfg)?;

    Ok(InitReport {
        label,
        device,
        repo_path: repo_dir,
        skill_path,
    })
}

/// Runs the 4-stage unified validation pipeline shared by CLI (`dotler check`) and MCP (`dotler_check`).
pub fn run_check(
    ctx: &CoreContext,
    group_filter: Option<&str>,
    _lock: &DotlerLockGuard,
) -> Result<CheckReport, EngineError> {
    let resolved = ctx.resolve_repo()?;
    let repo_cfg = &resolved.repo_config;
    let repo_path = &resolved.repo_path;

    // 1. Validate group filter existence
    if let Some(filter_grp) = group_filter
        && !repo_cfg.groups.contains_key(filter_grp)
    {
        let available = repo_cfg.groups.keys().cloned().collect();
        return Err(EngineError::GroupNotFound {
            group: filter_grp.to_string(),
            available,
        });
    }

    // 2. Validate path security and 3-state selection rule syntax
    for (g_name, g_cfg) in &repo_cfg.groups {
        if let Some(filter) = group_filter
            && filter != g_name
        {
            continue;
        }
        for p in g_cfg.paths.values() {
            validate_path_security(p)?;
        }
        parse_selection_rules(&g_cfg.files)?;
    }

    // 3. Detect cross-group target file collisions
    repo_cfg.detect_cross_group_collisions(&resolved.devices, &resolved.os_info)?;

    // 4. Reject symlinks in repository and detect .enc format mismatches
    let home_dir = expand_tilde("~");
    for (g_name, g_cfg) in &repo_cfg.groups {
        if let Some(filter) = group_filter
            && filter != g_name
        {
            continue;
        }
        let group_repo_dir = repo_path.join(g_name);
        validate_dir_no_symlinks(&group_repo_dir)?;
        if let Some(target_base_str) =
            resolve_group_target_path(g_cfg, &resolved.devices, &resolved.os_info)
        {
            let target_base_path = expand_tilde(&target_base_str);
            validate_os_dir_path(&target_base_path, &home_dir)?;
        }
        if !group_repo_dir.is_dir() {
            continue;
        }
        let rules = parse_selection_rules(&g_cfg.files)?;
        for entry in WalkDir::new(&group_repo_dir)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file() {
                let file_name = entry.file_name().to_string_lossy();
                if file_name.starts_with(TMP_FILE_PREFIX) || file_name == ".git" {
                    continue;
                }
                if let Ok(rel) = entry.path().strip_prefix(&group_repo_dir) {
                    let rel_str = rel.to_string_lossy();
                    if rel_str.split('/').any(|s| s == ".git") {
                        continue;
                    }
                    let (clean_rel, is_enc_file) =
                        if let Some(stripped) = rel_str.strip_suffix(".enc") {
                            (stripped.to_string(), true)
                        } else {
                            (rel_str.to_string(), false)
                        };
                    if let Some(mode) = evaluate_selection(&rules, &clean_rel) {
                        match mode {
                            SelectionMode::EncryptedInclude if !is_enc_file => {
                                return Err(EngineError::EncryptionMismatch {
                                    path: entry.path().to_path_buf(),
                                    reason: format!(
                                        "Repository file '{}' format conflicts with encryption rule in dotler.toml. Run 'dotler tidy' to reconcile format.",
                                        clean_rel
                                    ),
                                });
                            }
                            SelectionMode::PlaintextInclude if is_enc_file => {
                                return Err(EngineError::EncryptionMismatch {
                                    path: entry.path().to_path_buf(),
                                    reason: format!(
                                        "Repository file '{}' format conflicts with encryption rule in dotler.toml. Run 'dotler tidy' to reconcile format.",
                                        clean_rel
                                    ),
                                });
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    Ok(CheckReport {
        status: "valid".to_string(),
        groups_checked: repo_cfg.groups.len(),
    })
}

/// Computes the 3-way synchronization status across OS files, repository files, and `state.db`.
pub fn run_status(
    ctx: &CoreContext,
    group_filter: Option<&str>,
    lock: &DotlerLockGuard,
) -> Result<Vec<FileActionPlan>, EngineError> {
    let local_cfg = ctx.local_config.get()?;
    let resolved = ctx.resolve_repo()?;
    let state_db = ctx.state_db.get()?;

    let has_enc = has_encrypted_rules(&resolved.repo_config)
        || has_encrypted_repo_files(&resolved.repo_path, &resolved.repo_config);
    let vault_key = unlock_vault_if_needed(
        &resolved.repo_config,
        local_cfg.use_keyring,
        ctx.is_interactive,
        has_enc && ctx.is_interactive,
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

    plan(&sync_engine, group_filter, lock)
}

/// Evaluates 3-way hash reconciliation for a [`SyncEngine`].
pub fn plan(
    engine: &SyncEngine,
    group_filter: Option<&str>,
    _lock: &DotlerLockGuard,
) -> Result<Vec<FileActionPlan>, EngineError> {
    let mut plans = Vec::new();
    let home_dir = engine.effective_home_dir();

    for (group_name, group_cfg) in &engine.repo_config.groups {
        if let Some(filter) = group_filter
            && filter != group_name
        {
            continue;
        }

        let target_base_str =
            match resolve_group_target_path(group_cfg, &engine.devices, &engine.os_info) {
                Some(base) => base,
                None => continue,
            };
        let target_base_path = engine.expand_target_base(&target_base_str);
        let rules = parse_selection_rules(&group_cfg.files)?;

        // 1. Gather candidate relative paths
        let mut candidates = BTreeSet::new();

        let group_repo_dir = engine.repo_dir.join(group_name);
        validate_dir_no_symlinks(&group_repo_dir)?;
        if group_repo_dir.is_dir() {
            for entry in WalkDir::new(&group_repo_dir)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                if entry.file_type().is_file() {
                    let file_name = entry.file_name().to_string_lossy();
                    if file_name.starts_with(TMP_FILE_PREFIX) {
                        continue;
                    }
                    if let Ok(rel) = entry.path().strip_prefix(&group_repo_dir) {
                        let rel_str = rel.to_string_lossy().to_string();
                        let clean_rel = if let Some(stripped) = rel_str.strip_suffix(".enc") {
                            stripped.to_string()
                        } else {
                            rel_str
                        };
                        candidates.insert(clean_rel);
                    }
                }
            }
        }

        for rule in &rules {
            if !rule.pattern.contains('*')
                && !rule.pattern.contains('?')
                && !rule.pattern.contains('[')
            {
                candidates.insert(rule.pattern.clone());
            }
        }

        if let Ok(records) = engine.state_db.list_synced_files(Some(&engine.repo_label)) {
            for r in records {
                if r.group_name == *group_name {
                    candidates.insert(r.relative_path);
                }
            }
        }

        validate_os_dir_path(&target_base_path, &home_dir)?;
        if target_base_path.is_dir() {
            let dotler_config_dir = if let Some(ref home) = engine.home_dir {
                home.join(".config").join("dotler")
            } else {
                expand_tilde("~/.config/dotler")
            };

            for entry in WalkDir::new(&target_base_path)
                .filter_entry(|e| {
                    if e.depth() == 0 {
                        return true;
                    }
                    let p = e.path();
                    if p.starts_with(&dotler_config_dir) || p == dotler_config_dir {
                        return false;
                    }
                    if p.starts_with(&engine.repo_dir) || p == engine.repo_dir {
                        return false;
                    }
                    if e.file_name() == ".git" {
                        return false;
                    }
                    if let Ok(rel) = p.strip_prefix(&target_base_path) {
                        let rel_str = rel.to_string_lossy();
                        if rel_str == ".config/dotler" || rel_str.starts_with(".config/dotler/") {
                            return false;
                        }
                        if rel_str.split('/').any(|s| s == ".git") {
                            return false;
                        }
                    }
                    true
                })
                .filter_map(|e| e.ok())
            {
                if entry.file_type().is_file()
                    || (entry.file_type().is_symlink() && !entry.path().is_dir())
                {
                    let file_name = entry.file_name().to_string_lossy();
                    if file_name.starts_with(TMP_FILE_PREFIX) {
                        continue;
                    }
                    if let Ok(rel) = entry.path().strip_prefix(&target_base_path) {
                        let rel_str = rel.to_string_lossy().to_string();
                        if rel_str == ".config/dotler" || rel_str.starts_with(".config/dotler/") {
                            continue;
                        }
                        if rel_str.split('/').any(|s| s == ".git") {
                            continue;
                        }
                        if entry.path().starts_with(&engine.repo_dir) {
                            continue;
                        }
                        if evaluate_selection(&rules, &rel_str).is_some() {
                            candidates.insert(rel_str);
                        }
                    }
                }
            }
        }

        // 2. Evaluate each candidate
        for rel_path in candidates {
            if rel_path == ".config/dotler" || rel_path.starts_with(".config/dotler/") {
                continue;
            }
            if rel_path.split('/').any(|s| s == ".git") {
                continue;
            }
            let target_os_path = target_base_path.join(&rel_path);
            if target_os_path.starts_with(&engine.repo_dir) {
                continue;
            }
            let mode = evaluate_selection(&rules, &rel_path);

            let db_record = engine
                .state_db
                .get_synced_file(&target_os_path.to_string_lossy())?;
            let db_hash = db_record.as_ref().map(|r| r.file_hash.clone());

            if mode.is_none() || mode == Some(SelectionMode::Exclude) {
                if db_record.is_some() {
                    plans.push(FileActionPlan {
                        repo_label: engine.repo_label.clone(),
                        group_name: group_name.clone(),
                        relative_path: rel_path.clone(),
                        target_os_path: target_os_path.clone(),
                        repo_file_path: group_repo_dir.join(&rel_path),
                        status: FileSyncStatus::Orphaned,
                        is_encrypted: false,
                        os_hash: None,
                        repo_hash: None,
                        db_hash,
                    });
                }
                continue;
            }

            validate_os_target_path(&target_os_path, &home_dir)?;

            let is_encrypted = mode == Some(SelectionMode::EncryptedInclude);
            let plain_repo_path = group_repo_dir.join(&rel_path);
            let enc_repo_path = group_repo_dir.join(format!("{}.enc", rel_path));

            let os_bytes = fs::read(&target_os_path).ok();
            let os_hash = os_bytes
                .as_ref()
                .map(|b| blake3::hash(b).to_hex().to_string());

            let mut repo_hash = None;
            let mut encryption_mismatch = false;

            if is_encrypted {
                if plain_repo_path.is_file() && !enc_repo_path.is_file() {
                    encryption_mismatch = true;
                } else if enc_repo_path.is_file()
                    && let Ok(bytes) = fs::read(&enc_repo_path)
                    && let Ok(enc_file) = EncryptedFile::from_bytes(&bytes)
                    && let Some(key) = engine.vault_key
                    && let Ok(plain) = key.decrypt_file(&enc_file)
                {
                    repo_hash = Some(blake3::hash(plain.expose_secret()).to_hex().to_string());
                }
            } else if enc_repo_path.is_file() && !plain_repo_path.is_file() {
                encryption_mismatch = true;
            } else if plain_repo_path.is_file()
                && let Ok(bytes) = fs::read(&plain_repo_path)
            {
                repo_hash = Some(blake3::hash(&bytes).to_hex().to_string());
            }

            let chosen_repo_path = if is_encrypted {
                enc_repo_path
            } else {
                plain_repo_path
            };

            let status = if encryption_mismatch {
                FileSyncStatus::EncryptionMismatch
            } else {
                match (&os_hash, &repo_hash, &db_hash) {
                    (Some(os_h), Some(repo_h), _) if os_h == repo_h => FileSyncStatus::Synced,
                    (Some(os_h), Some(repo_h), Some(db_h)) => {
                        if os_h == db_h {
                            FileSyncStatus::ModifiedInRepo
                        } else if repo_h == db_h {
                            FileSyncStatus::ModifiedLocally
                        } else {
                            FileSyncStatus::Conflict
                        }
                    }
                    (Some(_), Some(_), None) => FileSyncStatus::Conflict,
                    (Some(_), None, Some(_)) => FileSyncStatus::MissingInRepo,
                    (Some(_), None, None) => FileSyncStatus::ModifiedLocally,
                    (None, Some(_), Some(_)) => FileSyncStatus::MissingLocally,
                    (None, Some(_), None) => FileSyncStatus::ModifiedInRepo,
                    (None, None, Some(_)) => FileSyncStatus::MissingLocally,
                    (None, None, None) => FileSyncStatus::MissingInRepo,
                }
            };

            plans.push(FileActionPlan {
                repo_label: engine.repo_label.clone(),
                group_name: group_name.clone(),
                relative_path: rel_path,
                target_os_path,
                repo_file_path: chosen_repo_path,
                status,
                is_encrypted,
                os_hash,
                repo_hash,
                db_hash,
            });
        }
    }

    plans.sort_by(|a, b| a.target_os_path.cmp(&b.target_os_path));
    Ok(plans)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::local::LocalConfig;
    use crate::config::repo::{OsInfo, RepoConfig};
    use crate::config::state::{DotlerLock, StateDb};
    use std::time::Duration;

    #[test]
    fn run_check_detects_cross_group_collision_and_enc_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let repo_dir = tmp.path().join("repo");
        fs::create_dir_all(repo_dir.join("g1")).unwrap();
        fs::create_dir_all(repo_dir.join("g2")).unwrap();

        // Cross-group collision on ~/.bashrc
        let collision_toml = r#"[g1]
os-nux = "~"
os-mac = "~"
files = ".bashrc"

[g2]
os-nux = "~"
os-mac = "~"
files = ".bashrc"
"#;
        fs::write(repo_dir.join("dotler.toml"), collision_toml).unwrap();

        let cfg_path = tmp.path().join("config.toml");
        let mut local_cfg = LocalConfig {
            default_repo: Some("main".to_string()),
            ..Default::default()
        };
        local_cfg
            .repos
            .insert("main".to_string(), repo_dir.to_string_lossy().to_string());

        let lock_path = tmp.path().join("dotler.lock");
        let lock = DotlerLock::new(lock_path.clone())
            .acquire(Duration::from_millis(500), Duration::from_millis(10))
            .unwrap();

        let mut ctx = CoreContext::with_paths(
            lock_path,
            cfg_path,
            tmp.path().join("state.db"),
            None,
            None,
            false,
        );
        ctx.local_config = crate::core::resource::Resource::from_value(local_cfg);

        let err = run_check(&ctx, None, &lock).unwrap_err();
        assert_eq!(err.error_code(), "CONFIG_ERROR");

        // Now test encryption mismatch (.enc file present for plaintext rule)
        let mismatch_toml = r#"[g1]
os-nux = "~"
os-mac = "~"
files = ".bashrc"
"#;
        fs::write(repo_dir.join("dotler.toml"), mismatch_toml).unwrap();
        fs::write(repo_dir.join("g1/.bashrc.enc"), b"cipher").unwrap();

        let err2 = run_check(&ctx, None, &lock).unwrap_err();
        assert_eq!(err2.error_code(), "ENCRYPTION_MISMATCH");
        assert_eq!(err2.exit_code(), 1);
    }

    #[test]
    fn plan_is_read_only_and_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let home_dir = tmp.path().join("home");
        let repo_dir = tmp.path().join("repo");
        fs::create_dir_all(&home_dir).unwrap();
        fs::create_dir_all(repo_dir.join("shell")).unwrap();

        fs::write(home_dir.join(".bashrc"), b"export A=1\n").unwrap();
        fs::write(repo_dir.join("shell/.bashrc"), b"export A=1\n").unwrap();

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

        let plans1 = plan(&engine, None, &lock).unwrap();
        let plans2 = plan(&engine, None, &lock).unwrap();
        assert_eq!(plans1, plans2);
        assert_eq!(plans1[0].status, FileSyncStatus::Synced);
        assert!(state_db.list_synced_files(None).unwrap().is_empty());
    }
}
