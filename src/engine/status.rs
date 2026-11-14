//! 3-way synchronization status reconciliation across OS files, repository files, and `state.db`.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::local::{WalkDir, expand_tilde};
use crate::config::repo::{
    GroupConfig, SelectionMode, SelectionRule, evaluate_selection, parse_selection_rules,
    render_home_template, resolve_group_target_path, unrender_home_template,
    validate_dir_no_symlinks, validate_os_dir_path, validate_os_target_path,
};
use crate::config::state::{DotlerLockGuard, TMP_FILE_PREFIX};
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
    #[serde(default)]
    pub is_template: bool,
    pub os_hash: Option<String>,
    pub repo_hash: Option<String>,
    pub db_hash: Option<String>,
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
    if let Some(filter) = group_filter
        && !engine.repo_config.groups.contains_key(filter)
    {
        return Err(EngineError::GroupNotFound {
            group: filter.to_string(),
            available: engine.repo_config.groups.keys().cloned().collect(),
        });
    }

    let mut plans = Vec::new();
    let home_dir = engine.effective_home_dir();

    for (group_name, group_cfg) in &engine.repo_config.groups {
        if let Some(filter) = group_filter
            && filter != group_name
        {
            continue;
        }
        plan_group(engine, group_name, group_cfg, &home_dir, &mut plans)?;
    }

    plans.sort_by(|a, b| a.target_os_path.cmp(&b.target_os_path));
    Ok(plans)
}

fn plan_group(
    engine: &SyncEngine,
    group_name: &str,
    group_cfg: &GroupConfig,
    home_dir: &Path,
    plans: &mut Vec<FileActionPlan>,
) -> Result<(), EngineError> {
    let target_base_str =
        match resolve_group_target_path(group_cfg, &engine.devices, &engine.os_info) {
            Some(base) => base,
            None => return Ok(()),
        };
    let target_base_path = engine.expand_target_base(&target_base_str);
    let rules = parse_selection_rules(&group_cfg.files)?;

    let group_repo_dir = engine.repo_dir.join(group_name);
    let mut candidates = BTreeSet::new();
    collect_repo_and_db_candidates(engine, group_name, &group_repo_dir, &mut candidates)?;
    collect_os_candidates(engine, &target_base_path, home_dir, &rules, &mut candidates)?;
    collect_single_file_rule_candidates(
        &target_base_path,
        &group_repo_dir,
        &rules,
        &mut candidates,
    );

    for rel_path in candidates {
        if is_reserved_dotler_or_git(&rel_path) {
            continue;
        }
        let target_os_path = target_base_path.join(&rel_path);
        if target_os_path.starts_with(&engine.repo_dir) {
            continue;
        }
        if let Some(entry) = build_file_plan(
            engine,
            group_name,
            &group_repo_dir,
            home_dir,
            &rules,
            rel_path,
            target_os_path,
        )? {
            plans.push(entry);
        }
    }

    Ok(())
}

fn collect_repo_and_db_candidates(
    engine: &SyncEngine,
    group_name: &str,
    group_repo_dir: &Path,
    candidates: &mut BTreeSet<String>,
) -> Result<(), EngineError> {
    validate_dir_no_symlinks(group_repo_dir)?;
    if group_repo_dir.is_dir() {
        for entry in WalkDir::new(group_repo_dir)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if !entry.file_type().is_file()
                || entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(TMP_FILE_PREFIX)
            {
                continue;
            }
            if let Ok(rel) = entry.path().strip_prefix(group_repo_dir) {
                let rel_str = rel.to_string_lossy().to_string();
                let clean = rel_str
                    .strip_suffix(".enc")
                    .map(str::to_string)
                    .unwrap_or(rel_str);
                candidates.insert(clean);
            }
        }
    }

    if let Ok(records) = engine.state_db.list_synced_files(Some(&engine.repo_label)) {
        for r in records.into_iter().filter(|r| r.group_name == group_name) {
            candidates.insert(r.relative_path);
        }
    }

    Ok(())
}

fn collect_os_candidates(
    engine: &SyncEngine,
    target_base_path: &Path,
    home_dir: &Path,
    rules: &[SelectionRule],
    candidates: &mut BTreeSet<String>,
) -> Result<(), EngineError> {
    validate_os_dir_path(target_base_path, home_dir)?;
    if !target_base_path.is_dir() {
        return Ok(());
    }

    let dotler_config_dir = engine
        .home_dir
        .as_ref()
        .map(|h| h.join(".config").join("dotler"))
        .unwrap_or_else(|| expand_tilde("~/.config/dotler"));

    for entry in WalkDir::new(target_base_path)
        .filter_entry(|e| {
            if e.depth() == 0 {
                return true;
            }
            let p = e.path();
            if p.starts_with(&dotler_config_dir)
                || p == dotler_config_dir
                || p.starts_with(&engine.repo_dir)
                || p == engine.repo_dir
                || e.file_name() == ".git"
            {
                return false;
            }
            !p.strip_prefix(target_base_path)
                .is_ok_and(|rel| is_reserved_dotler_or_git(&rel.to_string_lossy()))
        })
        .filter_map(|e| e.ok())
    {
        let ft = entry.file_type();
        if !(ft.is_file() || (ft.is_symlink() && !entry.path().is_dir()))
            || entry
                .file_name()
                .to_string_lossy()
                .starts_with(TMP_FILE_PREFIX)
        {
            continue;
        }
        if let Ok(rel) = entry.path().strip_prefix(target_base_path) {
            let rel_str = rel.to_string_lossy().to_string();
            if !is_reserved_dotler_or_git(&rel_str)
                && !entry.path().starts_with(&engine.repo_dir)
                && evaluate_selection(rules, &rel_str).is_some()
            {
                candidates.insert(rel_str);
            }
        }
    }

    Ok(())
}

fn collect_single_file_rule_candidates(
    target_base_path: &Path,
    group_repo_dir: &Path,
    rules: &[SelectionRule],
    candidates: &mut BTreeSet<String>,
) {
    for rule in rules {
        if rule.mode == SelectionMode::Exclude || rule.pattern.ends_with('/') {
            continue;
        }
        let trimmed = rule.pattern.trim_start_matches("./").trim_end_matches('/');
        if trimmed.is_empty()
            || trimmed.contains('*')
            || trimmed.contains('?')
            || trimmed.contains('[')
        {
            continue;
        }
        let dir_prefix = format!("{trimmed}/");
        if target_base_path.join(trimmed).is_dir()
            || group_repo_dir.join(trimmed).is_dir()
            || candidates.iter().any(|c| c.starts_with(&dir_prefix))
            || rules
                .iter()
                .any(|r| r.pattern.trim_start_matches("./").starts_with(&dir_prefix))
        {
            continue;
        }
        candidates.insert(trimmed.to_string());
    }
}

fn build_file_plan(
    engine: &SyncEngine,
    group_name: &str,
    group_repo_dir: &Path,
    home_dir: &Path,
    rules: &[SelectionRule],
    rel_path: String,
    target_os_path: PathBuf,
) -> Result<Option<FileActionPlan>, EngineError> {
    let mode = evaluate_selection(rules, &rel_path);
    let db_record = engine
        .state_db
        .get_synced_file(&target_os_path.to_string_lossy())?;
    let db_hash = db_record.as_ref().map(|r| r.file_hash.clone());

    if mode.is_none() || mode == Some(SelectionMode::Exclude) {
        return Ok(db_record.map(|_| FileActionPlan {
            repo_label: engine.repo_label.clone(),
            group_name: group_name.to_string(),
            repo_file_path: group_repo_dir.join(&rel_path),
            relative_path: rel_path,
            target_os_path,
            status: FileSyncStatus::Orphaned,
            is_encrypted: false,
            is_template: false,
            os_hash: None,
            repo_hash: None,
            db_hash,
        }));
    }

    validate_os_target_path(&target_os_path, home_dir)?;
    let is_encrypted = mode.is_some_and(|m| m.is_encrypted());
    let is_template = mode.is_some_and(|m| m.is_template());
    let plain_repo_path = group_repo_dir.join(&rel_path);
    let enc_repo_path = group_repo_dir.join(format!("{rel_path}.enc"));

    let os_bytes = fs::read(&target_os_path).ok();
    if is_template && let Some(ref bytes) = os_bytes {
        unrender_home_template(bytes, home_dir, &rel_path)?;
    }
    let os_hash = os_bytes
        .as_ref()
        .map(|b| blake3::hash(b).to_hex().to_string());

    let (repo_hash, encryption_mismatch) = compute_repo_hash_and_mismatch(
        engine,
        home_dir,
        &rel_path,
        is_encrypted,
        is_template,
        &plain_repo_path,
        &enc_repo_path,
    )?;

    let chosen_repo_path = if is_encrypted {
        enc_repo_path
    } else {
        plain_repo_path
    };
    let status = classify_sync_status(&os_hash, &repo_hash, &db_hash, encryption_mismatch);

    Ok(Some(FileActionPlan {
        repo_label: engine.repo_label.clone(),
        group_name: group_name.to_string(),
        relative_path: rel_path,
        target_os_path,
        repo_file_path: chosen_repo_path,
        status,
        is_encrypted,
        is_template,
        os_hash,
        repo_hash,
        db_hash,
    }))
}

#[allow(clippy::too_many_arguments)]
fn compute_repo_hash_and_mismatch(
    engine: &SyncEngine,
    home_dir: &Path,
    rel_path: &str,
    is_encrypted: bool,
    is_template: bool,
    plain_repo_path: &Path,
    enc_repo_path: &Path,
) -> Result<(Option<String>, bool), EngineError> {
    if is_encrypted {
        if plain_repo_path.is_file() && !enc_repo_path.is_file() {
            return Ok((None, true));
        }
        if enc_repo_path.is_file()
            && let Ok(bytes) = fs::read(enc_repo_path)
            && let Ok(enc_file) = EncryptedFile::from_bytes(&bytes)
            && let Some(key) = engine.vault_key
            && let Ok(plain) = key.decrypt_file(&enc_file)
        {
            return Ok((
                Some(hash_maybe_template(
                    plain.expose_secret(),
                    is_template,
                    home_dir,
                    rel_path,
                )?),
                false,
            ));
        }
        return Ok((None, false));
    }

    if enc_repo_path.is_file() && !plain_repo_path.is_file() {
        return Ok((None, true));
    }
    if plain_repo_path.is_file()
        && let Ok(bytes) = fs::read(plain_repo_path)
    {
        return Ok((
            Some(hash_maybe_template(
                &bytes,
                is_template,
                home_dir,
                rel_path,
            )?),
            false,
        ));
    }
    Ok((None, false))
}

fn hash_maybe_template(
    bytes: &[u8],
    is_template: bool,
    home_dir: &Path,
    rel_path: &str,
) -> Result<String, EngineError> {
    let rendered = if is_template {
        render_home_template(bytes, home_dir, rel_path)?
    } else {
        bytes.to_vec()
    };
    Ok(blake3::hash(&rendered).to_hex().to_string())
}

fn classify_sync_status(
    os_hash: &Option<String>,
    repo_hash: &Option<String>,
    db_hash: &Option<String>,
    encryption_mismatch: bool,
) -> FileSyncStatus {
    if encryption_mismatch {
        return FileSyncStatus::EncryptionMismatch;
    }
    match (os_hash, repo_hash, db_hash) {
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
        (Some(_), None, Some(_)) | (None, None, None) => FileSyncStatus::MissingInRepo,
        (Some(_), None, None) => FileSyncStatus::ModifiedLocally,
        (None, Some(_), Some(_)) | (None, None, Some(_)) => FileSyncStatus::MissingLocally,
        (None, Some(_), None) => FileSyncStatus::ModifiedInRepo,
    }
}

fn is_reserved_dotler_or_git(rel: &str) -> bool {
    rel == ".config/dotler"
        || rel.starts_with(".config/dotler/")
        || rel.split('/').any(|s| s == ".git")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::repo::{OsInfo, RepoConfig};
    use crate::config::state::{DotlerLock, StateDb};
    use std::time::Duration;

    struct PlanEnv {
        _tmp: tempfile::TempDir,
        home_dir: PathBuf,
        repo_dir: PathBuf,
        state_db: StateDb,
        lock: DotlerLockGuard,
    }

    impl PlanEnv {
        fn new() -> Self {
            let tmp = tempfile::tempdir().unwrap();
            let home_dir = tmp.path().join("home");
            let repo_dir = tmp.path().join("repo");
            fs::create_dir_all(&home_dir).unwrap();
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

        fn run_plan(&self, toml: &str) -> Vec<FileActionPlan> {
            let repo_cfg = RepoConfig::parse(toml).unwrap();
            let engine = SyncEngine::new(
                "main",
                &self.repo_dir,
                &repo_cfg,
                &self.state_db,
                vec![],
                OsInfo::detect(),
                None,
            )
            .with_home_dir(&self.home_dir);
            plan(&engine, None, &self.lock).unwrap()
        }
    }

    #[test]
    fn plan_is_read_only_and_idempotent() {
        let env = PlanEnv::new();
        fs::create_dir_all(env.repo_dir.join("shell")).unwrap();
        fs::write(env.home_dir.join(".bashrc"), b"export A=1\n").unwrap();
        fs::write(env.repo_dir.join("shell/.bashrc"), b"export A=1\n").unwrap();

        let toml = "[shell]\nos-nux = \"~\"\nos-mac = \"~\"\nfiles = \".bashrc\"\n";
        let plans1 = env.run_plan(toml);
        let plans2 = env.run_plan(toml);
        assert_eq!(plans1, plans2);
        assert_eq!(plans1[0].status, FileSyncStatus::Synced);
        assert!(env.state_db.list_synced_files(None).unwrap().is_empty());
    }

    #[test]
    fn plan_handles_directory_include_and_exclude_rules_without_wildcard_suffix() {
        let env = PlanEnv::new();
        let nvim_os = env.home_dir.join(".config").join("nvim");
        fs::create_dir_all(nvim_os.join("lua").join("plugins")).unwrap();
        fs::create_dir_all(nvim_os.join("cache").join("sub")).unwrap();
        fs::create_dir_all(nvim_os.join("tmp_dir")).unwrap();
        fs::create_dir_all(env.repo_dir.join("nvim")).unwrap();

        fs::write(nvim_os.join("init.lua"), b"-- root\n").unwrap();
        fs::write(nvim_os.join("lua/core.lua"), b"-- core\n").unwrap();
        fs::write(nvim_os.join("lua/plugins/lsp.lua"), b"-- lsp\n").unwrap();
        fs::write(nvim_os.join("cache/a.txt"), b"cached a\n").unwrap();
        fs::write(nvim_os.join("cache/sub/b.txt"), b"cached b\n").unwrap();
        fs::write(nvim_os.join("tmp_dir/c.txt"), b"temp c\n").unwrap();

        let toml_exclude = "[nvim]\nos-nux = \"~/.config/nvim\"\nos-mac = \"~/.config/nvim\"\nfiles = \"\"\"\n*\n!cache\n!tmp_dir/\n\"\"\"\n";
        let plans1 = env.run_plan(toml_exclude);
        let rel1: Vec<&str> = plans1.iter().map(|p| p.relative_path.as_str()).collect();
        assert_eq!(
            rel1,
            vec!["init.lua", "lua/core.lua", "lua/plugins/lsp.lua"]
        );

        let toml_include_dir = "[nvim]\nos-nux = \"~/.config/nvim\"\nos-mac = \"~/.config/nvim\"\nfiles = \"\"\"\nlua\n!lua/plugins\n\"\"\"\n";
        let plans2 = env.run_plan(toml_include_dir);
        let rel2: Vec<&str> = plans2.iter().map(|p| p.relative_path.as_str()).collect();
        assert_eq!(rel2, vec!["lua/core.lua"]);

        let toml_nested = "[nvim]\nos-nux = \"~/.config/nvim\"\nos-mac = \"~/.config/nvim\"\nfiles = \"\"\"\n*\n!cache\ncache/keep.txt\n!cache/sub\n!tmp_dir/\n!lua\n\"\"\"\n";
        let plans3 = env.run_plan(toml_nested);
        let rel3: Vec<(&str, FileSyncStatus)> = plans3
            .iter()
            .map(|p| (p.relative_path.as_str(), p.status))
            .collect();
        assert_eq!(
            rel3,
            vec![
                ("cache/keep.txt", FileSyncStatus::MissingInRepo),
                ("init.lua", FileSyncStatus::ModifiedLocally),
            ]
        );

        let toml_nonexistent = "[nvim]\nos-nux = \"~/.config/nvim\"\nos-mac = \"~/.config/nvim\"\nfiles = \"\"\"\nnonexistent_dir\n!nonexistent_dir/sub\n\"\"\"\n";
        let plans4 = env.run_plan(toml_nonexistent);
        assert!(
            plans4.is_empty(),
            "non-existent directory with sub-rule must not be planned as a single file: {plans4:?}"
        );
    }
}
