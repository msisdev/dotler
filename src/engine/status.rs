//! 3-way synchronization status reconciliation across OS files, repository files, and `state.db`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::local::{WalkDir, expand_tilde};
use crate::config::path_security::resolve_with_existing_ancestors;
use crate::config::repo::{
    GroupConfig, SelectionMode, SelectionRule, evaluate_selection, group_matches_filter,
    group_repo_dir, is_cwd_group_path, is_delegated_to_subgroup, parse_selection_rules,
    render_home_template, split_group_root_and_subpath, unrender_home_template,
    validate_dir_no_symlinks, validate_os_dir_path_with_home, validate_os_target_path_with_home,
    validate_repo_target_disjointness, validate_rule_pattern,
};
use crate::config::state::{DotlerLockGuard, TMP_FILE_PREFIX};
use crate::core::context::CoreContext;
use crate::core::vault_loader::{
    has_encrypted_repo_files, has_encrypted_rules, unlock_vault_if_needed,
};
use crate::crypto::ExposeSecret;
use crate::crypto::vault::{
    CONTENT_ENC_SUFFIX, EncryptedFile, FULL_ENC_SUFFIX, FullEncryptedFile,
    LEGACY_CONTENT_ENC_SUFFIX, is_full_enc_name, is_legacy_dotler_archive_bytes,
    parse_legacy_fenc_filename_stem, strip_content_enc_suffix,
};
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
    pub is_full_encrypted: bool,
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

    plan(&sync_engine, group_filter, lock)
}

/// Evaluates 3-way hash reconciliation for a [`SyncEngine`].
pub fn plan(
    engine: &SyncEngine,
    group_filter: Option<&str>,
    _lock: &DotlerLockGuard,
) -> Result<Vec<FileActionPlan>, EngineError> {
    if let Some(filter) = group_filter
        && !engine
            .repo_config
            .groups
            .keys()
            .any(|g| group_matches_filter(g, filter))
    {
        return Err(EngineError::GroupNotFound {
            group: filter.to_string(),
            available: engine.repo_config.groups.keys().cloned().collect(),
        });
    }

    let misplaced_targets = collect_misplaced_ancestor_targets(engine)?;
    let mut plans = Vec::new();
    let home_dir = engine.effective_home_dir();

    for (group_name, group_cfg) in &engine.repo_config.groups {
        if let Some(filter) = group_filter
            && !group_matches_filter(group_name, filter)
        {
            continue;
        }
        plan_group(
            engine,
            group_name,
            group_cfg,
            &home_dir,
            &misplaced_targets,
            &mut plans,
        )?;
    }

    let mut seen_targets: BTreeMap<PathBuf, &str> = BTreeMap::new();
    for p in &plans {
        let resolved_target = resolve_with_existing_ancestors(&p.target_os_path);
        if let Some(prev_group) = seen_targets.insert(resolved_target, p.group_name.as_str())
            && prev_group != p.group_name
        {
            return Err(EngineError::Config(
                crate::config::ConfigError::CrossGroupFileCollision {
                    path: p.target_os_path.display().to_string(),
                    group1: prev_group.to_string(),
                    group2: p.group_name.clone(),
                },
            ));
        }
    }

    plans.sort_by(|a, b| a.target_os_path.cmp(&b.target_os_path));
    Ok(plans)
}

fn collect_misplaced_ancestor_targets(
    engine: &SyncEngine,
) -> Result<BTreeSet<PathBuf>, EngineError> {
    let mut misplaced = BTreeSet::new();
    let Some(key) = engine.vault_key else {
        return Ok(misplaced);
    };
    let expected_vid = engine
        .repo_config
        .vault
        .as_ref()
        .map(|v| v.vault_id.as_str());

    for group_name in engine.repo_config.groups.keys() {
        let delegated_subpaths = engine.repo_config.descendant_subpaths(group_name);
        if delegated_subpaths.is_empty() {
            continue;
        }
        let Some(base_str) =
            engine
                .repo_config
                .resolve_target_path(group_name, &engine.devices, &engine.os_info)
        else {
            continue;
        };
        let (target_base_path, _) = engine.expand_target_base_checked(&base_str)?;
        let g_repo_dir = group_repo_dir(&engine.repo_dir, group_name);
        if !g_repo_dir.is_dir() {
            continue;
        }
        for entry in WalkDir::new(&g_repo_dir)
            .filter_entry(|e| {
                if e.depth() == 0 {
                    return true;
                }
                !e.path().strip_prefix(&g_repo_dir).is_ok_and(|rel| {
                    is_delegated_to_subgroup(&rel.to_string_lossy(), &delegated_subpaths)
                })
            })
            .filter_map(|e| e.ok())
        {
            if !entry.file_type().is_file() {
                continue;
            }
            let fname = entry.file_name().to_string_lossy().to_string();
            let is_fenc = is_full_enc_name(&fname)
                || (parse_legacy_fenc_filename_stem(&fname).is_some()
                    && fs::read(entry.path())
                        .map(|b| is_legacy_dotler_archive_bytes(&b, expected_vid))
                        .unwrap_or(false));
            if !is_fenc {
                continue;
            }
            if let Ok(bytes) = fs::read(entry.path())
                && let Ok(fenc) = FullEncryptedFile::from_bytes(&bytes)
                && let Ok((dec_rel, _)) = key.decrypt_full_file(&fname, &fenc)
            {
                validate_rule_pattern(&dec_rel)?;
                if is_delegated_to_subgroup(&dec_rel, &delegated_subpaths) {
                    misplaced.insert(target_base_path.join(dec_rel));
                }
            }
        }
    }
    Ok(misplaced)
}

fn plan_group(
    engine: &SyncEngine,
    group_name: &str,
    group_cfg: &GroupConfig,
    home_dir: &Path,
    misplaced_ancestor_targets: &BTreeSet<PathBuf>,
    plans: &mut Vec<FileActionPlan>,
) -> Result<(), EngineError> {
    let target_base_str =
        match engine
            .repo_config
            .resolve_target_path(group_name, &engine.devices, &engine.os_info)
        {
            Some(base) => base,
            None => return Ok(()),
        };
    let (target_base_path, boundary_dir) = engine.expand_target_base_checked(&target_base_str)?;
    validate_repo_target_disjointness(
        &engine.repo_dir,
        engine.repo_config.groups.keys().map(String::as_str),
        &target_base_path,
    )?;
    let is_cwd_group = is_cwd_group_path(&target_base_str);
    let canon_repo = resolve_with_existing_ancestors(&engine.repo_dir);
    let canon_target_base = resolve_with_existing_ancestors(&target_base_path);
    let in_project_repo = canon_target_base.starts_with(&canon_repo);
    let rules = parse_selection_rules(&group_cfg.files)?;
    let delegated_subpaths = engine.repo_config.descendant_subpaths(group_name);

    let group_repo_dir = group_repo_dir(&engine.repo_dir, group_name);
    let mut candidates = BTreeSet::new();
    let mut misplaced_rels = BTreeSet::new();
    let cwd_scope = if is_cwd_group {
        Some((target_base_path.as_path(), canon_target_base.as_path()))
    } else {
        None
    };
    collect_repo_and_db_candidates(
        engine,
        group_name,
        &group_repo_dir,
        &delegated_subpaths,
        cwd_scope,
        &mut candidates,
        &mut misplaced_rels,
    )?;
    for misplaced_target in misplaced_ancestor_targets {
        if let Ok(rel) = misplaced_target.strip_prefix(&target_base_path) {
            let rel_str = rel.to_string_lossy().to_string();
            if !rel_str.is_empty() && !is_delegated_to_subgroup(&rel_str, &delegated_subpaths) {
                candidates.insert(rel_str.clone());
                misplaced_rels.insert(rel_str);
            }
        }
    }
    collect_os_candidates(
        engine,
        &target_base_path,
        &boundary_dir,
        home_dir,
        in_project_repo,
        &delegated_subpaths,
        &rules,
        &mut candidates,
    )?;
    collect_single_file_rule_candidates(
        &target_base_path,
        &group_repo_dir,
        &delegated_subpaths,
        &rules,
        &mut candidates,
    );

    for rel_path in candidates {
        if is_reserved_dotler_or_git(&rel_path)
            || is_delegated_to_subgroup(&rel_path, &delegated_subpaths)
        {
            continue;
        }
        let target_os_path = target_base_path.join(&rel_path);
        if in_project_repo {
            validate_repo_target_disjointness(
                &engine.repo_dir,
                engine.repo_config.groups.keys().map(String::as_str),
                &target_os_path,
            )?;
        } else if target_os_path.starts_with(&engine.repo_dir) {
            continue;
        }
        let has_misplaced = misplaced_rels.contains(&rel_path);
        if let Some(entry) = build_file_plan(
            engine,
            group_name,
            &group_repo_dir,
            &boundary_dir,
            home_dir,
            &rules,
            rel_path,
            target_os_path,
            has_misplaced,
        )? {
            plans.push(entry);
        }
    }

    Ok(())
}

fn combine_nested_fenc_rel(repo_rel: &Path, dec_rel: String) -> (String, bool) {
    match repo_rel.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => {
            let parent_str = parent.to_string_lossy();
            (format!("{parent_str}/{dec_rel}"), true)
        }
        _ => (dec_rel, false),
    }
}

fn collect_repo_and_db_candidates(
    engine: &SyncEngine,
    group_name: &str,
    group_repo_dir: &Path,
    delegated_subpaths: &[String],
    cwd_scope: Option<(&Path, &Path)>,
    candidates: &mut BTreeSet<String>,
    misplaced_rels: &mut BTreeSet<String>,
) -> Result<(), EngineError> {
    validate_dir_no_symlinks(group_repo_dir)?;
    if group_repo_dir.is_dir() {
        for entry in WalkDir::new(group_repo_dir)
            .filter_entry(|e| {
                if e.depth() == 0 {
                    return true;
                }
                !e.path().strip_prefix(group_repo_dir).is_ok_and(|rel| {
                    is_delegated_to_subgroup(&rel.to_string_lossy(), delegated_subpaths)
                })
            })
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
                let fname = entry.file_name().to_string_lossy().to_string();
                if is_full_enc_name(&rel_str) {
                    if let Some(key) = engine.vault_key
                        && let Ok(bytes) = fs::read(entry.path())
                        && let Ok(fenc) = FullEncryptedFile::from_bytes(&bytes)
                        && let Ok((dec_rel, _)) = key.decrypt_full_file(&fname, &fenc)
                    {
                        validate_rule_pattern(&dec_rel)?;
                        let (eff_rel, is_nested_fenc) = combine_nested_fenc_rel(rel, dec_rel);
                        if !is_delegated_to_subgroup(&eff_rel, delegated_subpaths) {
                            if is_nested_fenc {
                                misplaced_rels.insert(eff_rel.clone());
                            }
                            candidates.insert(eff_rel);
                        }
                    }
                    continue;
                }
                if let Some(stripped) = strip_content_enc_suffix(&rel_str) {
                    if !is_delegated_to_subgroup(stripped, delegated_subpaths) {
                        candidates.insert(stripped.to_string());
                    }
                    continue;
                }
                let expected_vid = engine
                    .repo_config
                    .vault
                    .as_ref()
                    .map(|v| v.vault_id.as_str());
                if parse_legacy_fenc_filename_stem(&fname).is_some()
                    && let Ok(bytes) = fs::read(entry.path())
                    && is_legacy_dotler_archive_bytes(&bytes, expected_vid)
                {
                    if let Some(key) = engine.vault_key
                        && let Ok(fenc) = FullEncryptedFile::from_bytes(&bytes)
                        && let Ok((dec_rel, _)) = key.decrypt_full_file(&fname, &fenc)
                    {
                        validate_rule_pattern(&dec_rel)?;
                        let (eff_rel, is_nested_fenc) = combine_nested_fenc_rel(rel, dec_rel);
                        if !is_delegated_to_subgroup(&eff_rel, delegated_subpaths) {
                            if is_nested_fenc {
                                misplaced_rels.insert(eff_rel.clone());
                            }
                            candidates.insert(eff_rel);
                        }
                    }
                    continue;
                }
                if let Some(stripped) = rel_str.strip_suffix(LEGACY_CONTENT_ENC_SUFFIX)
                    && let Ok(bytes) = fs::read(entry.path())
                    && is_legacy_dotler_archive_bytes(&bytes, expected_vid)
                {
                    if !is_delegated_to_subgroup(stripped, delegated_subpaths) {
                        candidates.insert(stripped.to_string());
                    }
                    continue;
                }
                if !is_delegated_to_subgroup(&rel_str, delegated_subpaths) {
                    candidates.insert(rel_str);
                }
            }
        }
    }

    if let Ok(records) = engine.state_db.list_synced_files(Some(&engine.repo_label)) {
        for r in records {
            if let Some((base_lex, base_canon)) = cwd_scope {
                let rec_path = Path::new(&r.target_path);
                if !rec_path.starts_with(base_lex)
                    && !resolve_with_existing_ancestors(rec_path).starts_with(base_canon)
                {
                    continue;
                }
            }
            let (mapped_group, mapped_rel) =
                if engine.repo_config.groups.contains_key(&r.group_name) {
                    engine
                        .repo_config
                        .resolve_owning_group(&r.group_name, &r.relative_path)
                } else {
                    let (rec_root, rec_sub_opt) = split_group_root_and_subpath(&r.group_name);
                    if let Some(rec_sub) = rec_sub_opt
                        && engine.repo_config.groups.contains_key(rec_root)
                    {
                        let combined = format!("{rec_sub}/{}", r.relative_path);
                        engine.repo_config.resolve_owning_group(rec_root, &combined)
                    } else {
                        continue;
                    }
                };
            if mapped_group == group_name
                && !is_delegated_to_subgroup(&mapped_rel, delegated_subpaths)
            {
                candidates.insert(mapped_rel);
            }
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn collect_os_candidates(
    engine: &SyncEngine,
    target_base_path: &Path,
    boundary_dir: &Path,
    home_dir: &Path,
    in_project_repo: bool,
    delegated_subpaths: &[String],
    rules: &[SelectionRule],
    candidates: &mut BTreeSet<String>,
) -> Result<(), EngineError> {
    validate_os_dir_path_with_home(target_base_path, boundary_dir, home_dir)?;
    if !target_base_path.is_dir() {
        return Ok(());
    }

    let dotler_config_dir = engine
        .home_dir
        .as_ref()
        .map(|h| h.join(".config").join("dotler"))
        .unwrap_or_else(|| expand_tilde("~/.config/dotler"));
    let manifest_path = engine.repo_dir.join("dotler.toml");
    let canon_manifest = resolve_with_existing_ancestors(&manifest_path);
    let group_storage_dirs: Vec<(PathBuf, PathBuf)> = if in_project_repo {
        engine
            .repo_config
            .groups
            .keys()
            .map(|g| {
                let p = group_repo_dir(&engine.repo_dir, g);
                let c = resolve_with_existing_ancestors(&p);
                (p, c)
            })
            .collect()
    } else {
        Vec::new()
    };

    let is_repo_internal = |p: &Path| -> bool {
        if in_project_repo {
            let rp = resolve_with_existing_ancestors(p);
            p == manifest_path
                || rp == canon_manifest
                || group_storage_dirs
                    .iter()
                    .any(|(gp, gc)| p == gp || p.starts_with(gp) || rp == *gc || rp.starts_with(gc))
        } else {
            p == engine.repo_dir || p.starts_with(&engine.repo_dir)
        }
    };

    for entry in WalkDir::new(target_base_path)
        .filter_entry(|e| {
            if e.depth() == 0 {
                return true;
            }
            let p = e.path();
            if p.starts_with(&dotler_config_dir)
                || p == dotler_config_dir
                || is_repo_internal(p)
                || e.file_name() == ".git"
            {
                return false;
            }
            !p.strip_prefix(target_base_path).is_ok_and(|rel| {
                let rel_s = rel.to_string_lossy();
                is_reserved_dotler_or_git(&rel_s)
                    || is_delegated_to_subgroup(&rel_s, delegated_subpaths)
            })
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
                && !is_delegated_to_subgroup(&rel_str, delegated_subpaths)
                && !is_repo_internal(entry.path())
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
    delegated_subpaths: &[String],
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
            || is_delegated_to_subgroup(trimmed, delegated_subpaths)
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

#[allow(clippy::too_many_arguments)]
fn build_file_plan(
    engine: &SyncEngine,
    group_name: &str,
    group_repo_dir: &Path,
    boundary_dir: &Path,
    home_dir: &Path,
    rules: &[SelectionRule],
    rel_path: String,
    target_os_path: PathBuf,
    has_misplaced_archive: bool,
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
            is_full_encrypted: false,
            is_template: false,
            os_hash: None,
            repo_hash: None,
            db_hash,
        }));
    }

    let mode_val = mode.unwrap();
    validate_os_target_path_with_home(&target_os_path, boundary_dir, home_dir)?;
    let is_encrypted = mode_val.is_encrypted();
    let is_full_encrypted = mode_val.is_full_encrypted();
    let is_template = mode_val.is_template();
    let plain_repo_path = group_repo_dir.join(&rel_path);
    let enc_repo_path = group_repo_dir.join(format!("{rel_path}{CONTENT_ENC_SUFFIX}"));
    let full_enc_repo_path = engine
        .vault_key
        .map(|k| group_repo_dir.join(k.derive_full_enc_filename(&rel_path)));
    let legacy_enc_exists = {
        let p = group_repo_dir.join(format!("{rel_path}{LEGACY_CONTENT_ENC_SUFFIX}"));
        let expected_vid = engine
            .repo_config
            .vault
            .as_ref()
            .map(|v| v.vault_id.as_str());
        p.is_file()
            && fs::read(&p)
                .map(|b| is_legacy_dotler_archive_bytes(&b, expected_vid))
                .unwrap_or(false)
    };
    let legacy_fenc_exists = engine.vault_key.is_some_and(|k| {
        let p = group_repo_dir.join(format!(
            "{}{}",
            k.derive_full_enc_token(&rel_path),
            crate::crypto::LEGACY_FULL_ENC_SUFFIX
        ));
        let expected_vid = engine
            .repo_config
            .vault
            .as_ref()
            .map(|v| v.vault_id.as_str());
        p.is_file()
            && fs::read(&p)
                .map(|b| is_legacy_dotler_archive_bytes(&b, expected_vid))
                .unwrap_or(false)
    });

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
        mode_val,
        is_template,
        &plain_repo_path,
        &enc_repo_path,
        full_enc_repo_path.as_deref(),
        legacy_enc_exists || legacy_fenc_exists || has_misplaced_archive,
    )?;

    let chosen_repo_path = if is_full_encrypted {
        full_enc_repo_path
            .unwrap_or_else(|| group_repo_dir.join(format!("<locked>{FULL_ENC_SUFFIX}")))
    } else if is_encrypted {
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
        is_full_encrypted,
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
    mode: SelectionMode,
    is_template: bool,
    plain_repo_path: &Path,
    enc_repo_path: &Path,
    full_enc_repo_path: Option<&Path>,
    has_legacy_archive: bool,
) -> Result<(Option<String>, bool), EngineError> {
    let fenc_exists = full_enc_repo_path.is_some_and(Path::is_file);
    if has_legacy_archive && !plain_repo_path.is_file() && !enc_repo_path.is_file() && !fenc_exists
    {
        return Ok((None, true));
    }

    if mode.is_full_encrypted() {
        if (plain_repo_path.is_file() || enc_repo_path.is_file()) && !fenc_exists {
            return Ok((None, true));
        }
        if let (Some(key), Some(fenc_path)) = (engine.vault_key, full_enc_repo_path)
            && fenc_path.is_file()
            && let Some(fname) = fenc_path.file_name().and_then(|s| s.to_str())
            && let Ok(bytes) = fs::read(fenc_path)
            && let Ok(fenc_file) = FullEncryptedFile::from_bytes(&bytes)
            && let Ok((dec_rel, plain)) = key.decrypt_full_file(fname, &fenc_file)
            && dec_rel == rel_path
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

    if mode.is_content_encrypted() {
        if (plain_repo_path.is_file() || fenc_exists) && !enc_repo_path.is_file() {
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

    if (enc_repo_path.is_file() || fenc_exists) && !plain_repo_path.is_file() {
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

    #[test]
    fn plan_in_project_cwd_skips_manifest_and_group_storage_and_scopes_db_records() {
        let tmp = tempfile::tempdir().unwrap();
        let home_dir = tmp.path().join("home");
        let project_a = tmp.path().join("project_a");
        let project_b = tmp.path().join("project_b");
        fs::create_dir_all(&home_dir).unwrap();
        fs::create_dir_all(project_a.join("secrets")).unwrap();
        fs::create_dir_all(project_a.join("other")).unwrap();
        fs::create_dir_all(project_a.join("nested")).unwrap();
        fs::create_dir_all(&project_b).unwrap();

        fs::write(project_a.join(".env"), b"A=1\n").unwrap();
        fs::write(project_a.join("nested/app.env"), b"B=2\n").unwrap();
        fs::write(project_a.join("other/ignored_storage_file"), b"cipher\n").unwrap();
        fs::write(project_b.join(".env"), b"B_ONLY=1\n").unwrap();

        let toml = "[secrets]\nos-nux = \".\"\nos-mac = \".\"\nos-win = \".\"\nos-bsd = \".\"\nfiles = \"*\"\n\n[other]\nos-nux = \"./other_target\"\nos-mac = \"./other_target\"\nos-win = \"./other_target\"\nos-bsd = \"./other_target\"\nfiles = \"*.conf\"\n";
        fs::write(project_a.join("dotler.toml"), toml).unwrap();
        let repo_cfg = RepoConfig::parse(toml).unwrap();

        let state_db = StateDb::open(&tmp.path().join("state.db")).unwrap();
        state_db
            .upsert_synced_file(&crate::config::state::SyncedFileRecord {
                target_path: project_a
                    .join("only_in_a.env")
                    .to_string_lossy()
                    .to_string(),
                repo_label: "proj".to_string(),
                group_name: "secrets".to_string(),
                relative_path: "only_in_a.env".to_string(),
                file_hash: "deadbeef".to_string(),
                updated_at: 100,
            })
            .unwrap();
        let lock = DotlerLock::new(tmp.path().join("dotler.lock"))
            .acquire(Duration::from_millis(500), Duration::from_millis(10))
            .unwrap();

        // Planning in project_a ignores `dotler.toml` and group storage (`other/`), while keeping `project_a` DB record.
        let engine_a = SyncEngine::new(
            "proj",
            &project_a,
            &repo_cfg,
            &state_db,
            vec![],
            OsInfo::detect(),
            None,
        )
        .with_home_dir(&home_dir)
        .with_cwd(&project_a);
        let plans_a = plan(&engine_a, Some("secrets"), &lock).unwrap();
        let rel_a: Vec<&str> = plans_a.iter().map(|p| p.relative_path.as_str()).collect();
        assert_eq!(rel_a, vec![".env", "nested/app.env", "only_in_a.env"]);

        // Planning in project_b scopes out `project_a`'s DB record (`only_in_a.env`).
        let engine_b = SyncEngine::new(
            "proj",
            &project_a,
            &repo_cfg,
            &state_db,
            vec![],
            OsInfo::detect(),
            None,
        )
        .with_home_dir(&home_dir)
        .with_cwd(&project_b);
        let plans_b = plan(&engine_b, Some("secrets"), &lock).unwrap();
        let rel_b: Vec<&str> = plans_b.iter().map(|p| p.relative_path.as_str()).collect();
        assert_eq!(rel_b, vec![".env"]);
    }
}
