//! Workspace initialization and unified static/format validation.

use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::agent::briefing::{DEFAULT_DOTLER_TOML, INIT_AI_HINT};
use crate::config::local::{
    WalkDir, expand_tilde, format_home_repo_path, resolve_home_for_config_path,
};
use crate::config::path_security::resolve_with_existing_ancestors;
use crate::config::repo::{
    SelectionMode, evaluate_selection, find_literal_full_enc_rules, group_matches_filter,
    group_repo_dir, is_cwd_group_path, is_delegated_to_subgroup, is_home_group_path,
    parse_selection_rules, render_home_template, rules_have_effective_full_encryption,
    validate_dir_no_symlinks, validate_os_dir_path_with_home, validate_path_security,
    validate_repo_target_disjointness, validate_rule_pattern,
};
use crate::config::state::{DotlerLockGuard, TMP_FILE_PREFIX, write_file_safe};
use crate::core::context::CoreContext;
use crate::core::vault_loader::unlock_vault_if_needed;
use crate::crypto::ExposeSecret;
use crate::crypto::vault::{
    EncryptedFile, FullEncryptedFile, LEGACY_CONTENT_ENC_SUFFIX, LEGACY_FULL_ENC_SUFFIX,
    is_content_enc_name, is_full_enc_name, is_legacy_dotler_archive_bytes,
    parse_fenc_filename_stem, strip_content_enc_suffix,
};
use crate::engine::EngineError;

pub use crate::engine::status::{FileActionPlan, FileSyncStatus, plan, run_status};

/// Result summary returned by [`run_check`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckReport {
    pub status: String,
    pub groups_checked: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
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
    pub hint: String,
}

/// Scaffolds a new dotler repository (`dotler.toml` with top AI hint comment) and registers it in `config.toml`.
pub fn run_init(
    ctx: &mut CoreContext,
    params: InitParams,
    _lock: &DotlerLockGuard,
) -> Result<InitReport, EngineError> {
    let repo_dir = match params.repo_path {
        Some(p) => p,
        None => std::env::current_dir()?,
    };

    let home = ctx
        .state_db
        .get()
        .map(|db| resolve_home_for_config_path(db.path()))
        .unwrap_or_else(|_| expand_tilde("~"));
    let repo_path_entry = format_home_repo_path(&repo_dir, &home)?;

    fs::create_dir_all(&repo_dir)?;

    let dotler_toml_path = repo_dir.join("dotler.toml");
    if !dotler_toml_path.exists() {
        write_file_safe(&dotler_toml_path, DEFAULT_DOTLER_TOML.as_bytes())?;
    }

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
        hint: INIT_AI_HINT.to_string(),
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

    // 1. Validate group filter existence (exact or subtree match)
    if let Some(filter_grp) = group_filter
        && !repo_cfg
            .groups
            .keys()
            .any(|g| group_matches_filter(g, filter_grp))
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
            && !group_matches_filter(g_name, filter)
        {
            continue;
        }
        for p in repo_cfg.effective_group_paths(g_name).values() {
            validate_path_security(p)?;
        }
        parse_selection_rules(&g_cfg.files)?;
    }

    let home_dir = ctx
        .state_db
        .get()
        .map(|db| resolve_home_for_config_path(db.path()))
        .unwrap_or_else(|_| expand_tilde("~"));
    let cwd = ctx.effective_cwd()?;

    // 3. Detect cross-group target file collisions (static manifest + expanded roots)
    repo_cfg.detect_cross_group_collisions(&resolved.devices, &resolved.os_info)?;
    repo_cfg.detect_cross_group_collisions_with_roots(
        &resolved.devices,
        &resolved.os_info,
        &home_dir,
        &cwd,
    )?;

    // 4. Reject symlinks in repository, collect literal enc=full warnings, and detect .dotler.enc/.dotler.fenc mismatches
    let use_keyring = ctx
        .local_config
        .get()
        .map(|c| c.use_keyring)
        .unwrap_or(false);
    let optional_vault_key = if repo_cfg.vault.is_some() {
        unlock_vault_if_needed(repo_cfg, use_keyring, false, false)
            .ok()
            .flatten()
    } else {
        None
    };
    let mut warnings = Vec::new();
    let expected_vid_opt = repo_cfg.vault.as_ref().map(|v| v.vault_id.as_str());
    let canon_repo = resolve_with_existing_ancestors(repo_path);

    let mut checked_count = 0usize;
    for (g_name, g_cfg) in &repo_cfg.groups {
        if let Some(filter) = group_filter
            && !group_matches_filter(g_name, filter)
        {
            continue;
        }
        checked_count += 1;
        let group_repo_dir = group_repo_dir(repo_path, g_name);
        let delegated_subpaths = repo_cfg.descendant_subpaths(g_name);
        validate_dir_no_symlinks(&group_repo_dir)?;
        let target_and_boundary = repo_cfg
            .resolve_target_path(g_name, &resolved.devices, &resolved.os_info)
            .map(|s| {
                if is_home_group_path(&s) {
                    let rel = s.strip_prefix("~/").unwrap_or("").trim_matches('/');
                    let target = if rel.is_empty() {
                        home_dir.clone()
                    } else {
                        home_dir.join(rel)
                    };
                    (target, home_dir.clone())
                } else if is_cwd_group_path(&s) {
                    let mut rel = s.strip_prefix('.').unwrap_or(&s).trim_start_matches('/');
                    while let Some(next) = rel.strip_prefix("./") {
                        rel = next.trim_start_matches('/');
                    }
                    let rel = rel.trim_end_matches('/');
                    let target = if rel.is_empty() || rel == "." {
                        cwd.clone()
                    } else {
                        cwd.join(rel)
                    };
                    (target, cwd.clone())
                } else {
                    (PathBuf::from(s), home_dir.clone())
                }
            });
        let target_base_opt = target_and_boundary.as_ref().map(|(t, _)| t.clone());
        if let Some((ref target_base_path, ref boundary_dir)) = target_and_boundary {
            validate_os_dir_path_with_home(target_base_path, boundary_dir, &home_dir)?;
            validate_repo_target_disjointness(
                repo_path,
                repo_cfg.groups.keys().map(String::as_str),
                target_base_path,
            )?;
        }
        let rules = parse_selection_rules(&g_cfg.files)?;
        if let Some(ref target_base_path) = target_base_opt {
            let in_project_repo =
                resolve_with_existing_ancestors(target_base_path).starts_with(&canon_repo);
            if in_project_repo {
                for rule in &rules {
                    if rule.mode == SelectionMode::Exclude {
                        continue;
                    }
                    let clean = rule.pattern.trim_start_matches("./").trim_end_matches('/');
                    if clean.is_empty()
                        || clean.contains('*')
                        || clean.contains('?')
                        || clean.contains('[')
                        || is_delegated_to_subgroup(clean, &delegated_subpaths)
                    {
                        continue;
                    }
                    if evaluate_selection(&rules, clean).is_some_and(|m| m.is_included()) {
                        let candidate_target = target_base_path.join(clean);
                        validate_repo_target_disjointness(
                            repo_path,
                            repo_cfg.groups.keys().map(String::as_str),
                            &candidate_target,
                        )?;
                    }
                }
            }
        }
        for (line_no, literal_pat) in
            find_literal_full_enc_rules(&rules, target_base_opt.as_deref(), Some(&group_repo_dir))
        {
            warnings.push(format!(
                "Group '{g_name}' line {line_no}: literal path '{literal_pat}' with 'enc=full' remains visible in dotler.toml; use a wildcard or directory pattern (e.g. '*.ext enc=full' or '* enc=full') to hide the filename in dotler.toml as well."
            ));
        }

        if !group_repo_dir.is_dir() {
            continue;
        }
        let has_full_enc_rule = rules_have_effective_full_encryption(&rules);
        for entry in WalkDir::new(&group_repo_dir)
            .filter_entry(|e| {
                if e.depth() == 0 {
                    return true;
                }
                !e.path().strip_prefix(&group_repo_dir).is_ok_and(|rel| {
                    is_delegated_to_subgroup(&rel.to_string_lossy(), &delegated_subpaths)
                })
            })
            .filter_map(|e| e.ok())
        {
            if !entry.file_type().is_file() {
                continue;
            }
            let file_name = entry.file_name().to_string_lossy();
            if file_name.starts_with(TMP_FILE_PREFIX) || file_name == ".git" {
                continue;
            }
            let Ok(rel) = entry.path().strip_prefix(&group_repo_dir) else {
                continue;
            };
            let rel_str = rel.to_string_lossy();
            if rel_str.split('/').any(|s| s == ".git") {
                continue;
            }

            if is_full_enc_name(&rel_str) {
                if rel_str.contains('/') || parse_fenc_filename_stem(&file_name).is_none() {
                    return Err(EngineError::EncryptionMismatch {
                        path: entry.path().to_path_buf(),
                        reason: format!(
                            "Repository file '{rel_str}' is not a valid flattened '<32-hex>.dotler.fenc' archive. Run 'dotler tidy' or 'dotler import --force'."
                        ),
                    });
                }
                if !has_full_enc_rule {
                    return Err(EngineError::EncryptionMismatch {
                        path: entry.path().to_path_buf(),
                        reason: format!(
                            "Repository file '{rel_str}' uses full encryption (.dotler.fenc), but no active 'enc=full' rule exists in dotler.toml. Run 'dotler tidy' to reconcile format."
                        ),
                    });
                }
                let bytes = fs::read(entry.path())?;
                let fenc_file = FullEncryptedFile::from_bytes(&bytes).map_err(|_| {
                    EngineError::EncryptionMismatch {
                        path: entry.path().to_path_buf(),
                        reason: format!(
                            "Repository file '{rel_str}' is not a valid .dotler.fenc archive. Run 'dotler import --force' to re-encrypt."
                        ),
                    }
                })?;
                let file_vid = crate::crypto::vault::bytes_to_hex(&fenc_file.vault_id);
                let expected_vid = expected_vid_opt
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .ok_or(EngineError::Config(
                        crate::config::ConfigError::MissingVaultConfig,
                    ))?;
                if file_vid != expected_vid {
                    return Err(EngineError::EncryptionMismatch {
                        path: entry.path().to_path_buf(),
                        reason: format!(
                            "Repository file '{rel_str}' is encrypted with vault '{file_vid}', which does not match dotler.toml vault '{expected_vid}'. Run 'dotler vault from file <repo>' to align vault keys or 'dotler import --force' to re-encrypt."
                        ),
                    });
                }
                if let Some(ref key) = optional_vault_key {
                    let (dec_rel, plain) = key
                        .decrypt_full_file(&file_name, &fenc_file)
                        .map_err(|_| EngineError::EncryptionMismatch {
                            path: entry.path().to_path_buf(),
                            reason: format!(
                                "Repository file '{rel_str}' failed full-encryption integrity or filename binding check. Run 'dotler import --force' to re-encrypt."
                            ),
                        })?;
                    validate_rule_pattern(&dec_rel)?;
                    if is_delegated_to_subgroup(&dec_rel, &delegated_subpaths) {
                        return Err(EngineError::EncryptionMismatch {
                            path: entry.path().to_path_buf(),
                            reason: format!(
                                "Repository file '{dec_rel}' in group '{g_name}' belongs to a configured sub-group. Run 'dotler tidy' to relocate it."
                            ),
                        });
                    }
                    if let Some(mode) = evaluate_selection(&rules, &dec_rel) {
                        if mode.is_included() && !mode.is_full_encrypted() {
                            return Err(EngineError::EncryptionMismatch {
                                path: entry.path().to_path_buf(),
                                reason: format!(
                                    "Repository file '{dec_rel}' format (.dotler.fenc) conflicts with selection rule in dotler.toml. Run 'dotler tidy' to reconcile format."
                                ),
                            });
                        }
                        if mode.is_template() {
                            render_home_template(plain.expose_secret(), &home_dir, &dec_rel)?;
                        }
                    }
                }
                continue;
            }

            if let Some(clean_rel) = strip_content_enc_suffix(&rel_str) {
                if let Some(mode) = evaluate_selection(&rules, clean_rel) {
                    if mode.is_included() && !mode.is_content_encrypted() {
                        return Err(EngineError::EncryptionMismatch {
                            path: entry.path().to_path_buf(),
                            reason: format!(
                                "Repository file '{clean_rel}' format conflicts with encryption rule in dotler.toml. Run 'dotler tidy' to reconcile format."
                            ),
                        });
                    } else if mode.is_content_encrypted() {
                        let bytes = fs::read(entry.path())?;
                        let enc_file = EncryptedFile::from_bytes(&bytes).map_err(|_| {
                            EngineError::EncryptionMismatch {
                                path: entry.path().to_path_buf(),
                                reason: format!(
                                    "Repository file '{rel_str}' is not a valid .dotler.enc archive. Run 'dotler import --force' to re-encrypt."
                                ),
                            }
                        })?;
                        let file_vid = crate::crypto::vault::bytes_to_hex(&enc_file.vault_id);
                        let expected_vid = expected_vid_opt
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .ok_or(EngineError::Config(
                                crate::config::ConfigError::MissingVaultConfig,
                            ))?;
                        if file_vid != expected_vid {
                            return Err(EngineError::EncryptionMismatch {
                                path: entry.path().to_path_buf(),
                                reason: format!(
                                    "Repository file '{rel_str}' is encrypted with vault '{file_vid}', which does not match dotler.toml vault '{expected_vid}'. Run 'dotler vault from file <repo>' to align vault keys or 'dotler import --force' to re-encrypt."
                                ),
                            });
                        }
                    }
                }
                continue;
            }

            if !is_content_enc_name(&rel_str)
                && (rel_str.ends_with(LEGACY_CONTENT_ENC_SUFFIX)
                    || rel_str.ends_with(LEGACY_FULL_ENC_SUFFIX))
            {
                let bytes = fs::read(entry.path())?;
                if is_legacy_dotler_archive_bytes(&bytes, expected_vid_opt) {
                    return Err(EngineError::EncryptionMismatch {
                        path: entry.path().to_path_buf(),
                        reason: format!(
                            "Repository file '{rel_str}' uses a legacy encrypted suffix (.enc/.fenc). Run 'dotler tidy' to migrate to .dotler.enc/.dotler.fenc."
                        ),
                    });
                }
            }

            let clean_rel = rel_str.as_ref();
            if let Some(mode) = evaluate_selection(&rules, clean_rel) {
                if mode.is_encrypted() {
                    return Err(EngineError::EncryptionMismatch {
                        path: entry.path().to_path_buf(),
                        reason: format!(
                            "Repository file '{clean_rel}' format conflicts with encryption rule in dotler.toml. Run 'dotler tidy' to reconcile format."
                        ),
                    });
                } else if mode == SelectionMode::TemplateInclude {
                    let bytes = fs::read(entry.path())?;
                    render_home_template(&bytes, &home_dir, clean_rel)?;
                }
            }
        }
    }

    Ok(CheckReport {
        status: "valid".to_string(),
        groups_checked: checked_count,
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::local::LocalConfig;
    use crate::config::state::DotlerLock;
    use std::time::Duration;

    #[test]
    fn run_check_detects_cross_group_collision_and_enc_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let repo_dir = tmp.path().join("repo");
        fs::create_dir_all(repo_dir.join("g1")).unwrap();
        fs::create_dir_all(repo_dir.join("g2")).unwrap();

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

        let mismatch_toml = "[g1]\nos-nux = \"~\"\nos-mac = \"~\"\nfiles = \".bashrc\"\n";
        fs::write(repo_dir.join("dotler.toml"), mismatch_toml).unwrap();
        fs::write(repo_dir.join("g1/.bashrc.dotler.enc"), b"cipher").unwrap();

        let err2 = run_check(&ctx, None, &lock).unwrap_err();
        assert_eq!(err2.error_code(), "ENCRYPTION_MISMATCH");
        assert_eq!(err2.exit_code(), 1);

        // Static .dotler.enc header vault_id mismatch check
        let pass_a = crate::crypto::SecretString::new("vault-a-pass-123".to_string());
        let pass_b = crate::crypto::SecretString::new("vault-b-pass-456".to_string());
        let (vcfg_a, _, _) = crate::crypto::vault::init_vault(&pass_a).unwrap();
        let (_, vkey_b, _) = crate::crypto::vault::init_vault(&pass_b).unwrap();
        let enc_b = vkey_b
            .encrypt_file(b"TOKEN=other_vault")
            .unwrap()
            .to_bytes();

        let _ = fs::remove_file(repo_dir.join("g1/.bashrc.dotler.enc"));
        fs::write(
            repo_dir.join("dotler.toml"),
            format!(
                "vault_id = \"{}\"\npassword_slot = \"{}\"\nrecovery_slot = \"{}\"\n\n[g1]\nos-nux = \"~\"\nos-mac = \"~\"\nfiles = \".secret enc\"\n",
                vcfg_a.vault_id, vcfg_a.password_slot, vcfg_a.recovery_slot
            ),
        )
        .unwrap();
        fs::write(repo_dir.join("g1/.secret.dotler.enc"), enc_b).unwrap();

        let err3 = run_check(&ctx, None, &lock).unwrap_err();
        assert_eq!(err3.error_code(), "ENCRYPTION_MISMATCH");
        assert_eq!(err3.exit_code(), 1);
        assert!(err3.hint().contains("vault from file"));

        // Empty vault_id in dotler.toml with enc rule must be rejected as MissingVaultConfig
        fs::write(
            repo_dir.join("dotler.toml"),
            format!(
                "vault_id = \"\"\npassword_slot = \"{}\"\nrecovery_slot = \"{}\"\n\n[g1]\nos-nux = \"~\"\nos-mac = \"~\"\nfiles = \".secret enc\"\n",
                vcfg_a.password_slot, vcfg_a.recovery_slot
            ),
        )
        .unwrap();
        let err4 = run_check(&ctx, None, &lock).unwrap_err();
        assert_eq!(err4.error_code(), "CONFIG_ERROR");
    }

    #[test]
    fn run_init_rejects_outside_home_before_creating_files() {
        let tmp = tempfile::tempdir().unwrap();
        let home_dir = tmp.path().join("home");
        let dotler_dir = home_dir.join(".config").join("dotler");
        let outside_repo = tmp.path().join("outside").join("dots");
        fs::create_dir_all(&dotler_dir).unwrap();

        let lock_path = dotler_dir.join("dotler.lock");
        let lock = DotlerLock::new(lock_path.clone())
            .acquire(Duration::from_millis(500), Duration::from_millis(10))
            .unwrap();
        let mut ctx = CoreContext::with_paths(
            lock_path,
            dotler_dir.join("config.toml"),
            dotler_dir.join("state.db"),
            None,
            None,
            false,
        );

        let err = run_init(
            &mut ctx,
            InitParams {
                label: Some("outside".to_string()),
                device: None,
                repo_path: Some(outside_repo.clone()),
            },
            &lock,
        )
        .unwrap_err();
        assert_eq!(err.error_code(), "CONFIG_ERROR");
        assert!(!outside_repo.exists());

        let inside_repo = home_dir.join("my-dots");
        let report = run_init(
            &mut ctx,
            InitParams {
                label: Some("main".to_string()),
                device: Some("laptop".to_string()),
                repo_path: Some(inside_repo.clone()),
            },
            &lock,
        )
        .unwrap();
        assert_eq!(report.repo_path, inside_repo);
        assert!(inside_repo.join("dotler.toml").is_file());
        assert_eq!(
            ctx.local_config
                .get()
                .unwrap()
                .repos
                .get("main")
                .map(String::as_str),
            Some("~/my-dots")
        );
    }

    #[test]
    fn run_check_validates_in_project_cwd_repo_and_blocks_storage_overlap_and_home_collision() {
        let tmp = tempfile::tempdir().unwrap();
        let home_dir = tmp.path().join("home");
        let dotler_dir = home_dir.join(".config").join("dotler");
        let project_dir = tmp.path().join("project");
        fs::create_dir_all(&dotler_dir).unwrap();
        fs::create_dir_all(&project_dir).unwrap();

        let lock_path = dotler_dir.join("dotler.lock");
        let lock = DotlerLock::new(lock_path.clone())
            .acquire(Duration::from_millis(500), Duration::from_millis(10))
            .unwrap();

        let pass = crate::crypto::SecretString::new("in-project-check-pass".to_string());
        let (vcfg, _, _) = crate::crypto::vault::init_vault(&pass).unwrap();

        // 1. Valid in-project repo using `.` for `[secrets]`.
        fs::write(
            project_dir.join("dotler.toml"),
            format!(
                "vault_id = \"{}\"\npassword_slot = \"{}\"\nrecovery_slot = \"{}\"\n\n[secrets]\nos-nux = \".\"\nos-mac = \".\"\nos-win = \".\"\nos-bsd = \".\"\nfiles = \".env enc\"\n",
                vcfg.vault_id, vcfg.password_slot, vcfg.recovery_slot
            ),
        )
        .unwrap();

        let mut ctx = CoreContext::with_paths(
            lock_path.clone(),
            dotler_dir.join("config.toml"),
            dotler_dir.join("state.db"),
            None,
            None,
            false,
        )
        .with_cwd(&project_dir);
        ctx.local_config = crate::core::resource::Resource::from_value(LocalConfig::default());

        let ok_rep = run_check(&ctx, None, &lock).unwrap();
        assert_eq!(ok_rep.status, "valid");

        // 2. Overlapping `[config]` storage directory with `os-nux = "./config"` -> HardBlockedPath.
        fs::write(
            project_dir.join("dotler.toml"),
            "[config]\nos-nux = \"./config\"\nos-mac = \"./config\"\nos-win = \"./config\"\nos-bsd = \"./config\"\nfiles = \"app.env\"\n",
        )
        .unwrap();
        let overlap_err = run_check(&ctx, None, &lock).unwrap_err();
        assert_eq!(overlap_err.exit_code(), 3);

        // 3. Literal rule targeting `<repo>/<group>/...` with `os-nux = "."` -> HardBlockedPath.
        fs::write(
            project_dir.join("dotler.toml"),
            "[config]\nos-nux = \".\"\nos-mac = \".\"\nos-win = \".\"\nos-bsd = \".\"\nfiles = \"config/secret.env\"\n",
        )
        .unwrap();
        let nested_overlap_err = run_check(&ctx, None, &lock).unwrap_err();
        assert_eq!(nested_overlap_err.exit_code(), 3);

        // 4. `~` + `.env` vs `.` + `.env` fails when `cwd == home_dir`, passes in `project_dir`.
        fs::write(
            project_dir.join("dotler.toml"),
            "[home_grp]\nos-nux = \"~\"\nos-mac = \"~\"\nos-win = \"~\"\nos-bsd = \"~\"\nfiles = \".env\"\n\n[proj_grp]\nos-nux = \".\"\nos-mac = \".\"\nos-win = \".\"\nos-bsd = \".\"\nfiles = \".env\"\n",
        )
        .unwrap();
        assert!(run_check(&ctx, None, &lock).is_ok());

        let mut local_cfg_home = LocalConfig::default();
        local_cfg_home.repos.insert(
            "proj".to_string(),
            project_dir.to_string_lossy().to_string(),
        );
        let mut ctx_at_home = CoreContext::with_paths(
            lock_path,
            dotler_dir.join("config.toml"),
            dotler_dir.join("state.db"),
            Some("proj".to_string()),
            None,
            false,
        )
        .with_cwd(&home_dir);
        ctx_at_home.local_config = crate::core::resource::Resource::from_value(local_cfg_home);
        let collision_err = run_check(&ctx_at_home, None, &lock).unwrap_err();
        assert_eq!(collision_err.error_code(), "CONFIG_ERROR");
    }
}
