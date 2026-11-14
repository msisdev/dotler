//! Workspace initialization and unified static/format validation.

use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::agent::briefing::{DEFAULT_DOTLER_TOML, INIT_AI_HINT};
use crate::config::local::{WalkDir, expand_tilde};
use crate::config::repo::{
    SelectionMode, evaluate_selection, parse_selection_rules, render_home_template,
    resolve_group_target_path, validate_dir_no_symlinks, validate_os_dir_path,
    validate_path_security,
};
use crate::config::state::{DotlerLockGuard, TMP_FILE_PREFIX, write_file_safe};
use crate::core::context::CoreContext;
use crate::engine::EngineError;

pub use crate::engine::status::{FileActionPlan, FileSyncStatus, plan, run_status};

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
            let (clean_rel, is_enc_file) = if let Some(stripped) = rel_str.strip_suffix(".enc") {
                (stripped.to_string(), true)
            } else {
                (rel_str.to_string(), false)
            };
            if let Some(mode) = evaluate_selection(&rules, &clean_rel) {
                let enc_conflict = (mode.is_encrypted() && !is_enc_file)
                    || (mode.is_included() && !mode.is_encrypted() && is_enc_file);
                if enc_conflict {
                    return Err(EngineError::EncryptionMismatch {
                        path: entry.path().to_path_buf(),
                        reason: format!(
                            "Repository file '{clean_rel}' format conflicts with encryption rule in dotler.toml. Run 'dotler tidy' to reconcile format."
                        ),
                    });
                } else if mode == SelectionMode::TemplateInclude && !is_enc_file {
                    let bytes = fs::read(entry.path())?;
                    render_home_template(&bytes, &home_dir, &clean_rel)?;
                }
            }
        }
    }

    Ok(CheckReport {
        status: "valid".to_string(),
        groups_checked: repo_cfg.groups.len(),
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
        fs::write(repo_dir.join("g1/.bashrc.enc"), b"cipher").unwrap();

        let err2 = run_check(&ctx, None, &lock).unwrap_err();
        assert_eq!(err2.error_code(), "ENCRYPTION_MISMATCH");
        assert_eq!(err2.exit_code(), 1);
    }
}
