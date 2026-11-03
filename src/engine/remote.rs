//! Remote Git repository engine.
//!
//! Provides remote URL normalization, shallow inspection (`git ls`),
//! staging clone with Re-Keying (`git clone`), Write-Ahead Logging installation
//! (`git install`), and sequential rollback restoration (`git uninstall`).

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};

use crate::config::local::{LocalConfig, expand_tilde};
use crate::config::repo::{
    OsInfo, RepoConfig, SelectionMode, evaluate_selection, parse_selection_rules,
    resolve_group_target_path, validate_path_security,
};
use crate::config::state::{BACKUPS_DIR_PATH, DotlerLockGuard, InstalledFileRecord, StateDb};
use crate::crypto::vault::{EncryptedFile, VaultKey};
use crate::engine::EngineError;
use crate::engine::sync::atomic_write_file;

struct TempDirGuard(PathBuf);

impl TempDirGuard {
    fn new() -> Result<Self, std::io::Error> {
        let rand_id: u64 = rand::random();
        let path = std::env::temp_dir().join(format!(".dotler-tmp-{rand_id:016x}"));
        fs::create_dir_all(&path)?;
        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub const BACKUPS_DIR_NAME: &str = "backups";
pub const REMOTE_TOML_FETCH_MAX_BYTES: usize = 1_048_576; // 1 MiB
pub const STAGING_CLONE_PREFIX: &str = ".dotler-tmp-clone-";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteRepoUrl {
    pub raw: String,
    pub clone_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupSelector {
    pub remote_group: String,
    pub local_alias: Option<String>,
}

impl GroupSelector {
    pub fn parse(s: &str) -> Self {
        if let Some((group, alias)) = s.split_once(':') {
            Self {
                remote_group: group.trim().to_string(),
                local_alias: Some(alias.trim().to_string()),
            }
        } else {
            Self {
                remote_group: s.trim().to_string(),
                local_alias: None,
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathOverride {
    pub group_name: String,
    pub custom_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteGroupInfo {
    pub name: String,
    pub target_paths: BTreeMap<String, String>,
    pub has_encrypted: bool,
    pub files_rule: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteRepoSummary {
    pub url: String,
    pub groups: Vec<RemoteGroupInfo>,
    pub has_vault: bool,
    pub vault_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloneReport {
    pub repo_url: String,
    pub destination: PathBuf,
    pub cloned_groups: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallReport {
    pub installed_files: Vec<PathBuf>,
    pub backed_up_files: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UninstallReport {
    pub removed_files: Vec<PathBuf>,
    pub restored_backups: Vec<PathBuf>,
}

pub fn parse_url(raw: &str) -> Result<RemoteRepoUrl, EngineError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(EngineError::InvalidUrlFormat {
            url: raw.to_string(),
            reason: "URL cannot be empty".to_string(),
        });
    }

    let clone_url = if let Some(slug) = trimmed.strip_prefix("gh:") {
        let clean = slug.trim_matches('/');
        if clean.is_empty() {
            return Err(EngineError::InvalidUrlFormat {
                url: raw.to_string(),
                reason: "Repository slug cannot be empty".to_string(),
            });
        }
        format!("https://github.com/{}.git", clean)
    } else if let Some(slug) = trimmed.strip_prefix("gl:") {
        let clean = slug.trim_matches('/');
        if clean.is_empty() {
            return Err(EngineError::InvalidUrlFormat {
                url: raw.to_string(),
                reason: "Repository slug cannot be empty".to_string(),
            });
        }
        format!("https://gitlab.com/{}.git", clean)
    } else if let Some(slug) = trimmed.strip_prefix("cb:") {
        let clean = slug.trim_matches('/');
        if clean.is_empty() {
            return Err(EngineError::InvalidUrlFormat {
                url: raw.to_string(),
                reason: "Repository slug cannot be empty".to_string(),
            });
        }
        format!("https://codeberg.org/{}.git", clean)
    } else if let Some(slug) = trimmed.strip_prefix("srht:") {
        let clean = slug.trim_matches('/');
        if clean.is_empty() {
            return Err(EngineError::InvalidUrlFormat {
                url: raw.to_string(),
                reason: "Repository slug cannot be empty".to_string(),
            });
        }
        format!("https://git.sr.ht/{}", clean)
    } else if let Some(slug) = trimmed.strip_prefix("bb:") {
        let clean = slug.trim_matches('/');
        if clean.is_empty() {
            return Err(EngineError::InvalidUrlFormat {
                url: raw.to_string(),
                reason: "Repository slug cannot be empty".to_string(),
            });
        }
        format!("https://bitbucket.org/{}.git", clean)
    } else if trimmed.starts_with("https://") || trimmed.starts_with("http://") {
        if trimmed.ends_with(".git") {
            trimmed.to_string()
        } else {
            format!("{}.git", trimmed)
        }
    } else if trimmed.starts_with("file://")
        || trimmed.starts_with('/')
        || trimmed.starts_with("./")
    {
        trimmed.to_string()
    } else {
        return Err(EngineError::InvalidUrlFormat {
            url: trimmed.to_string(),
            reason: "Unrecognized URL scheme. Use gh:, gl:, cb:, srht:, bb:, or https://"
                .to_string(),
        });
    };

    Ok(RemoteRepoUrl {
        raw: trimmed.to_string(),
        clone_url,
    })
}

pub struct GitRunner;

impl GitRunner {
    pub fn clone_shallow(url: &str, branch: Option<&str>, dest: &Path) -> Result<(), EngineError> {
        let mut cmd = Command::new("git");
        cmd.arg("clone").arg("--depth").arg("1");
        if let Some(b) = branch {
            cmd.arg("--branch").arg(b);
        }
        cmd.arg(url).arg(dest);

        let output = cmd.output().map_err(|e| EngineError::GitError {
            operation: "clone".to_string(),
            message: format!("Failed to execute git clone: {e}"),
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(EngineError::GitError {
                operation: "clone".to_string(),
                message: format!("git clone failed: {}", stderr.trim()),
            });
        }

        Ok(())
    }

    pub fn fetch_file_shallow(
        url: &str,
        branch: Option<&str>,
        file_path: &str,
        max_bytes: usize,
    ) -> Result<Vec<u8>, EngineError> {
        let local_path = if let Some(stripped) = url.strip_prefix("file://") {
            Path::new(stripped)
        } else {
            Path::new(url)
        };

        if local_path.is_dir() {
            let direct_file = local_path.join(file_path);
            if direct_file.is_file() {
                let metadata = fs::metadata(&direct_file)?;
                if metadata.len() as usize > max_bytes {
                    return Err(EngineError::PayloadExceeded {
                        size_bytes: metadata.len() as usize,
                        limit_bytes: max_bytes,
                    });
                }
                return Ok(fs::read(&direct_file)?);
            }
        }

        let temp_dir = TempDirGuard::new().map_err(EngineError::Io)?;
        Self::clone_shallow(url, branch, temp_dir.path())?;

        let target_file = temp_dir.path().join(file_path);
        if !target_file.is_file() {
            return Err(EngineError::MissingRemoteToml {
                url: url.to_string(),
            });
        }

        let metadata = fs::metadata(&target_file)?;
        if metadata.len() as usize > max_bytes {
            return Err(EngineError::PayloadExceeded {
                size_bytes: metadata.len() as usize,
                limit_bytes: max_bytes,
            });
        }

        let content = fs::read(&target_file)?;
        Ok(content)
    }
}

pub fn list_remote(
    url: &RemoteRepoUrl,
    branch: Option<&str>,
    _lock: &DotlerLockGuard,
) -> Result<RemoteRepoSummary, EngineError> {
    let raw_toml = GitRunner::fetch_file_shallow(
        &url.clone_url,
        branch,
        "dotler.toml",
        REMOTE_TOML_FETCH_MAX_BYTES,
    )?;

    let toml_str = String::from_utf8(raw_toml).map_err(|_| EngineError::GitError {
        operation: "fetch".to_string(),
        message: "dotler.toml is not valid UTF-8".to_string(),
    })?;

    let repo_config = RepoConfig::parse(&toml_str)?;

    let mut groups = Vec::new();
    for (group_name, group) in &repo_config.groups {
        let rules = parse_selection_rules(&group.files).unwrap_or_default();
        let has_encrypted = rules
            .iter()
            .any(|r| r.mode == SelectionMode::EncryptedInclude);

        groups.push(RemoteGroupInfo {
            name: group_name.clone(),
            target_paths: group.paths.clone(),
            has_encrypted,
            files_rule: group.files.clone(),
        });
    }

    Ok(RemoteRepoSummary {
        url: url.raw.clone(),
        groups,
        has_vault: repo_config.vault.is_some(),
        vault_id: repo_config.vault.as_ref().map(|v| v.vault_id.clone()),
    })
}

#[allow(clippy::too_many_arguments)]
pub fn clone_repo(
    url: &RemoteRepoUrl,
    selectors: &[GroupSelector],
    branch: Option<&str>,
    target_dir: &Path,
    local_config_path: Option<&Path>,
    remote_vault_key: Option<&VaultKey>,
    local_vault_key: Option<&VaultKey>,
    _lock: &DotlerLockGuard,
) -> Result<CloneReport, EngineError> {
    if target_dir.exists() && target_dir.read_dir()?.next().is_some() {
        return Err(EngineError::GitError {
            operation: "clone".to_string(),
            message: format!(
                "Destination directory '{}' already exists and is not empty",
                target_dir.display()
            ),
        });
    }

    let parent = target_dir.parent().unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;

    let rand_id: u32 = rand::random();
    let staging_dir = parent.join(format!("{STAGING_CLONE_PREFIX}{:08x}", rand_id));

    struct AutoCleanup<'a>(&'a Path, bool);
    impl<'a> Drop for AutoCleanup<'a> {
        fn drop(&mut self) {
            if self.1 && self.0.exists() {
                let _ = fs::remove_dir_all(self.0);
            }
        }
    }
    let mut cleanup = AutoCleanup(&staging_dir, true);

    GitRunner::clone_shallow(&url.clone_url, branch, &staging_dir)?;

    let toml_path = staging_dir.join("dotler.toml");
    if !toml_path.is_file() {
        return Err(EngineError::MissingRemoteToml {
            url: url.raw.clone(),
        });
    }
    let repo_config = RepoConfig::load(&toml_path)?;
    repo_config.validate()?;

    let selected_groups: Vec<String> = if selectors.is_empty() {
        repo_config.groups.keys().cloned().collect()
    } else {
        for sel in selectors {
            if !repo_config.groups.contains_key(&sel.remote_group) {
                return Err(EngineError::GroupNotFound {
                    group: sel.remote_group.clone(),
                    available: repo_config.groups.keys().cloned().collect(),
                });
            }
        }
        selectors.iter().map(|s| s.remote_group.clone()).collect()
    };

    for g_name in &selected_groups {
        let group = &repo_config.groups[g_name];
        for path in group.paths.values() {
            validate_path_security(path)?;
        }
    }

    // In-Memory Re-Keying if local vault exists and remote vault is different
    if let (Some(r_key), Some(l_key)) = (remote_vault_key, local_vault_key)
        && r_key.vault_id() != l_key.vault_id()
    {
        for entry in walkdir::WalkDir::new(&staging_dir).min_depth(1) {
            let entry = entry.map_err(std::io::Error::from)?;
            if entry.file_type().is_file()
                && entry.path().extension().and_then(|s| s.to_str()) == Some("enc")
            {
                let enc_bytes = fs::read(entry.path())?;
                let enc_file = EncryptedFile::from_bytes(&enc_bytes)?;
                let decrypted = r_key.decrypt_file(&enc_file)?;
                let re_encrypted = l_key.encrypt_file(decrypted.expose_secret())?;
                atomic_write_file(entry.path(), &re_encrypted.to_bytes())?;
            }
        }
    }

    fs::rename(&staging_dir, target_dir)?;
    cleanup.1 = false; // Disarm cleanup

    if let Some(cfg_path) = local_config_path {
        let mut local_config = if cfg_path.is_file() {
            LocalConfig::load(cfg_path)?
        } else {
            LocalConfig::default()
        };
        let label = target_dir
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("~"));
        let repo_path_entry = if let Ok(rel) = target_dir.strip_prefix(&home) {
            if rel.as_os_str().is_empty() {
                "~".to_string()
            } else {
                format!("~/{}", rel.display())
            }
        } else {
            format!(
                "~/{}",
                target_dir
                    .file_name()
                    .map(|f| f.to_string_lossy())
                    .unwrap_or_default()
            )
        };
        local_config.repos.insert(label, repo_path_entry);
        local_config.save_atomic(cfg_path)?;
    }

    Ok(CloneReport {
        repo_url: url.raw.clone(),
        destination: target_dir.to_path_buf(),
        cloned_groups: selected_groups,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn install_remote(
    url: &RemoteRepoUrl,
    groups: &[String],
    path_override: Option<&Path>,
    branch: Option<&str>,
    devices: &[String],
    state: &StateDb,
    _lock: &DotlerLockGuard,
) -> Result<InstallReport, EngineError> {
    let temp_dir = TempDirGuard::new().map_err(EngineError::Io)?;
    GitRunner::clone_shallow(&url.clone_url, branch, temp_dir.path())?;

    let toml_path = temp_dir.path().join("dotler.toml");
    if !toml_path.is_file() {
        return Err(EngineError::MissingRemoteToml {
            url: url.raw.clone(),
        });
    }
    let repo_config = RepoConfig::load(&toml_path)?;
    repo_config.validate()?;

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
    let mut installed_files = Vec::new();
    let mut backed_up_files = Vec::new();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    for g_name in &target_groups {
        let group = &repo_config.groups[g_name];
        let target_base: PathBuf = if let Some(override_path) = path_override {
            let home = resolve_home_for_state(state);
            let path_str = override_path.to_string_lossy();
            let check_path = if path_str == "~" || path_str.starts_with("~/") {
                path_str.to_string()
            } else if override_path == home {
                "~".to_string()
            } else if let Ok(rel) = override_path.strip_prefix(&home) {
                format!("~/{}", rel.to_string_lossy().trim_start_matches('/'))
            } else {
                path_str.to_string()
            };
            validate_path_security(&check_path)?;
            if path_str == "~" {
                home
            } else if let Some(stripped) = path_str.strip_prefix("~/") {
                home.join(stripped)
            } else {
                override_path.to_path_buf()
            }
        } else {
            let path_str =
                resolve_group_target_path(group, devices, &os_info).ok_or_else(|| {
                    EngineError::GroupNotFound {
                        group: g_name.clone(),
                        available: repo_config.groups.keys().cloned().collect(),
                    }
                })?;
            validate_path_security(&path_str)?;
            let home = resolve_home_for_state(state);
            if path_str == "~" {
                home
            } else if let Some(stripped) = path_str.strip_prefix("~/") {
                home.join(stripped)
            } else {
                PathBuf::from(path_str)
            }
        };

        let group_dir = temp_dir.path().join(g_name);
        if !group_dir.is_dir() {
            continue;
        }

        let rules = parse_selection_rules(&group.files).unwrap_or_default();

        for entry in walkdir::WalkDir::new(&group_dir).min_depth(1) {
            let entry = entry.map_err(std::io::Error::from)?;
            if entry.file_type().is_dir() {
                continue;
            }

            let rel_path = entry.path().strip_prefix(&group_dir).unwrap();
            let rel_path_str = rel_path.to_string_lossy().to_string();

            if let Some(SelectionMode::Exclude) = evaluate_selection(&rules, &rel_path_str) {
                continue;
            }

            let clean_rel = if let Some(stripped) = rel_path_str.strip_suffix(".enc") {
                stripped.to_string()
            } else {
                rel_path_str.clone()
            };

            let target_file_path = target_base.join(&clean_rel);
            let target_str = target_file_path.to_string_lossy().to_string();

            // 1. Check existing installed_files record to preserve original backup
            let existing = state.get_installed_file(&target_str)?;
            let backup_path: Option<String> = if let Some(ref ext) = existing {
                ext.backup_path.clone()
            } else if target_file_path.is_file() {
                let bp = create_backup_file(&target_file_path, &clean_rel, timestamp, state)?;
                backed_up_files.push(PathBuf::from(&bp));
                Some(bp)
            } else {
                None
            };

            // 2. Read source payload
            let file_content = fs::read(entry.path())?;
            let hash = blake3::hash(&file_content).to_hex().to_string();

            // 3. Sequential Write-Ahead commit to SQLite
            let record = InstalledFileRecord {
                target_path: target_str.clone(),
                repo_url: url.clone_url.clone(),
                group_name: g_name.clone(),
                relative_path: clean_rel,
                file_hash: hash,
                updated_at: timestamp,
                backup_path,
            };
            state.upsert_installed_file(&record)?;

            // 4. Atomic file deployment
            atomic_write_file(&target_file_path, &file_content)?;
            installed_files.push(target_file_path);
        }
    }

    Ok(InstallReport {
        installed_files,
        backed_up_files,
    })
}

pub fn uninstall_remote(
    groups: &[String],
    state: &StateDb,
    _lock: &DotlerLockGuard,
    dry_run: bool,
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

    let mut removed_files = Vec::new();
    let mut restored_backups = Vec::new();

    for record in filtered_records {
        let target = PathBuf::from(&record.target_path);

        if let Some(ref bp_str) = record.backup_path {
            let bp = PathBuf::from(bp_str);
            if bp.is_file() {
                if !dry_run {
                    let backup_bytes = fs::read(&bp)?;
                    atomic_write_file(&target, &backup_bytes)?;
                    state.remove_installed_file(&record.target_path)?;
                    let _ = fs::remove_file(&bp);
                    if let Some(p) = bp.parent() {
                        let _ = fs::remove_dir(p);
                    }
                }
                restored_backups.push(target);
            } else {
                if !dry_run {
                    if target.is_file() {
                        let _ = fs::remove_file(&target);
                    }
                    state.remove_installed_file(&record.target_path)?;
                }
                removed_files.push(target);
            }
        } else {
            if !dry_run {
                if target.is_file() {
                    let _ = fs::remove_file(&target);
                }
                state.remove_installed_file(&record.target_path)?;
            }
            removed_files.push(target);
        }
    }

    Ok(UninstallReport {
        removed_files,
        restored_backups,
    })
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
    atomic_write_file(&dest, &source_bytes)?;
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
        dirs::home_dir().unwrap_or_else(|| PathBuf::from("."))
    }
}
