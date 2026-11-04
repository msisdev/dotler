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
    OsInfo, RepoConfig, SelectionMode, evaluate_selection, is_symlink, parse_selection_rules,
    resolve_group_target_path, validate_dir_no_symlinks, validate_os_dir_path,
    validate_os_target_path, validate_path_security,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subpath: Option<String>,
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
pub struct RemoteManifestSummary {
    pub path: String,
    pub groups: Vec<RemoteGroupInfo>,
    pub has_vault: bool,
    pub vault_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteRepoSummary {
    pub url: String,
    #[serde(default)]
    pub manifests: Vec<RemoteManifestSummary>,
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

fn normalize_subpath(raw_sub: &str) -> Result<String, EngineError> {
    let trimmed = raw_sub.trim_matches('/');
    if trimmed.contains("..") || trimmed.contains('\\') {
        return Err(EngineError::HardBlockedPath {
            path: PathBuf::from(raw_sub),
            reason: "directory traversal ('..') or backslash is prohibited in dotler.toml path"
                .to_string(),
        });
    }
    if trimmed.is_empty() || trimmed == "dotler.toml" {
        return Ok(String::new());
    }
    if let Some(stripped) = trimmed.strip_suffix("/dotler.toml") {
        return Ok(stripped.trim_matches('/').to_string());
    }
    Ok(trimmed.to_string())
}

fn split_two_segment_slug(clean: &str) -> (&str, Option<&str>) {
    if let Some((repo_part, sub_part)) = clean.split_once(".git/") {
        return (repo_part, Some(sub_part));
    }
    let mut indices = clean.match_indices('/');
    if let (Some(_), Some((second_slash, _))) = (indices.next(), indices.next()) {
        let repo_part = clean[..second_slash]
            .trim_end_matches('/')
            .trim_end_matches(".git");
        let sub_part = &clean[second_slash + 1..];
        (repo_part, Some(sub_part))
    } else {
        (clean.trim_end_matches(".git"), None)
    }
}

fn is_git_repo_dir(dir: &Path) -> bool {
    dir.join(".git").exists() || (dir.join("HEAD").is_file() && dir.join("objects").is_dir())
}

pub fn parse_url(raw: &str) -> Result<RemoteRepoUrl, EngineError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(EngineError::InvalidUrlFormat {
            url: raw.to_string(),
            reason: "URL cannot be empty".to_string(),
        });
    }

    let (clone_url, subpath) = if let Some(slug) = trimmed.strip_prefix("gh:") {
        let clean = slug.trim_matches('/');
        if clean.is_empty() {
            return Err(EngineError::InvalidUrlFormat {
                url: raw.to_string(),
                reason: "Repository slug cannot be empty".to_string(),
            });
        }
        let (repo_part, sub) = split_two_segment_slug(clean);
        let sub_norm = match sub {
            Some(s) => Some(normalize_subpath(s)?),
            None => None,
        };
        (format!("https://github.com/{}.git", repo_part), sub_norm)
    } else if let Some(slug) = trimmed.strip_prefix("gl:") {
        let clean = slug.trim_matches('/');
        if clean.is_empty() {
            return Err(EngineError::InvalidUrlFormat {
                url: raw.to_string(),
                reason: "Repository slug cannot be empty".to_string(),
            });
        }
        if let Some((repo_part, sub_part)) = clean.split_once(".git/") {
            (
                format!("https://gitlab.com/{}.git", repo_part),
                Some(normalize_subpath(sub_part)?),
            )
        } else if clean.ends_with("/dotler.toml") {
            let (repo_part, sub) = split_two_segment_slug(clean);
            let sub_norm = match sub {
                Some(s) => Some(normalize_subpath(s)?),
                None => Some(String::new()),
            };
            (format!("https://gitlab.com/{}.git", repo_part), sub_norm)
        } else {
            (
                format!("https://gitlab.com/{}.git", clean.trim_end_matches(".git")),
                None,
            )
        }
    } else if let Some(slug) = trimmed.strip_prefix("cb:") {
        let clean = slug.trim_matches('/');
        if clean.is_empty() {
            return Err(EngineError::InvalidUrlFormat {
                url: raw.to_string(),
                reason: "Repository slug cannot be empty".to_string(),
            });
        }
        let (repo_part, sub) = split_two_segment_slug(clean);
        let sub_norm = match sub {
            Some(s) => Some(normalize_subpath(s)?),
            None => None,
        };
        (format!("https://codeberg.org/{}.git", repo_part), sub_norm)
    } else if let Some(slug) = trimmed.strip_prefix("srht:") {
        let clean = slug.trim_matches('/');
        if clean.is_empty() {
            return Err(EngineError::InvalidUrlFormat {
                url: raw.to_string(),
                reason: "Repository slug cannot be empty".to_string(),
            });
        }
        let (repo_part, sub) = split_two_segment_slug(clean);
        let sub_norm = match sub {
            Some(s) => Some(normalize_subpath(s)?),
            None => None,
        };
        (format!("https://git.sr.ht/{}", repo_part), sub_norm)
    } else if let Some(slug) = trimmed.strip_prefix("bb:") {
        let clean = slug.trim_matches('/');
        if clean.is_empty() {
            return Err(EngineError::InvalidUrlFormat {
                url: raw.to_string(),
                reason: "Repository slug cannot be empty".to_string(),
            });
        }
        let (repo_part, sub) = split_two_segment_slug(clean);
        let sub_norm = match sub {
            Some(s) => Some(normalize_subpath(s)?),
            None => None,
        };
        (format!("https://bitbucket.org/{}.git", repo_part), sub_norm)
    } else if trimmed.starts_with("https://") || trimmed.starts_with("http://") {
        if let Some((left, right)) = trimmed.split_once(".git/") {
            (format!("{left}.git"), Some(normalize_subpath(right)?))
        } else if let Some((scheme, rest)) = trimmed.split_once("://")
            && let Some((host, path_part)) = rest.split_once('/')
        {
            let clean_path = path_part.trim_matches('/');
            let is_two_seg_host = matches!(
                host,
                "github.com" | "codeberg.org" | "bitbucket.org" | "git.sr.ht"
            );
            if is_two_seg_host || clean_path.ends_with("/dotler.toml") {
                let (repo_part, sub) = split_two_segment_slug(clean_path);
                let sub_norm = match sub {
                    Some(s) => Some(normalize_subpath(s)?),
                    None => None,
                };
                let url_out = format!("{scheme}://{host}/{repo_part}.git");
                (url_out, sub_norm)
            } else if trimmed.ends_with(".git") {
                (trimmed.to_string(), None)
            } else {
                (format!("{}.git", trimmed.trim_end_matches('/')), None)
            }
        } else if trimmed.ends_with(".git") {
            (trimmed.to_string(), None)
        } else {
            (format!("{}.git", trimmed), None)
        }
    } else if trimmed.starts_with("file://")
        || trimmed.starts_with('/')
        || trimmed.starts_with("./")
    {
        if let Some((left, right)) = trimmed.split_once(".git/")
            && !left.ends_with('/')
        {
            (format!("{left}.git"), Some(normalize_subpath(right)?))
        } else {
            let has_file_scheme = trimmed.starts_with("file://");
            let fs_str = trimmed.strip_prefix("file://").unwrap_or(trimmed);
            let (cand_str, explicit_toml) = if let Some(s) = fs_str.strip_suffix("/dotler.toml") {
                (s, true)
            } else {
                (fs_str, false)
            };
            let cand_path = Path::new(cand_str);
            let mut found_split: Option<(String, String)> = None;
            if explicit_toml || !is_git_repo_dir(cand_path) {
                for anc in cand_path.ancestors() {
                    if is_git_repo_dir(anc) {
                        if let Ok(rel) = cand_path.strip_prefix(anc) {
                            let repo_str = if has_file_scheme {
                                format!("file://{}", anc.display())
                            } else {
                                anc.display().to_string()
                            };
                            found_split = Some((repo_str, rel.to_string_lossy().to_string()));
                        }
                        break;
                    }
                }
            }
            if let Some((repo_str, rel_str)) = found_split {
                (repo_str, Some(normalize_subpath(&rel_str)?))
            } else if explicit_toml {
                let repo_str = if has_file_scheme {
                    format!("file://{cand_str}")
                } else {
                    cand_str.to_string()
                };
                (repo_str, Some(String::new()))
            } else {
                (trimmed.to_string(), None)
            }
        }
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
        subpath,
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
            if is_symlink(&direct_file) {
                return Err(EngineError::HardBlockedPath {
                    path: direct_file,
                    reason: "symbolic links are prohibited inside a dotler repository".to_string(),
                });
            }
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
        if is_symlink(&target_file) {
            return Err(EngineError::HardBlockedPath {
                path: target_file,
                reason: "symbolic links are prohibited inside a dotler repository".to_string(),
            });
        }
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

struct DiscoveredManifest {
    rel_manifest_path: String,
    manifest_dir: PathBuf,
    config: RepoConfig,
}

fn load_and_validate_remote_manifest(
    toml_path: &Path,
    max_bytes: usize,
) -> Result<RepoConfig, EngineError> {
    if is_symlink(toml_path) {
        return Err(EngineError::HardBlockedPath {
            path: toml_path.to_path_buf(),
            reason: "symbolic links are prohibited inside a dotler repository".to_string(),
        });
    }
    let metadata = fs::metadata(toml_path)?;
    if metadata.len() as usize > max_bytes {
        return Err(EngineError::PayloadExceeded {
            size_bytes: metadata.len() as usize,
            limit_bytes: max_bytes,
        });
    }
    let raw_toml = fs::read(toml_path)?;
    let toml_str = String::from_utf8(raw_toml).map_err(|_| EngineError::GitError {
        operation: "fetch".to_string(),
        message: "dotler.toml is not valid UTF-8".to_string(),
    })?;
    let repo_config = RepoConfig::parse(&toml_str)?;
    repo_config.validate()?;
    Ok(repo_config)
}

fn discover_manifests_in_tree(
    repo_root: &Path,
    subpath: Option<&str>,
    raw_url: &str,
) -> Result<Vec<DiscoveredManifest>, EngineError> {
    validate_dir_no_symlinks(repo_root).map_err(|e| match e {
        crate::config::ConfigError::HardBlockedPath { path, reason } => {
            EngineError::HardBlockedPath {
                path: PathBuf::from(path),
                reason,
            }
        }
        other => EngineError::Config(other),
    })?;

    if let Some(sub) = subpath {
        let rel_dir = normalize_subpath(sub)?;
        let manifest_dir = if rel_dir.is_empty() {
            repo_root.to_path_buf()
        } else {
            repo_root.join(&rel_dir)
        };
        let toml_path = manifest_dir.join("dotler.toml");
        if !toml_path.is_file() {
            return Err(EngineError::MissingRemoteToml {
                url: raw_url.to_string(),
            });
        }
        let rel_manifest_path = if rel_dir.is_empty() {
            "dotler.toml".to_string()
        } else {
            format!("{rel_dir}/dotler.toml")
        };
        let config = load_and_validate_remote_manifest(&toml_path, REMOTE_TOML_FETCH_MAX_BYTES)?;
        return Ok(vec![DiscoveredManifest {
            rel_manifest_path,
            manifest_dir,
            config,
        }]);
    }

    let mut found_paths: Vec<(usize, String, PathBuf, PathBuf)> = Vec::new();
    for entry in walkdir::WalkDir::new(repo_root)
        .into_iter()
        .filter_entry(|e| e.file_name() != ".git")
    {
        let entry = entry.map_err(std::io::Error::from)?;
        if entry.file_type().is_file() && entry.file_name() == "dotler.toml" {
            let full_path = entry.path().to_path_buf();
            let manifest_dir = full_path.parent().unwrap_or(repo_root).to_path_buf();
            let rel_path = full_path
                .strip_prefix(repo_root)
                .unwrap_or(&full_path)
                .components()
                .map(|c| c.as_os_str().to_string_lossy())
                .collect::<Vec<_>>()
                .join("/");
            let depth = rel_path.matches('/').count();
            found_paths.push((depth, rel_path, manifest_dir, full_path));
        }
    }

    // Sort by BFS depth first (shallowest first), then Unicode code point order
    found_paths.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

    if found_paths.is_empty() {
        return Err(EngineError::MissingRemoteToml {
            url: raw_url.to_string(),
        });
    }

    let mut manifests = Vec::with_capacity(found_paths.len());
    for (_depth, rel_manifest_path, manifest_dir, toml_path) in found_paths {
        let config = load_and_validate_remote_manifest(&toml_path, REMOTE_TOML_FETCH_MAX_BYTES)?;
        manifests.push(DiscoveredManifest {
            rel_manifest_path,
            manifest_dir,
            config,
        });
    }

    Ok(manifests)
}

fn build_manifest_summary(m: &DiscoveredManifest) -> RemoteManifestSummary {
    let mut groups = Vec::new();
    for (group_name, group) in &m.config.groups {
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

    RemoteManifestSummary {
        path: m.rel_manifest_path.clone(),
        groups,
        has_vault: m.config.vault.is_some(),
        vault_id: m.config.vault.as_ref().map(|v| v.vault_id.clone()),
    }
}

pub fn list_remote(
    url: &RemoteRepoUrl,
    branch: Option<&str>,
    _lock: &DotlerLockGuard,
) -> Result<RemoteRepoSummary, EngineError> {
    let local_path = if let Some(stripped) = url.clone_url.strip_prefix("file://") {
        Path::new(stripped)
    } else {
        Path::new(&url.clone_url)
    };
    let is_bare = local_path.join("HEAD").is_file()
        && local_path.join("objects").is_dir()
        && !local_path.join(".git").exists();

    let discovered = if local_path.is_dir() && !is_bare && branch.is_none() {
        discover_manifests_in_tree(local_path, url.subpath.as_deref(), &url.raw)?
    } else {
        let temp_dir = TempDirGuard::new().map_err(EngineError::Io)?;
        GitRunner::clone_shallow(&url.clone_url, branch, temp_dir.path())?;
        discover_manifests_in_tree(temp_dir.path(), url.subpath.as_deref(), &url.raw)?
    };

    let manifests: Vec<RemoteManifestSummary> =
        discovered.iter().map(build_manifest_summary).collect();
    let primary = &manifests[0];

    Ok(RemoteRepoSummary {
        url: url.raw.clone(),
        groups: primary.groups.clone(),
        has_vault: primary.has_vault,
        vault_id: primary.vault_id.clone(),
        manifests,
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
    let discovered = discover_manifests_in_tree(&staging_dir, url.subpath.as_deref(), &url.raw)?;
    let primary = &discovered[0];
    let repo_config = &primary.config;
    let manifest_dir = &primary.manifest_dir;

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
        for entry in walkdir::WalkDir::new(manifest_dir).min_depth(1) {
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

    if manifest_dir == &staging_dir {
        fs::rename(&staging_dir, target_dir)?;
        cleanup.1 = false; // Disarm cleanup
    } else {
        if target_dir.exists() {
            let _ = fs::remove_dir(target_dir);
        }
        fs::rename(manifest_dir, target_dir)?;
        // Leave cleanup.1 = true so the outer staging_dir is removed on Drop
    }

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

        let home = resolve_home_for_state(state);
        validate_os_dir_path(&target_base, &home)?;

        let group_dir = manifest_dir.join(g_name);
        if !group_dir.is_dir() {
            continue;
        }

        let rules = parse_selection_rules(&group.files).unwrap_or_default();

        for entry in walkdir::WalkDir::new(&group_dir).min_depth(1) {
            let entry = entry.map_err(std::io::Error::from)?;
            if entry.file_type().is_symlink() || is_symlink(entry.path()) {
                return Err(EngineError::HardBlockedPath {
                    path: entry.path().to_path_buf(),
                    reason: "symbolic links are prohibited inside a dotler repository".to_string(),
                });
            }
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
            validate_os_target_path(&target_file_path, &home)?;
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
                    if target.is_file() || is_symlink(&target) {
                        let _ = fs::remove_file(&target);
                    }
                    state.remove_installed_file(&record.target_path)?;
                }
                removed_files.push(target);
            }
        } else {
            if !dry_run {
                if target.is_file() || is_symlink(&target) {
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
