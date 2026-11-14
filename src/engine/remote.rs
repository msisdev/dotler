//! Remote Git repository URL parsing, manifest discovery, and shallow inspection (`git ls`).

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::local::WalkDir;
use crate::config::repo::{RepoConfig, is_symlink, parse_selection_rules};
use crate::config::state::DotlerLockGuard;
use crate::engine::EngineError;
use crate::engine::git_transport::TempDirGuard;

pub use crate::engine::git_clone::{
    CloneReport, GroupSelector, STAGING_CLONE_PREFIX, clone_repo, clone_repo_with_observer,
    run_git_clone,
};
pub use crate::engine::git_install::{
    BACKUPS_DIR_NAME, InstallReport, PathOverride, UninstallReport, install_remote,
    install_remote_with_observer, run_git_install, run_git_uninstall, uninstall_remote,
    uninstall_remote_with_observer,
};
pub use crate::engine::git_transport::{GitRunner, fetch_http_text};

pub const REMOTE_TOML_FETCH_MAX_BYTES: usize = 1_048_576; // 1 MiB

/// Parsed Git remote URL with normalized clone URL and optional monorepo subpath.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteRepoUrl {
    pub raw: String,
    pub clone_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subpath: Option<String>,
}

/// Remote group metadata discovered in `dotler.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteGroupInfo {
    pub name: String,
    pub target_paths: BTreeMap<String, String>,
    pub has_encrypted: bool,
    pub files_rule: String,
}

/// Summary of one discovered `dotler.toml` manifest inside a remote repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteManifestSummary {
    pub path: String,
    pub groups: Vec<RemoteGroupInfo>,
    pub has_vault: bool,
    pub vault_id: Option<String>,
}

/// Summary returned by `git ls`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteRepoSummary {
    pub url: String,
    #[serde(default)]
    pub manifests: Vec<RemoteManifestSummary>,
    pub groups: Vec<RemoteGroupInfo>,
    pub has_vault: bool,
    pub vault_id: Option<String>,
}

pub(crate) struct DiscoveredManifest {
    pub(crate) rel_manifest_path: String,
    pub(crate) manifest_dir: PathBuf,
    pub(crate) config: RepoConfig,
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

fn parse_shorthand_slug(
    raw: &str,
    slug: &str,
    host_base: &str,
    append_dot_git: bool,
) -> Result<(String, Option<String>), EngineError> {
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
    let suffix = if append_dot_git { ".git" } else { "" };
    Ok((format!("{host_base}{repo_part}{suffix}"), sub_norm))
}

impl RemoteRepoUrl {
    /// Parses and normalizes a raw Git repository URL or shorthand (`gh:`/`github:`, `gl:`/`gitlab:`,
    /// `cb:`/`codeberg:`, `srht:`/`sourcehut:`, `bb:`/`bitbucket:`, `https://`, `http://`, `file://`).
    pub fn parse(raw: &str) -> Result<Self, EngineError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(EngineError::InvalidUrlFormat {
                url: raw.to_string(),
                reason: "URL cannot be empty".to_string(),
            });
        }

        let (clone_url, subpath) = if let Some(slug) = trimmed
            .strip_prefix("gh:")
            .or_else(|| trimmed.strip_prefix("github:"))
        {
            parse_shorthand_slug(raw, slug, "https://github.com/", true)?
        } else if let Some(slug) = trimmed
            .strip_prefix("gl:")
            .or_else(|| trimmed.strip_prefix("gitlab:"))
        {
            let clean = slug.trim_matches('/');
            if clean.is_empty() {
                return Err(EngineError::InvalidUrlFormat {
                    url: raw.to_string(),
                    reason: "Repository slug cannot be empty".to_string(),
                });
            }
            if let Some((repo_part, sub_part)) = clean.split_once(".git/") {
                (
                    format!("https://gitlab.com/{repo_part}.git"),
                    Some(normalize_subpath(sub_part)?),
                )
            } else if clean.ends_with("/dotler.toml") {
                let (repo_part, sub) = split_two_segment_slug(clean);
                let sub_norm = match sub {
                    Some(s) => Some(normalize_subpath(s)?),
                    None => Some(String::new()),
                };
                (format!("https://gitlab.com/{repo_part}.git"), sub_norm)
            } else {
                (
                    format!("https://gitlab.com/{}.git", clean.trim_end_matches(".git")),
                    None,
                )
            }
        } else if let Some(slug) = trimmed
            .strip_prefix("cb:")
            .or_else(|| trimmed.strip_prefix("codeberg:"))
        {
            parse_shorthand_slug(raw, slug, "https://codeberg.org/", true)?
        } else if let Some(slug) = trimmed
            .strip_prefix("srht:")
            .or_else(|| trimmed.strip_prefix("sourcehut:"))
        {
            parse_shorthand_slug(raw, slug, "https://git.sr.ht/", false)?
        } else if let Some(slug) = trimmed
            .strip_prefix("bb:")
            .or_else(|| trimmed.strip_prefix("bitbucket:"))
        {
            parse_shorthand_slug(raw, slug, "https://bitbucket.org/", true)?
        } else if trimmed.starts_with("https://") || trimmed.starts_with("http://") {
            parse_http_repo_url(trimmed)?
        } else if trimmed.starts_with("file://")
            || trimmed.starts_with('/')
            || trimmed.starts_with("./")
        {
            parse_local_repo_url(trimmed)?
        } else {
            return Err(EngineError::InvalidUrlFormat {
                url: trimmed.to_string(),
                reason: "Unrecognized URL scheme. Use gh:/github:, gl:/gitlab:, cb:/codeberg:, srht:/sourcehut:, bb:/bitbucket:, or https://"
                    .to_string(),
            });
        };

        Ok(RemoteRepoUrl {
            raw: trimmed.to_string(),
            clone_url,
            subpath,
        })
    }
}

fn parse_http_repo_url(trimmed: &str) -> Result<(String, Option<String>), EngineError> {
    if let Some((left, right)) = trimmed.split_once(".git/") {
        return Ok((format!("{left}.git"), Some(normalize_subpath(right)?)));
    }
    if let Some((scheme, rest)) = trimmed.split_once("://")
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
            return Ok((format!("{scheme}://{host}/{repo_part}.git"), sub_norm));
        }
        if trimmed.ends_with(".git") {
            return Ok((trimmed.to_string(), None));
        }
        return Ok((format!("{}.git", trimmed.trim_end_matches('/')), None));
    }
    if trimmed.ends_with(".git") {
        Ok((trimmed.to_string(), None))
    } else {
        Ok((format!("{trimmed}.git"), None))
    }
}

fn parse_local_repo_url(trimmed: &str) -> Result<(String, Option<String>), EngineError> {
    if let Some((left, right)) = trimmed.split_once(".git/")
        && !left.ends_with('/')
    {
        return Ok((format!("{left}.git"), Some(normalize_subpath(right)?)));
    }
    let has_file_scheme = trimmed.starts_with("file://");
    let fs_str = trimmed.strip_prefix("file://").unwrap_or(trimmed);
    let (cand_str, explicit_toml) = match fs_str.strip_suffix("/dotler.toml") {
        Some(s) => (s, true),
        None => (fs_str, false),
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
        Ok((repo_str, Some(normalize_subpath(&rel_str)?)))
    } else if explicit_toml {
        let repo_str = if has_file_scheme {
            format!("file://{cand_str}")
        } else {
            cand_str.to_string()
        };
        Ok((repo_str, Some(String::new())))
    } else {
        Ok((trimmed.to_string(), None))
    }
}

pub fn parse_url(raw: &str) -> Result<RemoteRepoUrl, EngineError> {
    RemoteRepoUrl::parse(raw)
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

pub(crate) fn discover_manifests_in_tree(
    repo_root: &Path,
    subpath: Option<&str>,
    raw_url: &str,
) -> Result<Vec<DiscoveredManifest>, EngineError> {
    crate::config::repo::validate_dir_no_symlinks(repo_root).map_err(|e| match e {
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
    for entry in WalkDir::new(repo_root).filter_entry(|e| e.file_name() != ".git") {
        let entry = entry?;
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

    // Sort by BFS depth first (shallowest first), then Unicode code point order.
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
    let groups = m
        .config
        .groups
        .iter()
        .map(|(group_name, group)| {
            let rules = parse_selection_rules(&group.files).unwrap_or_default();
            RemoteGroupInfo {
                name: group_name.clone(),
                target_paths: group.paths.clone(),
                has_encrypted: crate::config::repo::rules_have_effective_encryption(&rules),
                files_rule: group.files.clone(),
            }
        })
        .collect();

    RemoteManifestSummary {
        path: m.rel_manifest_path.clone(),
        groups,
        has_vault: m.config.vault.is_some(),
        vault_id: m.config.vault.as_ref().map(|v| v.vault_id.clone()),
    }
}

/// Inspects a remote repository cleanly without polluting persistent local configuration.
pub fn list_remote(
    url: &RemoteRepoUrl,
    branch: Option<&str>,
    _lock: &DotlerLockGuard,
) -> Result<RemoteRepoSummary, EngineError> {
    let local_path = Path::new(
        url.clone_url
            .strip_prefix("file://")
            .unwrap_or(&url.clone_url),
    );
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

/// High-level entry point for `dotler git ls` shared by CLI and MCP.
pub fn run_git_ls(
    url_raw: &str,
    branch: Option<&str>,
    lock: &DotlerLockGuard,
) -> Result<RemoteRepoSummary, EngineError> {
    let url = parse_url(url_raw)?;
    list_remote(&url, branch, lock)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shorthand_prefix_url_normalization() {
        let gh = parse_url("gh:user/repo").unwrap();
        assert_eq!(gh.clone_url, "https://github.com/user/repo.git");
        assert_eq!(gh.subpath, None);

        assert_eq!(
            parse_url("github:user/repo").unwrap().clone_url,
            "https://github.com/user/repo.git"
        );
        assert_eq!(
            parse_url("gl:user/repo").unwrap().clone_url,
            "https://gitlab.com/user/repo.git"
        );
        assert_eq!(
            parse_url("gitlab:user/repo").unwrap().clone_url,
            "https://gitlab.com/user/repo.git"
        );
        assert_eq!(
            parse_url("cb:user/repo").unwrap().clone_url,
            "https://codeberg.org/user/repo.git"
        );
        assert_eq!(
            parse_url("codeberg:user/repo").unwrap().clone_url,
            "https://codeberg.org/user/repo.git"
        );
        assert_eq!(
            parse_url("srht:~user/repo").unwrap().clone_url,
            "https://git.sr.ht/~user/repo"
        );
        assert_eq!(
            parse_url("sourcehut:~user/repo").unwrap().clone_url,
            "https://git.sr.ht/~user/repo"
        );
        assert_eq!(
            parse_url("bb:user/repo").unwrap().clone_url,
            "https://bitbucket.org/user/repo.git"
        );
        assert_eq!(
            parse_url("bitbucket:user/repo").unwrap().clone_url,
            "https://bitbucket.org/user/repo.git"
        );

        assert!(parse_url("").is_err());
        assert!(parse_url("invalid:scheme").is_err());
    }
}
