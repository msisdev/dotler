//! Remote Git repository engine.
//!
//! Provides remote URL normalization, shallow inspection (`git ls`),
//! staging clone with Re-Keying (`git clone`), Write-Ahead Logging installation
//! (`git install`), and sequential rollback restoration (`git uninstall`).

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

use serde::{Deserialize, Serialize};

use crate::config::local::{LocalConfig, WalkDir, expand_tilde};
use crate::config::repo::{
    OsInfo, RepoConfig, SelectionMode, evaluate_selection, is_symlink, parse_selection_rules,
    resolve_group_target_path, validate_dir_no_symlinks, validate_os_dir_path,
    validate_os_target_path, validate_path_security,
};
use crate::config::state::{
    BACKUPS_DIR_PATH, DotlerLockGuard, InstalledFileRecord, StateDb, write_file_safe,
};
use crate::core::context::CoreContext;
use crate::crypto::ExposeSecret;
use crate::crypto::vault::{EncryptedFile, VaultKey};
use crate::engine::EngineError;
use crate::engine::observer::{
    CommandObserver, NoopObserver, PlanActionKind, PlanDirection, PlanPreviewEntry,
};

struct TempDirGuard(PathBuf);

impl TempDirGuard {
    fn new() -> Result<Self, std::io::Error> {
        let rand_id: u64 = crate::crypto::random_u64();
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
        } else if let Some(slug) = trimmed
            .strip_prefix("cb:")
            .or_else(|| trimmed.strip_prefix("codeberg:"))
        {
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
        } else if let Some(slug) = trimmed
            .strip_prefix("srht:")
            .or_else(|| trimmed.strip_prefix("sourcehut:"))
        {
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
        } else if let Some(slug) = trimmed
            .strip_prefix("bb:")
            .or_else(|| trimmed.strip_prefix("bitbucket:"))
        {
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
                let (cand_str, explicit_toml) = if let Some(s) = fs_str.strip_suffix("/dotler.toml")
                {
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

pub fn parse_url(raw: &str) -> Result<RemoteRepoUrl, EngineError> {
    RemoteRepoUrl::parse(raw)
}

#[derive(Default)]
struct UreqGitHttp {
    redirected_base: Option<String>,
}

impl UreqGitHttp {
    fn effective_url(&self, base_url: &str, mut url: String) -> String {
        if let Some(effective_base) = &self.redirected_base {
            url.replace_range(..base_url.len(), effective_base);
        }
        url
    }
}

impl gix_transport::client::blocking_io::http::Http for UreqGitHttp {
    type Headers = gix::features::io::pipe::Reader;
    type ResponseBody = gix::features::io::pipe::Reader;
    type PostBody = gix::features::io::pipe::Writer;

    fn get(
        &mut self,
        url: &str,
        base_url: &str,
        headers: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Result<
        gix_transport::client::blocking_io::http::GetResponse<Self::Headers, Self::ResponseBody>,
        gix_transport::client::blocking_io::http::Error,
    > {
        use gix::features::io::pipe;
        use gix_transport::client::blocking_io::http::{Error as HttpError, GetResponse};

        let effective_url = self.effective_url(base_url, url.to_owned());
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(std::time::Duration::from_secs(30)))
            .http_status_as_error(false)
            .build();
        let agent: ureq::Agent = config.into();
        let mut req = agent.get(&effective_url);
        for h in headers {
            if let Some((k, v)) = h.as_ref().split_once(':') {
                req = req.header(k.trim(), v.trim());
            }
        }

        let res = req.call().map_err(|e| HttpError::InitHttpClient {
            source: Box::new(e),
        })?;
        let status = res.status().as_u16();
        if !(200..300).contains(&status) {
            let kind = if status == 401 {
                std::io::ErrorKind::PermissionDenied
            } else {
                std::io::ErrorKind::Other
            };
            return Err(HttpError::PostBody(std::io::Error::new(
                kind,
                format!("HTTP status {status}"),
            )));
        }

        let (mut headers_tx, headers_rx) = pipe::unidirectional(1);
        let (mut body_tx, body_rx) = pipe::unidirectional(0);

        let mut header_bytes = Vec::new();
        for (name, val) in res.headers() {
            if let Ok(v_str) = val.to_str() {
                let _ = writeln!(header_bytes, "{}:{v_str}", name.as_str());
            }
        }
        if !header_bytes.is_empty() {
            let _ = headers_tx.write_all(&header_bytes);
        }
        drop(headers_tx);

        let mut reader = res.into_body().into_reader();
        std::thread::spawn(move || {
            if let Err(e) = std::io::copy(&mut reader, &mut body_tx) {
                let _ = body_tx.channel.send(Err(e));
            }
        });

        Ok(GetResponse {
            headers: headers_rx,
            body: body_rx,
        })
    }

    fn post(
        &mut self,
        url: &str,
        base_url: &str,
        headers: impl IntoIterator<Item = impl AsRef<str>>,
        _body: gix_transport::client::blocking_io::http::PostBodyDataKind,
    ) -> Result<
        gix_transport::client::blocking_io::http::PostResponse<
            Self::Headers,
            Self::ResponseBody,
            Self::PostBody,
        >,
        gix_transport::client::blocking_io::http::Error,
    > {
        use gix::features::io::pipe;
        use gix_transport::client::blocking_io::http::PostResponse;

        let effective_url = self.effective_url(base_url, url.to_owned());
        let header_list: Vec<(String, String)> = headers
            .into_iter()
            .filter_map(|h| {
                h.as_ref()
                    .split_once(':')
                    .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
            })
            .collect();

        let (post_body_tx, mut post_body_rx) = pipe::unidirectional(0);
        let (mut headers_tx, headers_rx) = pipe::unidirectional(1);
        let (mut body_tx, body_rx) = pipe::unidirectional(0);

        std::thread::spawn(move || {
            let mut upload_buf = Vec::new();
            if let Err(e) = post_body_rx.read_to_end(&mut upload_buf) {
                let _ = headers_tx.channel.send(Err(e));
                return;
            }
            let config = ureq::Agent::config_builder()
                .timeout_global(Some(std::time::Duration::from_secs(30)))
                .http_status_as_error(false)
                .build();
            let agent: ureq::Agent = config.into();
            let mut req = agent.post(&effective_url);
            for (k, v) in &header_list {
                req = req.header(k, v);
            }
            let res = match req.send(&upload_buf[..]) {
                Ok(r) => r,
                Err(e) => {
                    let _ = headers_tx.channel.send(Err(std::io::Error::other(e)));
                    return;
                }
            };
            let status = res.status().as_u16();
            if !(200..300).contains(&status) {
                let kind = if status == 401 {
                    std::io::ErrorKind::PermissionDenied
                } else {
                    std::io::ErrorKind::Other
                };
                let _ = headers_tx.channel.send(Err(std::io::Error::new(
                    kind,
                    format!("HTTP status {status}"),
                )));
                return;
            }
            let mut header_bytes = Vec::new();
            for (name, val) in res.headers() {
                if let Ok(v_str) = val.to_str() {
                    let _ = writeln!(header_bytes, "{}:{v_str}", name.as_str());
                }
            }
            if !header_bytes.is_empty() {
                let _ = headers_tx.write_all(&header_bytes);
            }
            drop(headers_tx);

            let mut reader = res.into_body().into_reader();
            if let Err(e) = std::io::copy(&mut reader, &mut body_tx) {
                let _ = body_tx.channel.send(Err(e));
            }
        });

        Ok(PostResponse {
            post_body: post_body_tx,
            headers: headers_rx,
            body: body_rx,
        })
    }

    fn configure(
        &mut self,
        _config: &dyn std::any::Any,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        Ok(())
    }

    fn redirected_base_url(&self) -> Option<String> {
        self.redirected_base.clone()
    }
}

fn materialize_tree_to_dir(
    repo: &gix::Repository,
    tree_id: gix::ObjectId,
    dest: &Path,
) -> Result<(), EngineError> {
    fs::create_dir_all(dest)?;
    let tree = repo
        .find_object(tree_id)
        .map_err(|e| EngineError::GitError {
            operation: "checkout".to_string(),
            message: format!("Failed to read tree object: {e}"),
        })?
        .try_into_tree()
        .map_err(|e| EngineError::GitError {
            operation: "checkout".to_string(),
            message: format!("Object is not a git tree: {e}"),
        })?;

    for entry_res in tree.iter() {
        let entry = entry_res.map_err(|e| EngineError::GitError {
            operation: "checkout".to_string(),
            message: format!("Failed to decode tree entry: {e}"),
        })?;
        let name = std::str::from_utf8(entry.filename()).map_err(|_| EngineError::GitError {
            operation: "checkout".to_string(),
            message: "Tree entry filename is not valid UTF-8".to_string(),
        })?;
        if name == ".git" || name.contains('/') || name.contains('\\') || name == ".." {
            continue;
        }
        let target_path = dest.join(name);
        match entry.mode().kind() {
            gix::objs::tree::EntryKind::Tree => {
                materialize_tree_to_dir(repo, entry.oid().to_owned(), &target_path)?;
            }
            gix::objs::tree::EntryKind::Blob | gix::objs::tree::EntryKind::BlobExecutable => {
                let obj = repo
                    .find_object(entry.oid())
                    .map_err(|e| EngineError::GitError {
                        operation: "checkout".to_string(),
                        message: format!("Failed to read blob object: {e}"),
                    })?;
                fs::write(&target_path, &obj.data)?;
                #[cfg(unix)]
                if entry.mode().kind() == gix::objs::tree::EntryKind::BlobExecutable {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = fs::set_permissions(&target_path, fs::Permissions::from_mode(0o755));
                }
            }
            gix::objs::tree::EntryKind::Link => {
                let obj = repo
                    .find_object(entry.oid())
                    .map_err(|e| EngineError::GitError {
                        operation: "checkout".to_string(),
                        message: format!("Failed to read symlink object: {e}"),
                    })?;
                let link_target =
                    std::str::from_utf8(&obj.data).map_err(|_| EngineError::GitError {
                        operation: "checkout".to_string(),
                        message: "Symlink target is not valid UTF-8".to_string(),
                    })?;
                #[cfg(unix)]
                {
                    std::os::unix::fs::symlink(link_target, &target_path)?;
                }
                #[cfg(windows)]
                {
                    let _ = std::os::windows::fs::symlink_file(link_target, &target_path);
                }
            }
            gix::objs::tree::EntryKind::Commit => {}
        }
    }
    Ok(())
}

/// Fetches a UTF-8 text payload (such as `dotler.toml` or JSON vault config) over HTTP/HTTPS GET
/// (or `file://` for local fixtures) within `max_bytes` using pure-Rust `ureq`.
pub fn fetch_http_text(url: &str, max_bytes: usize) -> Result<String, EngineError> {
    let trimmed = url.trim();
    if let Some(file_path) = trimmed.strip_prefix("file://") {
        let p = Path::new(file_path);
        if is_symlink(p) {
            return Err(EngineError::HardBlockedPath {
                path: p.to_path_buf(),
                reason: "symbolic links are prohibited".to_string(),
            });
        }
        let metadata = fs::metadata(p).map_err(|e| EngineError::GitError {
            operation: "http-get".to_string(),
            message: format!("Failed to read '{}': {e}", p.display()),
        })?;
        if metadata.len() as usize > max_bytes {
            return Err(EngineError::PayloadExceeded {
                size_bytes: metadata.len() as usize,
                limit_bytes: max_bytes,
            });
        }
        let bytes = fs::read(p)?;
        return String::from_utf8(bytes).map_err(|_| EngineError::GitError {
            operation: "http-get".to_string(),
            message: "Response payload is not valid UTF-8".to_string(),
        });
    }

    if !trimmed.starts_with("https://") && !trimmed.starts_with("http://") {
        return Err(EngineError::InvalidUrlFormat {
            url: trimmed.to_string(),
            reason: "Expected an http:// or https:// URL".to_string(),
        });
    }

    let config = ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(20)))
        .build();
    let agent: ureq::Agent = config.into();
    let response = agent
        .get(trimmed)
        .header("User-Agent", concat!("dotler/", env!("CARGO_PKG_VERSION")))
        .header(
            "Accept",
            "application/toml, application/json, text/plain, */*",
        )
        .call()
        .map_err(|e| EngineError::GitError {
            operation: "http-get".to_string(),
            message: format!("HTTP GET request to '{trimmed}' failed: {e}"),
        })?;

    let mut reader = response
        .into_body()
        .into_reader()
        .take((max_bytes + 1) as u64);
    let mut buf = Vec::new();
    reader
        .read_to_end(&mut buf)
        .map_err(|e| EngineError::GitError {
            operation: "http-get".to_string(),
            message: format!("Failed to read HTTP response body: {e}"),
        })?;
    if buf.len() > max_bytes {
        return Err(EngineError::PayloadExceeded {
            size_bytes: buf.len(),
            limit_bytes: max_bytes,
        });
    }

    String::from_utf8(buf).map_err(|_| EngineError::GitError {
        operation: "http-get".to_string(),
        message: "HTTP response body is not valid UTF-8".to_string(),
    })
}

pub struct GitRunner;

impl GitRunner {
    pub fn clone_shallow(url: &str, branch: Option<&str>, dest: &Path) -> Result<(), EngineError> {
        let local_candidate = if let Some(stripped) = url.strip_prefix("file://") {
            Some(Path::new(stripped))
        } else if !url.contains("://") {
            Some(Path::new(url))
        } else {
            None
        };

        if let Some(local_path) = local_candidate {
            if !local_path.exists() {
                return Err(EngineError::GitError {
                    operation: "clone".to_string(),
                    message: format!(
                        "Local git repository '{}' does not exist",
                        local_path.display()
                    ),
                });
            }
            let src_repo = gix::open(local_path).map_err(|e| EngineError::GitError {
                operation: "clone".to_string(),
                message: format!(
                    "Failed to open git repository '{}': {e}",
                    local_path.display()
                ),
            })?;

            let commit_id = if let Some(b) = branch {
                let ref_name = format!("refs/heads/{b}");
                let mut r = src_repo
                    .find_reference(&ref_name)
                    .or_else(|_| src_repo.find_reference(b))
                    .map_err(|e| EngineError::GitError {
                        operation: "clone".to_string(),
                        message: format!("Branch '{b}' not found: {e}"),
                    })?;
                r.peel_to_id()
                    .map_err(|e| EngineError::GitError {
                        operation: "clone".to_string(),
                        message: format!("Failed to peel branch '{b}': {e}"),
                    })?
                    .detach()
            } else {
                src_repo
                    .head_id()
                    .map_err(|e| EngineError::GitError {
                        operation: "clone".to_string(),
                        message: format!("Failed to resolve HEAD: {e}"),
                    })?
                    .detach()
            };

            let tree_id = src_repo
                .find_object(commit_id)
                .map_err(|e| EngineError::GitError {
                    operation: "clone".to_string(),
                    message: format!("Failed to find commit {commit_id}: {e}"),
                })?
                .peel_to_tree()
                .map_err(|e| EngineError::GitError {
                    operation: "clone".to_string(),
                    message: format!("Failed to peel commit {commit_id} to tree: {e}"),
                })?
                .id;

            fs::create_dir_all(dest)?;
            let _ = gix::init(dest);
            materialize_tree_to_dir(&src_repo, tree_id, dest)?;
            return Ok(());
        }

        fs::create_dir_all(dest)?;
        let repo = gix::init(dest).map_err(|e| EngineError::GitError {
            operation: "clone".to_string(),
            message: format!("Failed to initialize staging repository: {e}"),
        })?;

        let refspec = match branch {
            Some(b) => format!("+refs/heads/{b}:refs/remotes/origin/{b}"),
            None => "+HEAD:refs/remotes/origin/HEAD".to_string(),
        };
        let remote = repo
            .remote_at(url)
            .map_err(|e| EngineError::GitError {
                operation: "clone".to_string(),
                message: format!("Invalid remote URL '{url}': {e}"),
            })?
            .with_fetch_tags(gix::remote::fetch::Tags::None)
            .with_refspecs(Some(refspec.as_str()), gix::remote::Direction::Fetch)
            .map_err(|e| EngineError::GitError {
                operation: "clone".to_string(),
                message: format!("Invalid refspec '{refspec}': {e}"),
            })?;

        let (sanitized_url, version) = remote
            .sanitized_url_and_version(gix::remote::Direction::Fetch)
            .map_err(|e| EngineError::GitError {
                operation: "clone".to_string(),
                message: format!("Failed to prepare remote URL '{url}': {e}"),
            })?;

        let transport = gix_transport::client::blocking_io::http::connect_http(
            UreqGitHttp::default(),
            sanitized_url,
            version,
            false,
        );
        let connection = remote.to_connection_with_transport(transport);
        let should_interrupt = AtomicBool::new(false);
        let depth = std::num::NonZeroU32::new(1).expect("non-zero");
        let outcome = connection
            .prepare_fetch(&mut gix::progress::Discard, Default::default())
            .map_err(|e| EngineError::GitError {
                operation: "clone".to_string(),
                message: format!("Failed to connect to '{url}': {e}"),
            })?
            .with_shallow(gix::remote::fetch::Shallow::DepthAtRemote(depth))
            .receive(&mut gix::progress::Discard, &should_interrupt)
            .map_err(|e| EngineError::GitError {
                operation: "clone".to_string(),
                message: format!("Failed to fetch pack from '{url}': {e}"),
            })?;

        let commit_id = outcome
            .ref_map
            .mappings
            .iter()
            .find_map(|m| m.remote.as_id().map(|id| id.to_owned()))
            .ok_or_else(|| EngineError::GitError {
                operation: "clone".to_string(),
                message: format!("No commit found on remote '{url}'"),
            })?;

        let tree_id = repo
            .find_object(commit_id)
            .map_err(|e| EngineError::GitError {
                operation: "clone".to_string(),
                message: format!("Failed to find fetched commit {commit_id}: {e}"),
            })?
            .peel_to_tree()
            .map_err(|e| EngineError::GitError {
                operation: "clone".to_string(),
                message: format!("Failed to peel fetched commit {commit_id} to tree: {e}"),
            })?
            .id;

        materialize_tree_to_dir(&repo, tree_id, dest)?;
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
        let has_encrypted = crate::config::repo::rules_have_effective_encryption(&rules);

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
    lock: &DotlerLockGuard,
) -> Result<CloneReport, EngineError> {
    let mut noop = NoopObserver;
    clone_repo_with_observer(
        url,
        selectors,
        branch,
        target_dir,
        local_config_path,
        remote_vault_key,
        local_vault_key,
        lock,
        false,
        &mut noop,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn clone_repo_with_observer(
    url: &RemoteRepoUrl,
    selectors: &[GroupSelector],
    branch: Option<&str>,
    target_dir: &Path,
    local_config_path: Option<&Path>,
    remote_vault_key: Option<&VaultKey>,
    local_vault_key: Option<&VaultKey>,
    _lock: &DotlerLockGuard,
    dry_run: bool,
    observer: &mut dyn CommandObserver,
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

    let rand_id: u32 = crate::crypto::random_u32();
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

    let selected_pairs: Vec<(String, String)> = if selectors.is_empty() {
        repo_config
            .groups
            .keys()
            .map(|k| (k.clone(), k.clone()))
            .collect()
    } else {
        for sel in selectors {
            if !repo_config.groups.contains_key(&sel.remote_group) {
                return Err(EngineError::GroupNotFound {
                    group: sel.remote_group.clone(),
                    available: repo_config.groups.keys().cloned().collect(),
                });
            }
        }
        selectors
            .iter()
            .map(|s| {
                let effective = s
                    .local_alias
                    .clone()
                    .unwrap_or_else(|| s.remote_group.clone());
                (s.remote_group.clone(), effective)
            })
            .collect()
    };
    let selected_groups: Vec<String> = selected_pairs.iter().map(|(_, eff)| eff.clone()).collect();

    for (remote_name, _) in &selected_pairs {
        let group = &repo_config.groups[remote_name];
        for path in group.paths.values() {
            validate_path_security(path)?;
        }
    }

    let mut preview_entries: Vec<PlanPreviewEntry> = Vec::new();
    let mut clone_files: Vec<(String, PathBuf, String, u64)> = Vec::new();
    for (remote_name, effective_name) in &selected_pairs {
        let g_dir = manifest_dir.join(remote_name);
        if g_dir.is_dir() {
            for entry in WalkDir::new(&g_dir).min_depth(1) {
                let entry = entry?;
                if entry.file_type().is_file() {
                    let rel = entry
                        .path()
                        .strip_prefix(&g_dir)
                        .unwrap_or(entry.path())
                        .to_string_lossy()
                        .to_string();
                    let is_enc = entry.path().extension().and_then(|s| s.to_str()) == Some("enc");
                    let size = fs::metadata(entry.path()).map(|m| m.len()).unwrap_or(0);
                    preview_entries.push(PlanPreviewEntry {
                        group_name: effective_name.clone(),
                        os_path: PathBuf::from(format!("{}/{}/{}", url.raw, remote_name, rel)),
                        os_action: PlanActionKind::Okay,
                        repo_path: target_dir.join(effective_name).join(&rel),
                        repo_action: PlanActionKind::Create,
                        direction: if is_enc {
                            PlanDirection::EncryptToRepo
                        } else {
                            PlanDirection::PlainToRepo
                        },
                    });
                    clone_files.push((
                        effective_name.clone(),
                        target_dir.join(effective_name),
                        rel,
                        size,
                    ));
                }
            }
        }
    }

    if preview_entries.is_empty() {
        let fallback_group = selected_groups
            .first()
            .cloned()
            .unwrap_or_else(|| "repo".to_string());
        preview_entries.push(PlanPreviewEntry {
            group_name: fallback_group.clone(),
            os_path: PathBuf::from(format!("{}/dotler.toml", url.raw)),
            os_action: PlanActionKind::Okay,
            repo_path: target_dir.join("dotler.toml"),
            repo_action: PlanActionKind::Create,
            direction: PlanDirection::PlainToRepo,
        });
        clone_files.push((
            fallback_group,
            target_dir.to_path_buf(),
            "dotler.toml".to_string(),
            0,
        ));
    }

    let approved = observer.confirm_plan(&preview_entries, dry_run)?;
    if dry_run {
        return Ok(CloneReport {
            repo_url: url.raw.clone(),
            destination: target_dir.to_path_buf(),
            cloned_groups: selected_groups,
        });
    }
    if !approved {
        return Ok(CloneReport {
            repo_url: url.raw.clone(),
            destination: target_dir.to_path_buf(),
            cloned_groups: Vec::new(),
        });
    }

    // Apply selective group pruning and local_alias renaming inside manifest_dir before moving
    if !selectors.is_empty() {
        for remote_group in repo_config.groups.keys() {
            if !selected_pairs.iter().any(|(r, _)| r == remote_group) {
                let unselected_dir = manifest_dir.join(remote_group);
                if unselected_dir.is_dir() {
                    let _ = fs::remove_dir_all(&unselected_dir);
                }
            }
        }
        for (remote_name, effective_name) in &selected_pairs {
            if remote_name != effective_name {
                let src_dir = manifest_dir.join(remote_name);
                let dst_dir = manifest_dir.join(effective_name);
                if src_dir.is_dir() {
                    fs::rename(&src_dir, &dst_dir)?;
                }
            }
        }
        let mut new_groups = BTreeMap::new();
        for (remote_name, effective_name) in &selected_pairs {
            if let Some(cfg) = repo_config.groups.get(remote_name) {
                new_groups.insert(effective_name.clone(), cfg.clone());
            }
        }
        let updated_cfg = RepoConfig {
            vault: repo_config.vault.clone(),
            groups: new_groups,
        };
        if let Ok(serialized) = toml::to_string_pretty(&updated_cfg) {
            write_file_safe(&manifest_dir.join("dotler.toml"), serialized.as_bytes())?;
        }
    }

    // In-Memory Re-Keying if local vault exists and remote vault is different
    if let (Some(r_key), Some(l_key)) = (remote_vault_key, local_vault_key)
        && r_key.vault_id() != l_key.vault_id()
    {
        for entry in WalkDir::new(manifest_dir).min_depth(1) {
            let entry = entry?;
            if entry.file_type().is_file()
                && entry.path().extension().and_then(|s| s.to_str()) == Some("enc")
            {
                let enc_bytes = fs::read(entry.path())?;
                let enc_file = EncryptedFile::from_bytes(&enc_bytes)?;
                let decrypted = r_key.decrypt_file(&enc_file)?;
                let re_encrypted = l_key.encrypt_file(decrypted.expose_secret())?;
                write_file_safe(entry.path(), &re_encrypted.to_bytes())?;
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

    let total = clone_files.len();
    for (g_name, g_base, rel, size) in &clone_files {
        observer.on_file_progress(g_name, g_base, rel, Some(*size));
    }
    if total > 0 {
        observer.finish_progress();
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
        let home = std::env::home_dir().unwrap_or_else(|| PathBuf::from("~"));
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
        if local_config.default_repo.is_none() {
            local_config.default_repo = Some(label.clone());
        }
        if local_config.default_devices.is_empty() {
            local_config.default_devices.push("default".to_string());
        }
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

struct PlannedInstallFile {
    group_name: String,
    target_base: PathBuf,
    source_path: PathBuf,
    clean_rel: String,
    target_file_path: PathBuf,
}

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
    let mut planned = Vec::new();
    let mut preview_entries = Vec::new();

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

            let rel_path = entry.path().strip_prefix(&group_dir).unwrap();
            let rel_path_str = rel_path.to_string_lossy().to_string();

            let is_enc = rel_path_str.ends_with(".enc");
            let clean_rel = if let Some(stripped) = rel_path_str.strip_suffix(".enc") {
                stripped.to_string()
            } else {
                rel_path_str.clone()
            };

            if !rules.is_empty()
                && matches!(
                    evaluate_selection(&rules, &clean_rel)
                        .or_else(|| evaluate_selection(&rules, &rel_path_str)),
                    None | Some(SelectionMode::Exclude)
                )
            {
                continue;
            }

            let target_file_path = target_base.join(&clean_rel);
            validate_os_target_path(&target_file_path, &home)?;

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

    let mut installed_files = Vec::new();
    let mut backed_up_files = Vec::new();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let total = planned.len();

    for item in planned {
        let target_str = item.target_file_path.to_string_lossy().to_string();

        // 1. Check existing installed_files record to preserve original backup
        let existing = state.get_installed_file(&target_str)?;
        let backup_path: Option<String> = if let Some(ref ext) = existing {
            ext.backup_path.clone()
        } else if item.target_file_path.is_file() {
            let bp = create_backup_file(&item.target_file_path, &item.clean_rel, timestamp, state)?;
            backed_up_files.push(PathBuf::from(&bp));
            Some(bp)
        } else {
            None
        };

        // 2. Read source payload
        let file_content = fs::read(&item.source_path)?;
        let hash = blake3::hash(&file_content).to_hex().to_string();

        // 3. Sequential Write-Ahead commit to SQLite
        let record = InstalledFileRecord {
            target_path: target_str.clone(),
            repo_url: url.clone_url.clone(),
            group_name: item.group_name.clone(),
            relative_path: item.clean_rel.clone(),
            file_hash: hash,
            updated_at: timestamp,
            backup_path,
        };
        state.upsert_installed_file(&record)?;

        // 4. Atomic file deployment
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

pub fn uninstall_remote(
    groups: &[String],
    state: &StateDb,
    lock: &DotlerLockGuard,
    dry_run: bool,
) -> Result<UninstallReport, EngineError> {
    let mut noop = NoopObserver;
    uninstall_remote_with_observer(groups, state, lock, dry_run, &mut noop)
}

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

        if let Some(ref bp_str) = record.backup_path {
            let bp = PathBuf::from(bp_str);
            if bp.is_file() {
                if !dry_run {
                    let backup_bytes = fs::read(&bp)?;
                    write_file_safe(&target, &backup_bytes)?;
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

/// High-level entry point for `dotler git ls` shared by CLI and MCP.
pub fn run_git_ls(
    url_raw: &str,
    branch: Option<&str>,
    lock: &DotlerLockGuard,
) -> Result<RemoteRepoSummary, EngineError> {
    let url = parse_url(url_raw)?;
    list_remote(&url, branch, lock)
}

/// High-level entry point for `dotler git clone` shared by CLI and MCP.
#[allow(clippy::too_many_arguments)]
pub fn run_git_clone(
    url_raw: &str,
    selectors: &[GroupSelector],
    branch: Option<&str>,
    target_dir: &Path,
    local_config_path: Option<&Path>,
    remote_vault_key: Option<&VaultKey>,
    local_vault_key: Option<&VaultKey>,
    lock: &DotlerLockGuard,
    dry_run: bool,
    observer: &mut dyn CommandObserver,
) -> Result<CloneReport, EngineError> {
    let url = parse_url(url_raw)?;
    clone_repo_with_observer(
        &url,
        selectors,
        branch,
        target_dir,
        local_config_path,
        remote_vault_key,
        local_vault_key,
        lock,
        dry_run,
        observer,
    )
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shorthand_prefix_url_normalization() {
        let gh = parse_url("gh:user/repo").unwrap();
        assert_eq!(gh.clone_url, "https://github.com/user/repo.git");
        assert_eq!(gh.subpath, None);

        let github = parse_url("github:user/repo").unwrap();
        assert_eq!(github.clone_url, "https://github.com/user/repo.git");

        let gl = parse_url("gl:user/repo").unwrap();
        assert_eq!(gl.clone_url, "https://gitlab.com/user/repo.git");

        let gitlab = parse_url("gitlab:user/repo").unwrap();
        assert_eq!(gitlab.clone_url, "https://gitlab.com/user/repo.git");

        let cb = parse_url("cb:user/repo").unwrap();
        assert_eq!(cb.clone_url, "https://codeberg.org/user/repo.git");

        let codeberg = parse_url("codeberg:user/repo").unwrap();
        assert_eq!(codeberg.clone_url, "https://codeberg.org/user/repo.git");

        let srht = parse_url("srht:~user/repo").unwrap();
        assert_eq!(srht.clone_url, "https://git.sr.ht/~user/repo");

        let sourcehut = parse_url("sourcehut:~user/repo").unwrap();
        assert_eq!(sourcehut.clone_url, "https://git.sr.ht/~user/repo");

        let bb = parse_url("bb:user/repo").unwrap();
        assert_eq!(bb.clone_url, "https://bitbucket.org/user/repo.git");

        let bitbucket = parse_url("bitbucket:user/repo").unwrap();
        assert_eq!(bitbucket.clone_url, "https://bitbucket.org/user/repo.git");

        assert!(parse_url("").is_err());
        assert!(parse_url("invalid:scheme").is_err());
    }

    #[test]
    fn test_ureq_git_http_get_and_post_headers_do_not_deadlock() {
        use gix_transport::client::blocking_io::http::{Http, PostBodyDataKind};
        use std::io::BufRead;
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = std::thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                let response = concat!(
                    "HTTP/1.1 200 OK\r\n",
                    "Content-Type: application/x-git-upload-pack-advertisement\r\n",
                    "Cache-Control: no-cache\r\n",
                    "X-Custom-Header: value\r\n",
                    "Content-Length: 4\r\n",
                    "Connection: close\r\n",
                    "\r\n",
                    "0000"
                );
                stream.write_all(response.as_bytes()).unwrap();
                stream.flush().unwrap();
            }
        });

        let base_url = format!("http://{addr}/repo.git");
        let get_url = format!("{base_url}/info/refs?service=git-upload-pack");
        let post_url = format!("{base_url}/git-upload-pack");

        let mut http = UreqGitHttp::default();
        let mut get_res = http
            .get(&get_url, &base_url, ["User-Agent: dotler-test"])
            .unwrap();
        let get_headers: Vec<String> = get_res.headers.lines().map(|l| l.unwrap()).collect();
        assert!(get_headers.iter().any(|h| h.contains("application/x-git-upload-pack-advertisement")));
        let mut get_body = String::new();
        get_res.body.read_to_string(&mut get_body).unwrap();
        assert_eq!(get_body, "0000");

        let mut post_res = http
            .post(
                &post_url,
                &base_url,
                ["Content-Type: application/x-git-upload-pack-request"],
                PostBodyDataKind::BoundedAndFitsIntoMemory,
            )
            .unwrap();
        post_res.post_body.write_all(b"0000").unwrap();
        drop(post_res.post_body);
        let post_headers: Vec<String> = post_res.headers.lines().map(|l| l.unwrap()).collect();
        assert!(post_headers.iter().any(|h| h.contains("application/x-git-upload-pack-advertisement")));
        let mut post_body = String::new();
        post_res.body.read_to_string(&mut post_body).unwrap();
        assert_eq!(post_body, "0000");

        server.join().unwrap();
    }
}
