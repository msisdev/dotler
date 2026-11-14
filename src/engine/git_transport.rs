//! Shallow Git clone transport and bounded HTTP payload fetching.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use crate::config::repo::is_symlink;
use crate::engine::EngineError;

/// RAII temporary directory deleted on drop.
pub(crate) struct TempDirGuard(PathBuf);

impl TempDirGuard {
    pub(crate) fn new() -> Result<Self, std::io::Error> {
        let rand_id: u64 = crate::crypto::random_u64();
        let path = std::env::temp_dir().join(format!(".dotler-tmp-{rand_id:016x}"));
        fs::create_dir_all(&path)?;
        Ok(Self(path))
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
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

fn build_http_agent(timeout_secs: u64, http_status_as_error: bool) -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(timeout_secs)))
        .http_status_as_error(http_status_as_error)
        .build()
        .into()
}

fn http_status_io_error(status: u16) -> std::io::Error {
    let kind = if status == 401 {
        std::io::ErrorKind::PermissionDenied
    } else {
        std::io::ErrorKind::Other
    };
    std::io::Error::new(kind, format!("HTTP status {status}"))
}

fn pipe_ureq_headers(headers: &ureq::http::HeaderMap, tx: &mut gix::features::io::pipe::Writer) {
    let mut header_bytes = Vec::new();
    for (name, val) in headers {
        if let Ok(v_str) = val.to_str() {
            let _ = writeln!(header_bytes, "{}:{v_str}", name.as_str());
        }
    }
    if !header_bytes.is_empty() {
        let _ = tx.write_all(&header_bytes);
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
        let mut req = build_http_agent(30, false).get(&effective_url);
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
            return Err(HttpError::PostBody(http_status_io_error(status)));
        }

        let (mut headers_tx, headers_rx) = pipe::unidirectional(1);
        let (mut body_tx, body_rx) = pipe::unidirectional(0);
        pipe_ureq_headers(res.headers(), &mut headers_tx);
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
            let agent = build_http_agent(30, false);
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
                let _ = headers_tx.channel.send(Err(http_status_io_error(status)));
                return;
            }
            pipe_ureq_headers(res.headers(), &mut headers_tx);
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

fn git_err(operation: &str, message: impl std::fmt::Display) -> EngineError {
    EngineError::GitError {
        operation: operation.to_string(),
        message: message.to_string(),
    }
}

fn peel_commit_tree_id(
    repo: &gix::Repository,
    commit_id: gix::ObjectId,
    label: &str,
) -> Result<gix::ObjectId, EngineError> {
    let obj = repo.find_object(commit_id).map_err(|e| {
        git_err(
            "clone",
            format!("Failed to find {label} commit {commit_id}: {e}"),
        )
    })?;
    let tree = obj.peel_to_tree().map_err(|e| {
        git_err(
            "clone",
            format!("Failed to peel {label} commit {commit_id} to tree: {e}"),
        )
    })?;
    Ok(tree.id)
}

fn materialize_tree_to_dir(
    repo: &gix::Repository,
    tree_id: gix::ObjectId,
    dest: &Path,
) -> Result<(), EngineError> {
    fs::create_dir_all(dest)?;
    let tree = repo
        .find_object(tree_id)
        .map_err(|e| git_err("checkout", format!("Failed to read tree object: {e}")))?
        .try_into_tree()
        .map_err(|e| git_err("checkout", format!("Object is not a git tree: {e}")))?;

    for entry_res in tree.iter() {
        let entry = entry_res
            .map_err(|e| git_err("checkout", format!("Failed to decode tree entry: {e}")))?;
        let name = std::str::from_utf8(entry.filename())
            .map_err(|_| git_err("checkout", "Tree entry filename is not valid UTF-8"))?;
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
                    .map_err(|e| git_err("checkout", format!("Failed to read blob object: {e}")))?;
                fs::write(&target_path, &obj.data)?;
                #[cfg(unix)]
                if entry.mode().kind() == gix::objs::tree::EntryKind::BlobExecutable {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = fs::set_permissions(&target_path, fs::Permissions::from_mode(0o755));
                }
            }
            gix::objs::tree::EntryKind::Link => {
                let obj = repo.find_object(entry.oid()).map_err(|e| {
                    git_err("checkout", format!("Failed to read symlink object: {e}"))
                })?;
                let link_target = std::str::from_utf8(&obj.data)
                    .map_err(|_| git_err("checkout", "Symlink target is not valid UTF-8"))?;
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

fn read_checked_local_file(path: &Path, max_bytes: usize) -> Result<Vec<u8>, EngineError> {
    if is_symlink(path) {
        return Err(EngineError::HardBlockedPath {
            path: path.to_path_buf(),
            reason: "symbolic links are prohibited inside a dotler repository".to_string(),
        });
    }
    let metadata = fs::metadata(path)?;
    if metadata.len() as usize > max_bytes {
        return Err(EngineError::PayloadExceeded {
            size_bytes: metadata.len() as usize,
            limit_bytes: max_bytes,
        });
    }
    Ok(fs::read(path)?)
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
        let metadata = fs::metadata(p)
            .map_err(|e| git_err("http-get", format!("Failed to read '{}': {e}", p.display())))?;
        if metadata.len() as usize > max_bytes {
            return Err(EngineError::PayloadExceeded {
                size_bytes: metadata.len() as usize,
                limit_bytes: max_bytes,
            });
        }
        let bytes = fs::read(p)?;
        return String::from_utf8(bytes)
            .map_err(|_| git_err("http-get", "Response payload is not valid UTF-8"));
    }

    if !trimmed.starts_with("https://") && !trimmed.starts_with("http://") {
        return Err(EngineError::InvalidUrlFormat {
            url: trimmed.to_string(),
            reason: "Expected an http:// or https:// URL".to_string(),
        });
    }

    let agent = build_http_agent(20, true);
    let response = agent
        .get(trimmed)
        .header("User-Agent", concat!("dotler/", env!("CARGO_PKG_VERSION")))
        .header(
            "Accept",
            "application/toml, application/json, text/plain, */*",
        )
        .call()
        .map_err(|e| {
            git_err(
                "http-get",
                format!("HTTP GET request to '{trimmed}' failed: {e}"),
            )
        })?;

    let mut reader = response
        .into_body()
        .into_reader()
        .take((max_bytes + 1) as u64);
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf).map_err(|e| {
        git_err(
            "http-get",
            format!("Failed to read HTTP response body: {e}"),
        )
    })?;
    if buf.len() > max_bytes {
        return Err(EngineError::PayloadExceeded {
            size_bytes: buf.len(),
            limit_bytes: max_bytes,
        });
    }

    String::from_utf8(buf).map_err(|_| git_err("http-get", "HTTP response body is not valid UTF-8"))
}

/// Pure-Rust Git shallow fetch and checkout executor backed by `gix` and `ureq`.
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
                return Err(git_err(
                    "clone",
                    format!(
                        "Local git repository '{}' does not exist",
                        local_path.display()
                    ),
                ));
            }
            let src_repo = gix::open(local_path).map_err(|e| {
                git_err(
                    "clone",
                    format!(
                        "Failed to open git repository '{}': {e}",
                        local_path.display()
                    ),
                )
            })?;
            let commit_id = if let Some(b) = branch {
                let ref_name = format!("refs/heads/{b}");
                let mut r = src_repo
                    .find_reference(&ref_name)
                    .or_else(|_| src_repo.find_reference(b))
                    .map_err(|e| git_err("clone", format!("Branch '{b}' not found: {e}")))?;
                r.peel_to_id()
                    .map_err(|e| git_err("clone", format!("Failed to peel branch '{b}': {e}")))?
                    .detach()
            } else {
                src_repo
                    .head_id()
                    .map_err(|e| git_err("clone", format!("Failed to resolve HEAD: {e}")))?
                    .detach()
            };
            let tree_id = peel_commit_tree_id(&src_repo, commit_id, "local")?;
            fs::create_dir_all(dest)?;
            let _ = gix::init(dest);
            return materialize_tree_to_dir(&src_repo, tree_id, dest);
        }

        fs::create_dir_all(dest)?;
        let repo = gix::init(dest).map_err(|e| {
            git_err(
                "clone",
                format!("Failed to initialize staging repository: {e}"),
            )
        })?;

        let refspec = match branch {
            Some(b) => format!("+refs/heads/{b}:refs/remotes/origin/{b}"),
            None => "+HEAD:refs/remotes/origin/HEAD".to_string(),
        };
        let remote = repo
            .remote_at(url)
            .map_err(|e| git_err("clone", format!("Invalid remote URL '{url}': {e}")))?
            .with_fetch_tags(gix::remote::fetch::Tags::None)
            .with_refspecs(Some(refspec.as_str()), gix::remote::Direction::Fetch)
            .map_err(|e| git_err("clone", format!("Invalid refspec '{refspec}': {e}")))?;

        let (sanitized_url, version) = remote
            .sanitized_url_and_version(gix::remote::Direction::Fetch)
            .map_err(|e| {
                git_err(
                    "clone",
                    format!("Failed to prepare remote URL '{url}': {e}"),
                )
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
            .map_err(|e| git_err("clone", format!("Failed to connect to '{url}': {e}")))?
            .with_shallow(gix::remote::fetch::Shallow::DepthAtRemote(depth))
            .receive(&mut gix::progress::Discard, &should_interrupt)
            .map_err(|e| git_err("clone", format!("Failed to fetch pack from '{url}': {e}")))?;

        let commit_id = outcome
            .ref_map
            .mappings
            .iter()
            .find_map(|m| m.remote.as_id().map(|id| id.to_owned()))
            .ok_or_else(|| git_err("clone", format!("No commit found on remote '{url}'")))?;
        let tree_id = peel_commit_tree_id(&repo, commit_id, "fetched")?;
        materialize_tree_to_dir(&repo, tree_id, dest)
    }

    pub fn fetch_file_shallow(
        url: &str,
        branch: Option<&str>,
        file_path: &str,
        max_bytes: usize,
    ) -> Result<Vec<u8>, EngineError> {
        let local_path = Path::new(url.strip_prefix("file://").unwrap_or(url));
        if local_path.is_dir() {
            let direct_file = local_path.join(file_path);
            if is_symlink(&direct_file) || direct_file.is_file() {
                return read_checked_local_file(&direct_file, max_bytes);
            }
        }

        let temp_dir = TempDirGuard::new().map_err(EngineError::Io)?;
        Self::clone_shallow(url, branch, temp_dir.path())?;

        let target_file = temp_dir.path().join(file_path);
        if !is_symlink(&target_file) && !target_file.is_file() {
            return Err(EngineError::MissingRemoteToml {
                url: url.to_string(),
            });
        }
        read_checked_local_file(&target_file, max_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(
            get_headers
                .iter()
                .any(|h| h.contains("application/x-git-upload-pack-advertisement"))
        );
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
        assert!(
            post_headers
                .iter()
                .any(|h| h.contains("application/x-git-upload-pack-advertisement"))
        );
        let mut post_body = String::new();
        post_res.body.read_to_string(&mut post_body).unwrap();
        assert_eq!(post_body, "0000");

        server.join().unwrap();
    }
}
