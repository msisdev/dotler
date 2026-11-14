//! Self-update engine: release metadata resolution, SHA-256 verification, and binary swap.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::cli::channel::{UpdateTempDir, update_err};
use crate::cli::commands::UpdateArgs;
use crate::cli::output::UpdateReport;
use crate::config::repo::OsInfo;
use crate::engine::EngineError;
use crate::tui::confirm::{ConfirmPrompt, confirm_proceed_to};

pub use crate::cli::channel::{
    DEFAULT_GITHUB_REPO, HOMEBREW_CORE_RELEASE_MARKER, InstallMethod, ReleaseMetadata,
    ReleaseTarget, detect_install_method, detect_release_target,
};

/// Normalizes a version string or Git tag (`v0.2.0` or `0.2.0`) into bare semver (`0.2.0`).
pub fn normalize_version(raw: &str) -> Result<String, EngineError> {
    let trimmed = raw.trim();
    let bare = trimmed.strip_prefix('v').unwrap_or(trimmed);
    if bare.is_empty()
        || !bare.chars().next().is_some_and(|c| c.is_ascii_digit())
        || !bare.contains('.')
        || bare
            .chars()
            .any(|c| !(c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '+'))
    {
        return Err(update_err(format!(
            "Invalid version identifier '{raw}'. Expected semantic version such as 'v0.2.0' or '0.2.0'."
        )));
    }
    Ok(bare.to_string())
}

/// Verifies that the SHA-256 digest of `archive_bytes` matches the expected hex digest in `sha256_text`.
pub fn verify_sha256_checksum(archive_bytes: &[u8], sha256_text: &str) -> Result<(), EngineError> {
    let expected = sha256_text
        .split_whitespace()
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();

    if expected.len() != 64 || !expected.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(update_err("Malformed SHA-256 checksum file in release assets."));
    }

    let mut hasher = Sha256::new();
    hasher.update(archive_bytes);
    let actual: String = hasher.finalize().iter().map(|b| format!("{b:02x}")).collect();

    if actual != expected {
        return Err(update_err(format!(
            "SHA-256 checksum mismatch for release archive (expected {expected}, got {actual})."
        )));
    }
    Ok(())
}

#[derive(Deserialize)]
struct GithubReleasePayload {
    tag_name: String,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    homebrew_core: Option<bool>,
}

/// Parses JSON or plain-text release metadata into a normalized [`ReleaseMetadata`].
pub fn parse_release_metadata(body: &str) -> Result<ReleaseMetadata, EngineError> {
    let env_core = std::env::var("DOTLER_HOMEBREW_CORE").ok().as_deref() == Some("1");
    let trimmed = body.trim();
    if trimmed.starts_with('{') {
        let parsed: GithubReleasePayload = serde_json::from_str(trimmed)
            .map_err(|e| update_err(format!("Failed to parse release metadata JSON: {e}")))?;
        let version = normalize_version(&parsed.tag_name)?;
        let body_has_marker = parsed
            .body
            .as_deref()
            .is_some_and(|b| b.contains(HOMEBREW_CORE_RELEASE_MARKER));
        Ok(ReleaseMetadata {
            version,
            homebrew_core_available: env_core || parsed.homebrew_core.unwrap_or(false) || body_has_marker,
        })
    } else {
        let first_line = trimmed.lines().next().unwrap_or("");
        let version = normalize_version(first_line)?;
        Ok(ReleaseMetadata {
            version,
            homebrew_core_available: env_core || trimmed.contains(HOMEBREW_CORE_RELEASE_MARKER),
        })
    }
}

fn fetch_bytes_from_source(source: &str) -> Result<Vec<u8>, EngineError> {
    if let Some(file_path) = source.strip_prefix("file://") {
        return fs::read(file_path)
            .map_err(|e| update_err(format!("Failed to read release asset from '{file_path}': {e}")));
    }
    if Path::new(source).is_absolute() && !source.starts_with("http") {
        return fs::read(source)
            .map_err(|e| update_err(format!("Failed to read release asset from '{source}': {e}")));
    }

    let mut response = ureq::get(source)
        .header("User-Agent", &format!("dotler/{}", env!("CARGO_PKG_VERSION")))
        .call()
        .map_err(|e| update_err(format!("Failed to download release asset '{source}': {e}")))?;

    let mut buf = Vec::new();
    response
        .body_mut()
        .as_reader()
        .read_to_end(&mut buf)
        .map_err(|e| update_err(format!("Failed to read response stream from '{source}': {e}")))?;
    Ok(buf)
}

/// Resolves the target release metadata (version and `homebrew-core` availability).
pub fn resolve_target_release(
    requested_version: Option<&str>,
    base_url_override: Option<&str>,
    repo: &str,
) -> Result<ReleaseMetadata, EngineError> {
    let env_core = std::env::var("DOTLER_HOMEBREW_CORE").ok().as_deref() == Some("1");
    if let Some(v) = requested_version {
        return Ok(ReleaseMetadata {
            version: normalize_version(v)?,
            homebrew_core_available: env_core,
        });
    }

    if let Some(base) = base_url_override {
        let trimmed_base = base.trim_end_matches('/');
        for suffix in ["latest.json", "latest-version", "latest"] {
            let candidate = format!("{trimmed_base}/{suffix}");
            if let Ok(bytes) = fetch_bytes_from_source(&candidate)
                && let Ok(text) = String::from_utf8(bytes)
                && let Ok(meta) = parse_release_metadata(&text)
            {
                return Ok(meta);
            }
        }
        return Err(update_err(format!(
            "Failed to resolve latest release version from '{trimmed_base}'."
        )));
    }

    // Hermetic sandbox guard when no explicit release mirror URL override is provided.
    if std::env::var("DOTLER_MOCK_KEYRING").ok().as_deref() == Some("1") {
        return Ok(ReleaseMetadata {
            version: env!("CARGO_PKG_VERSION").to_string(),
            homebrew_core_available: env_core,
        });
    }

    let api_url = format!("https://api.github.com/repos/{repo}/releases/latest");
    let mut response = ureq::get(&api_url)
        .header("User-Agent", &format!("dotler/{}", env!("CARGO_PKG_VERSION")))
        .header("Accept", "application/vnd.github+json")
        .call()
        .map_err(|e| update_err(format!("Failed to query latest release from GitHub ('{api_url}'): {e}")))?;

    let body = response
        .body_mut()
        .read_to_string()
        .map_err(|e| update_err(format!("Failed to read GitHub API response: {e}")))?;
    parse_release_metadata(&body)
}

fn fetch_release_asset(
    base_url_override: Option<&str>,
    repo: &str,
    version: &str,
    file_name: &str,
) -> Result<Vec<u8>, EngineError> {
    let tag = format!("v{version}");
    if let Some(base) = base_url_override {
        let trimmed = base.trim_end_matches('/');
        let versioned = format!("{trimmed}/{tag}/{file_name}");
        if let Ok(bytes) = fetch_bytes_from_source(&versioned) {
            return Ok(bytes);
        }
        return fetch_bytes_from_source(&format!("{trimmed}/{file_name}"));
    }
    fetch_bytes_from_source(&format!("https://github.com/{repo}/releases/download/{tag}/{file_name}"))
}

fn run_cmd_success(program: &str, args: &[&str]) -> bool {
    Command::new(program).args(args).status().map(|s| s.success()).unwrap_or(false)
}

fn extract_binary_from_archive(
    archive_path: &Path,
    archive_ext: &str,
    extract_dir: &Path,
) -> Result<PathBuf, EngineError> {
    let arch = archive_path.to_string_lossy();
    let dest = extract_dir.to_string_lossy();

    if archive_ext == "tar.gz" {
        if !run_cmd_success("tar", &["-xzf", &arch, "-C", &dest]) {
            return Err(update_err("Archive extraction with 'tar -xzf' failed."));
        }
    } else if archive_ext == "zip" {
        let ps_cmd = format!("Expand-Archive -Path '{arch}' -DestinationPath '{dest}' -Force");
        let extracted = run_cmd_success("tar", &["-xf", &arch, "-C", &dest])
            || run_cmd_success("unzip", &["-q", &arch, "-d", &dest])
            || run_cmd_success("powershell", &["-NoProfile", "-Command", &ps_cmd]);
        if !extracted {
            return Err(update_err("Failed to extract '.zip' release archive."));
        }
    } else {
        return Err(update_err(format!("Unsupported archive extension '{archive_ext}'.")));
    }

    for bin_name in ["dotler", "dotler.exe"] {
        let candidate = extract_dir.join(bin_name);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(update_err("Extracted release archive did not contain the 'dotler' binary."))
}

/// Atomically replaces `target_exe` with `extracted_bin` in the same filesystem directory.
pub fn replace_executable_atomically(
    extracted_bin: &Path,
    target_exe: &Path,
) -> Result<(), EngineError> {
    let parent_dir = target_exe.parent().ok_or_else(|| {
        EngineError::AtomicReplaceFailed(format!(
            "Target executable path '{}' has no parent directory.",
            target_exe.display()
        ))
    })?;

    fs::create_dir_all(parent_dir)?;
    let tmp_dest = parent_dir.join(format!(".dotler-update-tmp-{}", std::process::id()));
    fs::copy(extracted_bin, &tmp_dest)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp_dest, fs::Permissions::from_mode(0o755))?;
    }

    if let Err(rename_err) = fs::rename(&tmp_dest, target_exe) {
        // Rename aside active Windows binaries before placing the new executable.
        let backup_old = target_exe.with_extension("old-exe");
        let _ = fs::remove_file(&backup_old);
        if target_exe.exists() && fs::rename(target_exe, &backup_old).is_ok() {
            if let Err(e) = fs::rename(&tmp_dest, target_exe) {
                let _ = fs::rename(&backup_old, target_exe);
                let _ = fs::remove_file(&tmp_dest);
                return Err(EngineError::Io(e));
            }
            let _ = fs::remove_file(&backup_old);
        } else {
            let _ = fs::remove_file(&tmp_dest);
            return Err(EngineError::Io(rename_err));
        }
    }
    Ok(())
}

/// Executes the `dotler update` workflow.
pub fn run_update(
    args: &UpdateArgs,
    is_interactive: bool,
    json_mode: bool,
) -> Result<UpdateReport, EngineError> {
    let current_version = env!("CARGO_PKG_VERSION").to_string();
    let os_info = OsInfo::detect();

    let exe_path = match std::env::var("DOTLER_UPDATE_EXE_PATH") {
        Ok(val) if !val.trim().is_empty() => PathBuf::from(val),
        _ => std::env::current_exe()?,
    };

    let install_method = detect_install_method(&exe_path, &os_info);
    let repo = std::env::var("DOTLER_REPO")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_GITHUB_REPO.to_string());
    let base_url_override = std::env::var("DOTLER_RELEASE_BASE_URL")
        .ok()
        .filter(|s| !s.trim().is_empty());

    let release_meta =
        resolve_target_release(args.version.as_deref(), base_url_override.as_deref(), &repo)?;
    let target_version = release_meta.version;
    let upgrade_cmd = install_method
        .upgrade_command_for(release_meta.homebrew_core_available)
        .map(str::to_string);

    let make_report = |status: &str, check_only: bool, cmd: Option<String>| UpdateReport {
        status: status.to_string(),
        check_only,
        version: current_version.clone(),
        target_version: Some(target_version.clone()),
        install_method: Some(install_method.as_str().to_string()),
        upgrade_command: cmd,
    };

    let is_same_version = current_version == target_version;
    let needs_brew_core_migration =
        matches!(install_method, InstallMethod::HomebrewTap) && release_meta.homebrew_core_available;

    if args.check {
        let status = if is_same_version && !needs_brew_core_migration {
            "up_to_date"
        } else {
            "update_available"
        };
        return Ok(make_report(status, true, upgrade_cmd));
    }
    if is_same_version && !needs_brew_core_migration && !args.force {
        return Ok(make_report("up_to_date", false, upgrade_cmd));
    }
    if install_method.is_package_manager() && !args.force {
        return Ok(make_report("managed_by_package_manager", false, upgrade_cmd));
    }
    if (is_interactive || ConfirmPrompt::has_mock_or_env_input()) && !args.yes && !json_mode {
        let mut stderr = std::io::stderr();
        let approved = confirm_proceed_to(&mut stderr, "update")
            .map_err(|e| EngineError::Io(std::io::Error::other(e.to_string())))?;
        if !approved {
            return Ok(make_report("cancelled", false, None));
        }
    }

    let libc_env = std::env::var("DOTLER_LIBC").ok();
    let release_target =
        detect_release_target(std::env::consts::OS, std::env::consts::ARCH, libc_env.as_deref())?;

    let archive_bytes = fetch_release_asset(
        base_url_override.as_deref(),
        &repo,
        &target_version,
        &release_target.archive_name,
    )?;
    let checksum_bytes = fetch_release_asset(
        base_url_override.as_deref(),
        &repo,
        &target_version,
        &release_target.checksum_name,
    )?;
    let checksum_text = String::from_utf8(checksum_bytes)
        .map_err(|_| update_err("Release checksum file is not valid UTF-8."))?;
    verify_sha256_checksum(&archive_bytes, &checksum_text)?;

    let tmp_dir = UpdateTempDir::new()?;
    let archive_path = tmp_dir.path().join(&release_target.archive_name);
    fs::write(&archive_path, &archive_bytes)?;

    let extracted_bin =
        extract_binary_from_archive(&archive_path, release_target.archive_ext, tmp_dir.path())?;
    replace_executable_atomically(&extracted_bin, &exe_path)?;

    Ok(make_report("updated", false, None))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_release_metadata_detects_homebrew_core_marker() {
        let tap = parse_release_metadata(r#"{"tag_name":"v0.2.1","body":"Normal"}"#).unwrap();
        assert_eq!(tap.version, "0.2.1");
        assert!(!tap.homebrew_core_available);

        let marker = parse_release_metadata(
            r#"{"tag_name":"v1.0.0","body":"Notes\n<!-- dotler:homebrew-core -->"}"#,
        )
        .unwrap();
        assert_eq!((marker.version.as_str(), marker.homebrew_core_available), ("1.0.0", true));

        let field = parse_release_metadata(r#"{"tag_name":"v1.0.0","homebrew_core":true}"#).unwrap();
        assert!(field.homebrew_core_available);
    }

    #[test]
    fn test_verify_sha256_checksum_accepts_valid_and_rejects_tampered() {
        let payload = b"dotler-release-binary-payload";
        let mut hasher = Sha256::new();
        hasher.update(payload);
        let hex: String = hasher.finalize().iter().map(|b| format!("{b:02x}")).collect();
        let sha_line = format!("{hex}  dotler-x86_64-unknown-linux-musl.tar.gz\n");

        assert!(verify_sha256_checksum(payload, &sha_line).is_ok());
        assert!(verify_sha256_checksum(b"tampered-payload", &sha_line).is_err());
        assert!(verify_sha256_checksum(payload, "not-a-valid-sha256\n").is_err());
    }

    #[test]
    fn test_normalize_version() {
        assert_eq!(normalize_version("v0.3.1").unwrap(), "0.3.1");
        assert_eq!(normalize_version("0.3.1").unwrap(), "0.3.1");
        assert!(normalize_version("").is_err());
        assert!(normalize_version("../etc/passwd").is_err());
    }

    #[test]
    fn test_extract_and_replace_executable_atomically() {
        let tmp = tempfile::tempdir().unwrap();
        let (staging, extract_dir, install_dir) =
            (tmp.path().join("staging"), tmp.path().join("extract"), tmp.path().join("bin"));
        for d in [&staging, &extract_dir, &install_dir] {
            fs::create_dir_all(d).unwrap();
        }

        let new_bin = b"#!/bin/sh\necho dotler v9.9.9\n";
        fs::write(staging.join("dotler"), new_bin).unwrap();

        let archive_path = tmp.path().join("dotler-test.tar.gz");
        let status = Command::new("tar")
            .args(["-C", &staging.to_string_lossy(), "-czf", &archive_path.to_string_lossy(), "dotler"])
            .status()
            .unwrap();
        assert!(status.success());

        let extracted = extract_binary_from_archive(&archive_path, "tar.gz", &extract_dir).unwrap();
        assert_eq!(fs::read(&extracted).unwrap(), new_bin);

        let target_exe = install_dir.join("dotler");
        fs::write(&target_exe, b"old-binary-bytes").unwrap();
        replace_executable_atomically(&extracted, &target_exe).unwrap();
        assert_eq!(fs::read(&target_exe).unwrap(), new_bin);
    }
}
