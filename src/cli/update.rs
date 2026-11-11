use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::cli::commands::UpdateArgs;
use crate::cli::output::UpdateReport;
use crate::config::repo::OsInfo;
use crate::engine::EngineError;
use crate::tui::confirm::{ConfirmPrompt, confirm_proceed_to};

/// Default GitHub repository `owner/name` for official releases.
pub const DEFAULT_GITHUB_REPO: &str = "msisdev/dotler";

/// Release notes marker indicating that `dotler` has graduated to official `homebrew-core`.
pub const HOMEBREW_CORE_RELEASE_MARKER: &str = "<!-- dotler:homebrew-core -->";

/// Classification of how the current `dotler` executable was installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallMethod {
    Standalone,
    HomebrewTap,
    HomebrewCore,
    Scoop,
    Winget,
    Nix,
    Cargo,
    Pacman,
    Apt,
    Dnf,
    Apk,
    SystemPackage,
}

impl InstallMethod {
    /// Machine-readable identifier for JSON reports and inline status messages.
    pub fn as_str(&self) -> &'static str {
        match self {
            InstallMethod::Standalone => "standalone",
            InstallMethod::HomebrewTap => "homebrew-tap",
            InstallMethod::HomebrewCore => "homebrew",
            InstallMethod::Scoop => "scoop",
            InstallMethod::Winget => "winget",
            InstallMethod::Nix => "nix",
            InstallMethod::Cargo => "cargo",
            InstallMethod::Pacman => "pacman",
            InstallMethod::Apt => "apt",
            InstallMethod::Dnf => "dnf",
            InstallMethod::Apk => "apk",
            InstallMethod::SystemPackage => "system",
        }
    }

    /// Returns `true` if the binary is managed by an external package manager.
    pub fn is_package_manager(&self) -> bool {
        !matches!(self, InstallMethod::Standalone)
    }

    /// Returns the recommended package manager upgrade command, accounting for `homebrew-core` migration.
    pub fn upgrade_command_for(&self, homebrew_core_available: bool) -> Option<&'static str> {
        match self {
            InstallMethod::Standalone => None,
            InstallMethod::HomebrewTap => {
                if homebrew_core_available {
                    Some(
                        "brew uninstall msisdev/tap/dotler && brew untap msisdev/tap && brew install dotler",
                    )
                } else {
                    Some("brew upgrade msisdev/tap/dotler")
                }
            }
            InstallMethod::HomebrewCore => Some("brew upgrade dotler"),
            InstallMethod::Scoop => Some("scoop update dotler"),
            InstallMethod::Winget => Some("winget upgrade msisdev.dotler"),
            InstallMethod::Nix => Some("nix profile upgrade dotler"),
            InstallMethod::Cargo => Some("cargo install dotler"),
            InstallMethod::Pacman => Some("yay -Syu dotler-bin"),
            InstallMethod::Apt => {
                Some("curl -fsSL https://msisdev.github.io/dotler/install.sh | sh")
            }
            InstallMethod::Dnf => Some(
                "sudo dnf upgrade https://github.com/msisdev/dotler/releases/latest/download/dotler-x86_64.rpm",
            ),
            InstallMethod::Apk => {
                Some("curl -fsSL https://msisdev.github.io/dotler/install.sh | sh")
            }
            InstallMethod::SystemPackage => {
                Some("curl -fsSL https://msisdev.github.io/dotler/install.sh | sh")
            }
        }
    }

    /// Returns the default upgrade command when `homebrew-core` migration is not active.
    pub fn upgrade_command(&self) -> Option<&'static str> {
        self.upgrade_command_for(false)
    }
}

/// Resolved target release metadata from GitHub Releases or a custom mirror.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseMetadata {
    pub version: String,
    pub homebrew_core_available: bool,
}

/// Platform release archive descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseTarget {
    pub triple: &'static str,
    pub archive_ext: &'static str,
    pub archive_name: String,
    pub checksum_name: String,
}

fn update_err(message: impl Into<String>) -> EngineError {
    EngineError::GitError {
        operation: "update".to_string(),
        message: message.into(),
    }
}

struct UpdateTempDir(PathBuf);

impl UpdateTempDir {
    fn new() -> Result<Self, std::io::Error> {
        let rand_id: u64 = crate::crypto::random_u64();
        let path = std::env::temp_dir().join(format!(".dotler-update-{rand_id:016x}"));
        fs::create_dir_all(&path)?;
        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for UpdateTempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Checks Homebrew's `INSTALL_RECEIPT.json` in the keg root (`<Cellar>/dotler/<version>/INSTALL_RECEIPT.json`)
/// to determine whether the formula was installed from official `homebrew/core` or a custom tap.
fn is_homebrew_core_receipt(exe_path: &Path) -> bool {
    let resolved = fs::canonicalize(exe_path).unwrap_or_else(|_| exe_path.to_path_buf());
    for candidate in [exe_path, resolved.as_path()] {
        if let Some(bin_dir) = candidate.parent()
            && let Some(keg_dir) = bin_dir.parent()
        {
            let receipt_path = keg_dir.join("INSTALL_RECEIPT.json");
            if let Ok(raw) = fs::read_to_string(&receipt_path)
                && let Ok(json) = serde_json::from_str::<serde_json::Value>(&raw)
                && let Some(tap) = json
                    .get("source")
                    .and_then(|s| s.get("tap"))
                    .and_then(|t| t.as_str())
            {
                return tap == "homebrew/core";
            }
        }
    }
    false
}

/// Detects the installation channel from the executable path and OS distribution metadata.
pub fn detect_install_method(exe_path: &Path, os_info: &OsInfo) -> InstallMethod {
    let raw_norm = exe_path.to_string_lossy().replace('\\', "/");
    let canon_norm = fs::canonicalize(exe_path)
        .ok()
        .map(|p| p.to_string_lossy().replace('\\', "/"))
        .unwrap_or_else(|| raw_norm.clone());

    for candidate in [&raw_norm, &canon_norm] {
        let lower = candidate.to_ascii_lowercase();
        if candidate.contains("/Cellar/dotler/")
            || candidate.contains("/opt/homebrew/")
            || candidate.contains("/home/linuxbrew/.linuxbrew/")
            || candidate.contains("/usr/local/Cellar/")
        {
            if is_homebrew_core_receipt(exe_path) {
                return InstallMethod::HomebrewCore;
            }
            return InstallMethod::HomebrewTap;
        }
        if lower.contains("/scoop/apps/dotler/") || lower.contains("/scoop/shims/") {
            return InstallMethod::Scoop;
        }
        if lower.contains("/microsoft/winget/packages/") || lower.contains("/windowsapps/") {
            return InstallMethod::Winget;
        }
        if candidate.starts_with("/nix/store/")
            || candidate.contains("/.nix-profile/")
            || candidate.contains("/etc/profiles/per-user/")
        {
            return InstallMethod::Nix;
        }
        if lower.contains("/.cargo/bin/") {
            return InstallMethod::Cargo;
        }
    }

    for candidate in [&raw_norm, &canon_norm] {
        if candidate.starts_with("/usr/bin/")
            || candidate.starts_with("/bin/")
            || candidate.starts_with("/sbin/")
        {
            let distro = os_info
                .distro
                .strip_prefix("os-")
                .unwrap_or(os_info.distro.as_str());
            return match distro {
                "arch" => InstallMethod::Pacman,
                "debian" | "ubuntu" => InstallMethod::Apt,
                "fedora" => InstallMethod::Dnf,
                "alpine" => InstallMethod::Apk,
                _ => InstallMethod::SystemPackage,
            };
        }
    }

    InstallMethod::Standalone
}

/// Resolves the release archive target triple and file names for the given OS, CPU architecture, and libc variant.
pub fn detect_release_target(
    os: &str,
    arch: &str,
    libc_env: Option<&str>,
) -> Result<ReleaseTarget, EngineError> {
    let norm_arch = match arch {
        "x86_64" | "amd64" => "x86_64",
        "aarch64" | "arm64" => "aarch64",
        other => {
            return Err(update_err(format!(
                "Unsupported CPU architecture '{other}' for prebuilt binary update. Install from source via 'cargo install dotler'."
            )));
        }
    };

    let libc_variant = libc_env.unwrap_or("musl");
    let (triple, archive_ext): (&'static str, &'static str) = match (os, norm_arch, libc_variant) {
        ("linux", "x86_64", "musl") => ("x86_64-unknown-linux-musl", "tar.gz"),
        ("linux", "x86_64", "gnu") => ("x86_64-unknown-linux-gnu", "tar.gz"),
        ("linux", "aarch64", "musl") => ("aarch64-unknown-linux-musl", "tar.gz"),
        ("linux", "aarch64", "gnu") => ("aarch64-unknown-linux-gnu", "tar.gz"),
        ("linux", _, bad_libc) => {
            return Err(update_err(format!(
                "Unsupported DOTLER_LIBC value '{bad_libc}' (expected 'musl' or 'gnu')."
            )));
        }
        ("macos" | "darwin", "x86_64", _) => ("x86_64-apple-darwin", "tar.gz"),
        ("macos" | "darwin", "aarch64", _) => ("aarch64-apple-darwin", "tar.gz"),
        ("windows", "x86_64", _) => ("x86_64-pc-windows-msvc", "zip"),
        ("windows", "aarch64", _) => ("aarch64-pc-windows-msvc", "zip"),
        (other_os, _, _) => {
            return Err(update_err(format!(
                "Unsupported operating system '{other_os}' for prebuilt binary update. Install from source via 'cargo install dotler'."
            )));
        }
    };

    let archive_name = format!("dotler-{triple}.{archive_ext}");
    let checksum_name = format!("{archive_name}.sha256");

    Ok(ReleaseTarget {
        triple,
        archive_ext,
        archive_name,
        checksum_name,
    })
}

/// Normalizes a version string or Git tag (`v0.2.0` or `0.2.0`) into bare semver (`0.2.0`).
pub fn normalize_version(raw: &str) -> Result<String, EngineError> {
    let trimmed = raw.trim();
    let bare = trimmed.strip_prefix('v').unwrap_or(trimmed);
    if bare.is_empty()
        || !bare
            .chars()
            .next()
            .map(|c| c.is_ascii_digit())
            .unwrap_or(false)
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
        return Err(update_err(
            "Malformed SHA-256 checksum file in release assets.",
        ));
    }

    let mut hasher = Sha256::new();
    hasher.update(archive_bytes);
    let digest = hasher.finalize();
    let actual: String = digest.iter().map(|b| format!("{b:02x}")).collect();

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
            .map(|b| b.contains(HOMEBREW_CORE_RELEASE_MARKER))
            .unwrap_or(false);
        let homebrew_core_available =
            env_core || parsed.homebrew_core.unwrap_or(false) || body_has_marker;
        Ok(ReleaseMetadata {
            version,
            homebrew_core_available,
        })
    } else {
        let first_line = trimmed.lines().next().unwrap_or("");
        let version = normalize_version(first_line)?;
        let homebrew_core_available = env_core || trimmed.contains(HOMEBREW_CORE_RELEASE_MARKER);
        Ok(ReleaseMetadata {
            version,
            homebrew_core_available,
        })
    }
}

fn fetch_bytes_from_source(source: &str) -> Result<Vec<u8>, EngineError> {
    if let Some(file_path) = source.strip_prefix("file://") {
        return fs::read(file_path).map_err(|e| {
            update_err(format!(
                "Failed to read release asset from '{file_path}': {e}"
            ))
        });
    }
    if Path::new(source).is_absolute() && !source.starts_with("http") {
        return fs::read(source)
            .map_err(|e| update_err(format!("Failed to read release asset from '{source}': {e}")));
    }

    let mut response = ureq::get(source)
        .header(
            "User-Agent",
            &format!("dotler/{}", env!("CARGO_PKG_VERSION")),
        )
        .call()
        .map_err(|e| update_err(format!("Failed to download release asset '{source}': {e}")))?;

    let mut buf = Vec::new();
    response
        .body_mut()
        .as_reader()
        .read_to_end(&mut buf)
        .map_err(|e| {
            update_err(format!(
                "Failed to read response stream from '{source}': {e}"
            ))
        })?;
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

    // In hermetic test sandboxes without an explicit release base URL override,
    // return the compiled package version without external network calls.
    if std::env::var("DOTLER_MOCK_KEYRING").ok().as_deref() == Some("1") {
        return Ok(ReleaseMetadata {
            version: env!("CARGO_PKG_VERSION").to_string(),
            homebrew_core_available: env_core,
        });
    }

    let api_url = format!("https://api.github.com/repos/{repo}/releases/latest");
    let mut response = ureq::get(&api_url)
        .header(
            "User-Agent",
            &format!("dotler/{}", env!("CARGO_PKG_VERSION")),
        )
        .header("Accept", "application/vnd.github+json")
        .call()
        .map_err(|e| {
            update_err(format!(
                "Failed to query latest release from GitHub ('{api_url}'): {e}"
            ))
        })?;

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
        let flat = format!("{trimmed}/{file_name}");
        return fetch_bytes_from_source(&flat);
    }

    let url = format!("https://github.com/{repo}/releases/download/{tag}/{file_name}");
    fetch_bytes_from_source(&url)
}

fn extract_binary_from_archive(
    archive_path: &Path,
    archive_ext: &str,
    extract_dir: &Path,
) -> Result<PathBuf, EngineError> {
    if archive_ext == "tar.gz" {
        let status = Command::new("tar")
            .args([
                "-xzf",
                &archive_path.to_string_lossy(),
                "-C",
                &extract_dir.to_string_lossy(),
            ])
            .status()
            .map_err(|e| update_err(format!("Failed to execute 'tar' to extract archive: {e}")))?;
        if !status.success() {
            return Err(update_err("Archive extraction with 'tar -xzf' failed."));
        }
    } else if archive_ext == "zip" {
        let tar_ok = Command::new("tar")
            .args([
                "-xf",
                &archive_path.to_string_lossy(),
                "-C",
                &extract_dir.to_string_lossy(),
            ])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);

        if !tar_ok {
            let unzip_ok = Command::new("unzip")
                .args([
                    "-q",
                    &archive_path.to_string_lossy(),
                    "-d",
                    &extract_dir.to_string_lossy(),
                ])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);

            if !unzip_ok {
                let ps_cmd = format!(
                    "Expand-Archive -Path '{}' -DestinationPath '{}' -Force",
                    archive_path.display(),
                    extract_dir.display()
                );
                let ps_ok = Command::new("powershell")
                    .args(["-NoProfile", "-Command", &ps_cmd])
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false);

                if !ps_ok {
                    return Err(update_err("Failed to extract '.zip' release archive."));
                }
            }
        }
    } else {
        return Err(update_err(format!(
            "Unsupported archive extension '{archive_ext}'."
        )));
    }

    for bin_name in ["dotler", "dotler.exe"] {
        let candidate = extract_dir.join(bin_name);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }

    Err(update_err(
        "Extracted release archive did not contain the 'dotler' binary.",
    ))
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

    let pid = std::process::id();
    let tmp_dest = parent_dir.join(format!(".dotler-update-tmp-{pid}"));

    fs::copy(extracted_bin, &tmp_dest)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o755);
        fs::set_permissions(&tmp_dest, perms)?;
    }

    if let Err(rename_err) = fs::rename(&tmp_dest, target_exe) {
        // On Windows, a running executable cannot be overwritten directly,
        // but can be renamed aside before placing the new binary.
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

    let is_same_version = current_version == target_version;
    let needs_brew_core_migration = matches!(install_method, InstallMethod::HomebrewTap)
        && release_meta.homebrew_core_available;

    if args.check {
        let status = if is_same_version && !needs_brew_core_migration {
            "up_to_date".to_string()
        } else {
            "update_available".to_string()
        };
        return Ok(UpdateReport {
            status,
            check_only: true,
            version: current_version,
            target_version: Some(target_version),
            install_method: Some(install_method.as_str().to_string()),
            upgrade_command: upgrade_cmd,
        });
    }

    if is_same_version && !needs_brew_core_migration && !args.force {
        return Ok(UpdateReport {
            status: "up_to_date".to_string(),
            check_only: false,
            version: current_version,
            target_version: Some(target_version),
            install_method: Some(install_method.as_str().to_string()),
            upgrade_command: upgrade_cmd,
        });
    }

    if install_method.is_package_manager() && !args.force {
        return Ok(UpdateReport {
            status: "managed_by_package_manager".to_string(),
            check_only: false,
            version: current_version,
            target_version: Some(target_version),
            install_method: Some(install_method.as_str().to_string()),
            upgrade_command: upgrade_cmd,
        });
    }

    if (is_interactive || ConfirmPrompt::has_mock_or_env_input()) && !args.yes && !json_mode {
        let mut stderr = std::io::stderr();
        let approved = confirm_proceed_to(&mut stderr, "update")
            .map_err(|e| EngineError::Io(std::io::Error::other(e.to_string())))?;
        if !approved {
            return Ok(UpdateReport {
                status: "cancelled".to_string(),
                check_only: false,
                version: current_version,
                target_version: Some(target_version),
                install_method: Some(install_method.as_str().to_string()),
                upgrade_command: None,
            });
        }
    }

    let libc_env = std::env::var("DOTLER_LIBC").ok();
    let release_target = detect_release_target(
        std::env::consts::OS,
        std::env::consts::ARCH,
        libc_env.as_deref(),
    )?;

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

    Ok(UpdateReport {
        status: "updated".to_string(),
        check_only: false,
        version: current_version,
        target_version: Some(target_version),
        install_method: Some(install_method.as_str().to_string()),
        upgrade_command: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_os(distro: &str) -> OsInfo {
        OsInfo::new(distro, "nux")
    }

    #[test]
    fn test_detect_install_method_across_package_managers_and_homebrew_receipt() {
        let os = dummy_os("ubuntu");

        assert_eq!(
            detect_install_method(
                Path::new("/opt/homebrew/Cellar/dotler/0.2.0/bin/dotler"),
                &os
            ),
            InstallMethod::HomebrewTap
        );
        assert_eq!(
            detect_install_method(Path::new("/home/linuxbrew/.linuxbrew/bin/dotler"), &os),
            InstallMethod::HomebrewTap
        );

        // Verify INSTALL_RECEIPT.json distinction between msisdev/tap and homebrew/core
        let tmp = tempfile::tempdir().unwrap();
        let keg_dir = tmp.path().join("opt/homebrew/Cellar/dotler/1.0.0");
        let bin_dir = keg_dir.join("bin");
        fs::create_dir_all(&bin_dir).unwrap();
        let brew_exe = bin_dir.join("dotler");
        fs::write(&brew_exe, b"bin").unwrap();

        fs::write(
            keg_dir.join("INSTALL_RECEIPT.json"),
            r#"{"source":{"tap":"msisdev/tap"}}"#,
        )
        .unwrap();
        let method_tap = detect_install_method(&brew_exe, &os);
        assert_eq!(method_tap, InstallMethod::HomebrewTap);
        assert_eq!(
            method_tap.upgrade_command_for(false),
            Some("brew upgrade msisdev/tap/dotler")
        );
        assert_eq!(
            method_tap.upgrade_command_for(true),
            Some(
                "brew uninstall msisdev/tap/dotler && brew untap msisdev/tap && brew install dotler"
            )
        );

        fs::write(
            keg_dir.join("INSTALL_RECEIPT.json"),
            r#"{"source":{"tap":"homebrew/core"}}"#,
        )
        .unwrap();
        let method_core = detect_install_method(&brew_exe, &os);
        assert_eq!(method_core, InstallMethod::HomebrewCore);
        assert_eq!(
            method_core.upgrade_command_for(true),
            Some("brew upgrade dotler")
        );

        assert_eq!(
            detect_install_method(
                Path::new("C:\\Users\\alice\\scoop\\apps\\dotler\\current\\dotler.exe"),
                &os
            ),
            InstallMethod::Scoop
        );
        assert_eq!(
            detect_install_method(
                Path::new(
                    "C:\\Users\\alice\\AppData\\Local\\Microsoft\\WinGet\\Packages\\msisdev.dotler\\dotler.exe"
                ),
                &os
            ),
            InstallMethod::Winget
        );
        assert_eq!(
            detect_install_method(Path::new("/nix/store/abc123-dotler-0.2.0/bin/dotler"), &os),
            InstallMethod::Nix
        );
        assert_eq!(
            detect_install_method(Path::new("/home/alice/.cargo/bin/dotler"), &os),
            InstallMethod::Cargo
        );
        assert_eq!(
            detect_install_method(Path::new("/usr/bin/dotler"), &dummy_os("arch")),
            InstallMethod::Pacman
        );
        assert_eq!(
            detect_install_method(Path::new("/usr/bin/dotler"), &dummy_os("ubuntu")),
            InstallMethod::Apt
        );
        assert_eq!(
            detect_install_method(Path::new("/usr/bin/dotler"), &dummy_os("fedora")),
            InstallMethod::Dnf
        );
        assert_eq!(
            detect_install_method(Path::new("/usr/bin/dotler"), &dummy_os("alpine")),
            InstallMethod::Apk
        );
        assert_eq!(
            detect_install_method(Path::new("/home/alice/.local/bin/dotler"), &os),
            InstallMethod::Standalone
        );
    }

    #[test]
    fn test_parse_release_metadata_detects_homebrew_core_marker() {
        let meta_tap =
            parse_release_metadata(r#"{"tag_name":"v0.2.1","body":"Normal release notes"}"#)
                .unwrap();
        assert_eq!(meta_tap.version, "0.2.1");
        assert!(!meta_tap.homebrew_core_available);

        let meta_core_marker = parse_release_metadata(
            r#"{"tag_name":"v1.0.0","body":"Release notes\n<!-- dotler:homebrew-core -->"}"#,
        )
        .unwrap();
        assert_eq!(meta_core_marker.version, "1.0.0");
        assert!(meta_core_marker.homebrew_core_available);

        let meta_core_field =
            parse_release_metadata(r#"{"tag_name":"v1.0.0","homebrew_core":true}"#).unwrap();
        assert_eq!(meta_core_field.version, "1.0.0");
        assert!(meta_core_field.homebrew_core_available);
    }

    #[test]
    fn test_detect_release_target_matrix() {
        let linux_musl = detect_release_target("linux", "x86_64", None).unwrap();
        assert_eq!(linux_musl.triple, "x86_64-unknown-linux-musl");
        assert_eq!(
            linux_musl.archive_name,
            "dotler-x86_64-unknown-linux-musl.tar.gz"
        );

        let linux_gnu = detect_release_target("linux", "aarch64", Some("gnu")).unwrap();
        assert_eq!(linux_gnu.triple, "aarch64-unknown-linux-gnu");

        let mac_arm = detect_release_target("macos", "aarch64", None).unwrap();
        assert_eq!(mac_arm.triple, "aarch64-apple-darwin");

        let win_x64 = detect_release_target("windows", "x86_64", None).unwrap();
        assert_eq!(win_x64.triple, "x86_64-pc-windows-msvc");
        assert_eq!(win_x64.archive_ext, "zip");

        assert!(detect_release_target("linux", "x86_64", Some("invalid")).is_err());
        assert!(detect_release_target("freebsd", "x86_64", None).is_err());
    }

    #[test]
    fn test_verify_sha256_checksum_accepts_valid_and_rejects_tampered() {
        let payload = b"dotler-release-binary-payload";
        let mut hasher = Sha256::new();
        hasher.update(payload);
        let hex: String = hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
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
        let staging = tmp.path().join("staging");
        let extract_dir = tmp.path().join("extract");
        let install_dir = tmp.path().join("bin");
        fs::create_dir_all(&staging).unwrap();
        fs::create_dir_all(&extract_dir).unwrap();
        fs::create_dir_all(&install_dir).unwrap();

        let new_bin_content = b"#!/bin/sh\necho dotler v9.9.9\n";
        fs::write(staging.join("dotler"), new_bin_content).unwrap();

        let archive_path = tmp.path().join("dotler-test.tar.gz");
        let status = Command::new("tar")
            .args([
                "-C",
                &staging.to_string_lossy(),
                "-czf",
                &archive_path.to_string_lossy(),
                "dotler",
            ])
            .status()
            .unwrap();
        assert!(status.success());

        let extracted = extract_binary_from_archive(&archive_path, "tar.gz", &extract_dir).unwrap();
        assert_eq!(fs::read(&extracted).unwrap(), new_bin_content);

        let target_exe = install_dir.join("dotler");
        fs::write(&target_exe, b"old-binary-bytes").unwrap();

        replace_executable_atomically(&extracted, &target_exe).unwrap();
        assert_eq!(fs::read(&target_exe).unwrap(), new_bin_content);
    }
}
