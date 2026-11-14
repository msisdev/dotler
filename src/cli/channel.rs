//! Install channel detection and target triple resolution for self-updates.

use std::fs;
use std::path::{Path, PathBuf};

use crate::config::repo::OsInfo;
use crate::engine::EngineError;

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
            InstallMethod::HomebrewTap => Some(if homebrew_core_available {
                "brew uninstall msisdev/tap/dotler && brew untap msisdev/tap && brew install dotler"
            } else {
                "brew upgrade msisdev/tap/dotler"
            }),
            InstallMethod::HomebrewCore => Some("brew upgrade dotler"),
            InstallMethod::Scoop => Some("scoop update dotler"),
            InstallMethod::Winget => Some("winget upgrade msisdev.dotler"),
            InstallMethod::Nix => Some("nix profile upgrade dotler"),
            InstallMethod::Cargo => Some("cargo install dotler"),
            InstallMethod::Pacman => Some("yay -Syu dotler-bin"),
            InstallMethod::Dnf => Some(
                "sudo dnf upgrade https://github.com/msisdev/dotler/releases/latest/download/dotler-x86_64.rpm",
            ),
            InstallMethod::Apt | InstallMethod::Apk | InstallMethod::SystemPackage => {
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

pub(crate) fn update_err(message: impl Into<String>) -> EngineError {
    EngineError::GitError {
        operation: "update".to_string(),
        message: message.into(),
    }
}

pub(crate) struct UpdateTempDir(PathBuf);

impl UpdateTempDir {
    pub(crate) fn new() -> Result<Self, std::io::Error> {
        let rand_id: u64 = crate::crypto::random_u64();
        let path = std::env::temp_dir().join(format!(".dotler-update-{rand_id:016x}"));
        fs::create_dir_all(&path)?;
        Ok(Self(path))
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for UpdateTempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

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
            return if is_homebrew_core_receipt(exe_path) {
                InstallMethod::HomebrewCore
            } else {
                InstallMethod::HomebrewTap
            };
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

        let tmp = tempfile::tempdir().unwrap();
        let keg_dir = tmp.path().join("opt/homebrew/Cellar/dotler/1.0.0");
        fs::create_dir_all(keg_dir.join("bin")).unwrap();
        let brew_exe = keg_dir.join("bin/dotler");
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
    fn test_detect_release_target_matrix() {
        let linux_musl = detect_release_target("linux", "x86_64", None).unwrap();
        assert_eq!(linux_musl.triple, "x86_64-unknown-linux-musl");
        assert_eq!(
            linux_musl.archive_name,
            "dotler-x86_64-unknown-linux-musl.tar.gz"
        );
        assert_eq!(
            detect_release_target("linux", "aarch64", Some("gnu"))
                .unwrap()
                .triple,
            "aarch64-unknown-linux-gnu"
        );
        assert_eq!(
            detect_release_target("macos", "aarch64", None)
                .unwrap()
                .triple,
            "aarch64-apple-darwin"
        );
        let win = detect_release_target("windows", "x86_64", None).unwrap();
        assert_eq!(
            (win.triple, win.archive_ext),
            ("x86_64-pc-windows-msvc", "zip")
        );
        assert!(detect_release_target("linux", "x86_64", Some("invalid")).is_err());
        assert!(detect_release_target("freebsd", "x86_64", None).is_err());
    }
}
