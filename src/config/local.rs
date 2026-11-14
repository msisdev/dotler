use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::lock::write_file_safe;
use crate::config::{ConfigError, StateError};

pub const LOCAL_CONFIG_DIR: &str = "~/.config/dotler";
pub const LOCAL_CONFIG_FILE: &str = "~/.config/dotler/config.toml";
pub const RESERVED_OS_PREFIX: &str = "os-";

pub fn expand_tilde(path: &str) -> PathBuf {
    if path == "~" {
        std::env::home_dir().unwrap_or_else(|| PathBuf::from("."))
    } else if let Some(stripped) = path.strip_prefix("~/") {
        std::env::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(stripped)
    } else {
        PathBuf::from(path)
    }
}

pub use crate::config::path_security::{WalkDir, WalkEntry};

/// Searches `start_dir` and its parent directories upward for a `dotler.toml` manifest.
/// Returns the directory containing the nearest `dotler.toml`, if found.
pub fn find_ancestor_repo_dir(start_dir: &Path) -> Option<PathBuf> {
    start_dir
        .ancestors()
        .find(|dir| dir.join("dotler.toml").is_file())
        .map(Path::to_path_buf)
}

fn default_use_keyring() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalConfig {
    #[serde(default)]
    pub default_devices: Vec<String>,
    #[serde(default)]
    pub default_repo: Option<String>,
    #[serde(default = "default_use_keyring")]
    pub use_keyring: bool,
    #[serde(default)]
    pub repos: BTreeMap<String, String>,
}

impl Default for LocalConfig {
    fn default() -> Self {
        Self {
            default_devices: Vec::new(),
            default_repo: None,
            use_keyring: true,
            repos: BTreeMap::new(),
        }
    }
}

impl LocalConfig {
    pub fn parse(content: &str) -> Result<Self, ConfigError> {
        let config: LocalConfig = toml::from_str(content).map_err(|e| {
            let msg = e.to_string();
            if msg.contains("unknown field") {
                ConfigError::UnknownField {
                    field: msg.clone(),
                    hint: "Check config.toml for unexpected or misspelled fields.".to_string(),
                }
            } else {
                ConfigError::TomlSyntaxError(msg)
            }
        })?;

        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        let mut seen_devices = HashSet::new();
        for dev in &self.default_devices {
            if dev.is_empty() {
                return Err(ConfigError::InvalidDeviceName {
                    device: dev.clone(),
                    reason: "device name cannot be empty".to_string(),
                });
            }
            if dev.chars().any(char::is_whitespace) {
                return Err(ConfigError::InvalidDeviceName {
                    device: dev.clone(),
                    reason: "device name cannot contain whitespace".to_string(),
                });
            }
            if dev.contains('/') || dev.contains('\\') {
                return Err(ConfigError::InvalidDeviceName {
                    device: dev.clone(),
                    reason: "device name cannot contain path separators".to_string(),
                });
            }
            if dev.starts_with(RESERVED_OS_PREFIX) {
                return Err(ConfigError::InvalidDeviceName {
                    device: dev.clone(),
                    reason: format!(
                        "device name cannot start with reserved prefix '{RESERVED_OS_PREFIX}'"
                    ),
                });
            }
            if dev == "files" || dev == "vault" {
                return Err(ConfigError::InvalidDeviceName {
                    device: dev.clone(),
                    reason: format!("'{dev}' is a reserved keyword"),
                });
            }
            if !seen_devices.insert(dev.clone()) {
                return Err(ConfigError::InvalidDeviceName {
                    device: dev.clone(),
                    reason: "duplicate device name in default_devices".to_string(),
                });
            }
        }

        if let Some(ref default_label) = self.default_repo
            && !self.repos.contains_key(default_label)
        {
            return Err(ConfigError::InvalidDefaultRepo {
                label: default_label.clone(),
            });
        }

        for (label, path) in &self.repos {
            if label.is_empty()
                || !label
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            {
                return Err(ConfigError::InvalidRepoLabel {
                    label: label.clone(),
                });
            }

            if path != "~" && !path.starts_with("~/") {
                return Err(ConfigError::InvalidHomePath {
                    path: path.clone(),
                    reason: "repository path must start with '~' or '~/'".to_string(),
                });
            }

            if path.contains("..") {
                return Err(ConfigError::HardBlockedPath {
                    path: path.clone(),
                    reason: "directory traversal ('..') is prohibited".to_string(),
                });
            }
            if path.contains('$') || path.contains('%') {
                return Err(ConfigError::HardBlockedPath {
                    path: path.clone(),
                    reason: "environment variable expansion is prohibited".to_string(),
                });
            }
            if path.contains('\\') {
                return Err(ConfigError::HardBlockedPath {
                    path: path.clone(),
                    reason: "backslash path separators are prohibited".to_string(),
                });
            }

            let trimmed = path.trim_end_matches('/');

            if trimmed == "~/.config/dotler" || trimmed.starts_with("~/.config/dotler/") {
                return Err(ConfigError::HardBlockedPath {
                    path: path.clone(),
                    reason: "repository path cannot point inside ~/.config/dotler".to_string(),
                });
            }

            if trimmed.split('/').any(|segment| segment == ".git") {
                return Err(ConfigError::HardBlockedPath {
                    path: path.clone(),
                    reason: "repository path cannot target .git directories".to_string(),
                });
            }
        }

        Ok(())
    }

    pub fn resolve_repo(&self, requested: Option<&str>) -> Result<(String, PathBuf), ConfigError> {
        if let Some(label) = requested {
            match self.repos.get(label) {
                Some(path) => Ok((label.to_string(), expand_tilde(path))),
                None => Err(ConfigError::UnknownRepoLabel {
                    label: label.to_string(),
                }),
            }
        } else if let Some(ref label) = self.default_repo {
            match self.repos.get(label) {
                Some(path) => Ok((label.clone(), expand_tilde(path))),
                None => Err(ConfigError::InvalidDefaultRepo {
                    label: label.clone(),
                }),
            }
        } else if self.repos.len() == 1 {
            let (label, path) = self.repos.iter().next().unwrap();
            Ok((label.clone(), expand_tilde(path)))
        } else if self.repos.is_empty() {
            Err(ConfigError::NoReposConfigured)
        } else {
            Err(ConfigError::AmbiguousDefaultRepo)
        }
    }

    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let content = fs::read_to_string(path)?;
        Self::parse(&content)
    }

    pub fn to_toml_string(&self) -> String {
        let devices_val = toml::Value::Array(
            self.default_devices
                .iter()
                .cloned()
                .map(toml::Value::String)
                .collect(),
        )
        .to_string();

        let default_repo_line = match &self.default_repo {
            Some(repo) => format!("default_repo = {}", toml::Value::String(repo.clone())),
            None => "# default_repo = \"default\"".to_string(),
        };

        let mut out = format!(
            "# Priority-ordered device profile names for path matching\ndefault_devices = {devices_val}\n\n# Default repository label used when --repo is omitted\n{default_repo_line}\n\n# Store and retrieve vault passphrases via OS keyring\nuse_keyring = {}\n\n# Registered dotfile repositories (<label> = \"~/path\")\n[repos]\n",
            self.use_keyring
        );

        for (label, repo_path) in &self.repos {
            let escaped_path = toml::Value::String(repo_path.clone()).to_string();
            out.push_str(&format!("{label} = {escaped_path}\n"));
        }

        out
    }

    pub fn save_atomic(&self, path: &Path) -> Result<(), ConfigError> {
        self.validate()?;
        let serialized = self.to_toml_string();

        write_file_safe(path, serialized.as_bytes()).map_err(|e| match e {
            StateError::Io(io) => ConfigError::IoError(io),
            other => ConfigError::AtomicRenameFailed(other.to_string()),
        })
    }
}

/// Creates a lazy [`Resource`] for `~/.config/dotler/config.toml` (or a custom path).
pub fn get_local_config(path: PathBuf) -> crate::config::Resource<LocalConfig, ConfigError> {
    let load_path = path.clone();
    let save_path = path;
    crate::config::Resource::new(
        move || {
            if load_path.is_file() {
                LocalConfig::load(&load_path)
            } else {
                Ok(LocalConfig::default())
            }
        },
        move |cfg: &LocalConfig| cfg.save_atomic(&save_path),
    )
}

/// Resolves the active `(repo_label, repo_dir)` by checking the current working directory's
/// ancestor chain for `dotler.toml` first (when `requested_label` is `None`), falling back
/// to `local_cfg.resolve_repo(requested_label)`.
pub fn resolve_repo_path_with_cwd(
    local_cfg: &LocalConfig,
    requested_label: Option<&str>,
) -> Result<(String, PathBuf), ConfigError> {
    if requested_label.is_none()
        && let Ok(current_dir) = std::env::current_dir()
        && let Some(repo_dir) = find_ancestor_repo_dir(&current_dir)
    {
        let canon_repo = fs::canonicalize(&repo_dir).unwrap_or_else(|_| repo_dir.clone());
        if let Some((reg_label, _)) = local_cfg.repos.iter().find(|(_, p)| {
            let exp = expand_tilde(p);
            fs::canonicalize(&exp).unwrap_or(exp) == canon_repo
        }) {
            return Ok((reg_label.clone(), repo_dir));
        }
        let label = repo_dir
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_else(|| "default".to_string());
        return Ok((label, repo_dir));
    }

    local_cfg.resolve_repo(requested_label)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_local_config_default_deserialization() {
        let config = LocalConfig::parse("").expect("empty config should parse to defaults");
        assert!(config.default_devices.is_empty());
        assert_eq!(config.default_repo, None);
        assert!(config.repos.is_empty());
    }

    #[test]
    fn test_local_config_full_parsing() {
        let content = r#"
default_devices = ["laptop", "workstation"]
default_repo = "main"

[repos]
main = "~/dotfiles"
work = "~/work-dotfiles"
"#;
        let config = LocalConfig::parse(content).expect("valid config should parse");
        assert_eq!(config.default_devices, vec!["laptop", "workstation"]);
        assert_eq!(config.default_repo.as_deref(), Some("main"));
        assert_eq!(config.repos.len(), 2);
        assert_eq!(
            config.repos.get("main").map(String::as_str),
            Some("~/dotfiles")
        );
        assert_eq!(
            config.repos.get("work").map(String::as_str),
            Some("~/work-dotfiles")
        );
    }

    #[test]
    fn test_local_config_deny_unknown_fields() {
        let content = r#"
devices = ["laptop"]
"#;
        let err =
            LocalConfig::parse(content).expect_err("unknown field 'devices' must be rejected");
        match err {
            ConfigError::UnknownField { field, .. } => {
                assert!(field.contains("devices"));
            }
            other => panic!("expected UnknownField, got: {other:?}"),
        }
    }

    #[test]
    fn test_validate_default_devices_valid() {
        let config = LocalConfig {
            default_devices: vec![
                "laptop".to_string(),
                "desktop_work".to_string(),
                "home-pc".to_string(),
            ],
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

fn local_with_repos(repos: &[(&str, &str)], default_repo: Option<&str>) -> LocalConfig {
    let mut cfg = LocalConfig::default();
    cfg.default_repo = default_repo.map(str::to_string);
    for &(k, v) in repos {
        cfg.repos.insert(k.to_string(), v.to_string());
    }
    cfg
}

    #[test]
    fn test_validate_default_devices_rejects_invalid_names() {
        for devices in [
            vec![""],
            vec!["laptop", "laptop"],
            vec!["my laptop"],
            vec!["dev/1"],
            vec!["dev\\1"],
            vec!["os-nux"],
            vec!["files"],
            vec!["vault"],
        ] {
            let config = LocalConfig {
                default_devices: devices.into_iter().map(str::to_string).collect(),
                ..Default::default()
            };
            assert!(matches!(config.validate(), Err(ConfigError::InvalidDeviceName { .. })));
        }
    }

    #[test]
    fn test_validate_default_repo_must_exist_in_repos() {
        let config = LocalConfig {
            default_repo: Some("nonexistent".to_string()),
            ..Default::default()
        };
        let err = config.validate().expect_err("default_repo not in repos must fail");
        assert!(matches!(err, ConfigError::InvalidDefaultRepo { label } if label == "nonexistent"));
    }

    #[test]
    fn test_validate_repos_rejects_invalid_label_or_path() {
        for (label, path, kind) in [
            ("bad label with spaces", "~/dotfiles", "label"),
            ("valid", "/etc/dotfiles", "home"),
            ("valid", "~/dotfiles/../escape", "blocked"),
            ("valid", "~/.config/dotler", "blocked"),
            ("valid", "~/repo/.git", "blocked"),
        ] {
            let err = local_with_repos(&[(label, path)], None)
                .validate()
                .expect_err("invalid repo config must fail");
            match kind {
                "label" => assert!(matches!(err, ConfigError::InvalidRepoLabel { .. })),
                "home" => assert!(matches!(err, ConfigError::InvalidHomePath { .. })),
                _ => assert!(matches!(err, ConfigError::HardBlockedPath { .. })),
            }
        }
    }

    #[test]
    fn test_resolve_repo_explicit_valid() {
        let cfg = local_with_repos(&[("myrepo", "~/my-dots")], None);
        assert_eq!(cfg.resolve_repo(Some("myrepo")).unwrap(), ("myrepo".to_string(), expand_tilde("~/my-dots")));
    }

    #[test]
    fn test_resolve_repo_explicit_unknown() {
        let err = LocalConfig::default().resolve_repo(Some("missing")).expect_err("should fail");
        assert!(matches!(err, ConfigError::UnknownRepoLabel { label } if label == "missing"));
    }

    #[test]
    fn test_resolve_repo_default_configured() {
        let cfg = local_with_repos(&[("repo1", "~/dots1"), ("repo2", "~/dots2")], Some("repo2"));
        assert_eq!(cfg.resolve_repo(None).unwrap(), ("repo2".to_string(), expand_tilde("~/dots2")));
    }

    #[test]
    fn test_resolve_repo_single_repo_auto_inference() {
        let cfg = local_with_repos(&[("only-one", "~/only-dots")], None);
        assert_eq!(cfg.resolve_repo(None).unwrap(), ("only-one".to_string(), expand_tilde("~/only-dots")));
    }

    #[test]
    fn test_resolve_repo_ambiguous_when_multiple_and_no_default() {
        let cfg = local_with_repos(&[("repo1", "~/dots1"), ("repo2", "~/dots2")], None);
        assert!(matches!(cfg.resolve_repo(None), Err(ConfigError::AmbiguousDefaultRepo)));
    }

    #[test]
    fn test_resolve_repo_no_repos_configured() {
        assert!(matches!(LocalConfig::default().resolve_repo(None), Err(ConfigError::NoReposConfigured)));
    }

    #[test]
    fn test_local_config_save_atomic() {
        let dir = tempdir().expect("tempdir");
        let config_path = dir.path().join("config.toml");

        let mut repos = BTreeMap::new();
        repos.insert("dotfiles".to_string(), "~/my-dots".to_string());
        let config = LocalConfig {
            default_devices: vec!["laptop".to_string()],
            default_repo: Some("dotfiles".to_string()),
            use_keyring: true,
            repos,
        };

        config
            .save_atomic(&config_path)
            .expect("atomic save must succeed");
        assert!(config_path.exists());

        let raw_saved = fs::read_to_string(&config_path).expect("read saved config");
        assert!(raw_saved.contains("# Priority-ordered device profile names for path matching\ndefault_devices = [\"laptop\"]"));
        assert!(raw_saved.contains(
            "# Default repository label used when --repo is omitted\ndefault_repo = \"dotfiles\""
        ));
        assert!(
            raw_saved.contains(
                "# Store and retrieve vault passphrases via OS keyring\nuse_keyring = true"
            )
        );
        assert!(
            raw_saved.contains("# Registered dotfile repositories (<label> = \"~/path\")\n[repos]")
        );

        let loaded = LocalConfig::load(&config_path).expect("loaded config must succeed");
        assert_eq!(loaded, config);
    }

    #[test]
    fn test_local_config_use_keyring_default_and_explicit_false() {
        let default_cfg = LocalConfig::parse("").expect("empty config should parse");
        assert!(default_cfg.use_keyring);

        let disabled_cfg =
            LocalConfig::parse("use_keyring = false\n").expect("use_keyring = false should parse");
        assert!(!disabled_cfg.use_keyring);

        let dir = tempdir().expect("tempdir");
        let config_path = dir.path().join("config.toml");
        disabled_cfg
            .save_atomic(&config_path)
            .expect("atomic save must succeed");
        let reloaded = LocalConfig::load(&config_path).expect("reload must succeed");
        assert!(!reloaded.use_keyring);
    }

    #[test]
    fn test_find_ancestor_repo_dir_walks_upward_to_nearest_dotler_toml() {
        let dir = tempdir().expect("tempdir");
        let repo_root = dir.path().join("my-dotfiles");
        let nested_sub = repo_root.join("nvim").join("lua").join("plugins");
        fs::create_dir_all(&nested_sub).unwrap();

        assert_eq!(find_ancestor_repo_dir(&nested_sub), None);

        fs::write(repo_root.join("dotler.toml"), "[nvim]\nfiles = \"*\"\n").unwrap();
        assert_eq!(find_ancestor_repo_dir(&nested_sub), Some(repo_root.clone()));
        assert_eq!(find_ancestor_repo_dir(&repo_root), Some(repo_root));
    }
}
