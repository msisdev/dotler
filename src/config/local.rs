use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::state::atomic_write_file;
use crate::config::{ConfigError, StateError};

pub const LOCAL_CONFIG_DIR: &str = "~/.config/dotler";
pub const LOCAL_CONFIG_FILE: &str = "~/.config/dotler/config.toml";
pub const RESERVED_OS_PREFIX: &str = "os-";

pub fn expand_tilde(path: &str) -> PathBuf {
    if path == "~" {
        dirs::home_dir().unwrap_or_else(|| PathBuf::from("."))
    } else if let Some(stripped) = path.strip_prefix("~/") {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(stripped)
    } else {
        PathBuf::from(path)
    }
}

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

fn is_true(val: &bool) -> bool {
    *val
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalConfig {
    #[serde(default)]
    pub default_devices: Vec<String>,
    #[serde(default)]
    pub default_repo: Option<String>,
    #[serde(default = "default_use_keyring", skip_serializing_if = "is_true")]
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

    pub fn save_atomic(&self, path: &Path) -> Result<(), ConfigError> {
        self.validate()?;
        let serialized = toml::to_string_pretty(self)
            .map_err(|e| ConfigError::TomlSyntaxError(e.to_string()))?;

        atomic_write_file(path, serialized.as_bytes()).map_err(|e| match e {
            StateError::Io(io) => ConfigError::IoError(io),
            other => ConfigError::AtomicRenameFailed(other.to_string()),
        })
    }
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

    #[test]
    fn test_validate_default_devices_reject_empty() {
        let config = LocalConfig {
            default_devices: vec!["".to_string()],
            ..Default::default()
        };
        let err = config.validate().expect_err("empty device name must fail");
        assert!(matches!(err, ConfigError::InvalidDeviceName { .. }));
    }

    #[test]
    fn test_validate_default_devices_reject_duplicates() {
        let config = LocalConfig {
            default_devices: vec!["laptop".to_string(), "laptop".to_string()],
            ..Default::default()
        };
        let err = config
            .validate()
            .expect_err("duplicate device names must fail");
        assert!(matches!(err, ConfigError::InvalidDeviceName { .. }));
    }

    #[test]
    fn test_validate_default_devices_reject_whitespace() {
        let config = LocalConfig {
            default_devices: vec!["my laptop".to_string()],
            ..Default::default()
        };
        let err = config
            .validate()
            .expect_err("device with whitespace must fail");
        assert!(matches!(err, ConfigError::InvalidDeviceName { .. }));
    }

    #[test]
    fn test_validate_default_devices_reject_slashes() {
        let config1 = LocalConfig {
            default_devices: vec!["dev/1".to_string()],
            ..Default::default()
        };
        let err = config1
            .validate()
            .expect_err("device with forward slash must fail");
        assert!(matches!(err, ConfigError::InvalidDeviceName { .. }));

        let config2 = LocalConfig {
            default_devices: vec!["dev\\1".to_string()],
            ..Default::default()
        };
        let err = config2
            .validate()
            .expect_err("device with backslash must fail");
        assert!(matches!(err, ConfigError::InvalidDeviceName { .. }));
    }

    #[test]
    fn test_validate_default_devices_reject_reserved_os_prefix() {
        let config = LocalConfig {
            default_devices: vec!["os-linux".to_string()],
            ..Default::default()
        };
        let err = config
            .validate()
            .expect_err("device with 'os-' prefix must fail");
        assert!(matches!(err, ConfigError::InvalidDeviceName { .. }));
    }

    #[test]
    fn test_validate_default_devices_reject_reserved_names() {
        let config1 = LocalConfig {
            default_devices: vec!["files".to_string()],
            ..Default::default()
        };
        let err = config1
            .validate()
            .expect_err("reserved device 'files' must fail");
        assert!(matches!(err, ConfigError::InvalidDeviceName { .. }));

        let config2 = LocalConfig {
            default_devices: vec!["vault".to_string()],
            ..Default::default()
        };
        let err = config2
            .validate()
            .expect_err("reserved device 'vault' must fail");
        assert!(matches!(err, ConfigError::InvalidDeviceName { .. }));
    }

    #[test]
    fn test_validate_default_repo_must_exist_in_repos() {
        let config = LocalConfig {
            default_repo: Some("nonexistent".to_string()),
            ..Default::default()
        };
        let err = config
            .validate()
            .expect_err("default_repo not in repos must fail");
        assert!(matches!(err, ConfigError::InvalidDefaultRepo { label } if label == "nonexistent"));
    }

    #[test]
    fn test_validate_repos_rejects_invalid_label_or_path() {
        let mut config = LocalConfig::default();
        config.repos.insert(
            "bad label with spaces".to_string(),
            "~/dotfiles".to_string(),
        );
        let err = config.validate().expect_err("invalid label must fail");
        assert!(matches!(err, ConfigError::InvalidRepoLabel { .. }));

        let mut config2 = LocalConfig::default();
        config2
            .repos
            .insert("valid".to_string(), "/etc/dotfiles".to_string());
        let err2 = config2
            .validate()
            .expect_err("path not starting with ~ must fail");
        assert!(matches!(err2, ConfigError::InvalidHomePath { .. }));

        let mut config3 = LocalConfig::default();
        config3
            .repos
            .insert("valid".to_string(), "~/dotfiles/../escape".to_string());
        let err3 = config3.validate().expect_err("path with .. must fail");
        assert!(matches!(err3, ConfigError::HardBlockedPath { .. }));

        let mut config4 = LocalConfig::default();
        config4
            .repos
            .insert("valid".to_string(), "~/.config/dotler".to_string());
        let err4 = config4
            .validate()
            .expect_err("path inside ~/.config/dotler must fail");
        assert!(matches!(err4, ConfigError::HardBlockedPath { .. }));

        let mut config5 = LocalConfig::default();
        config5
            .repos
            .insert("valid".to_string(), "~/repo/.git".to_string());
        let err5 = config5
            .validate()
            .expect_err("path targeting .git must fail");
        assert!(matches!(err5, ConfigError::HardBlockedPath { .. }));
    }

    #[test]
    fn test_resolve_repo_explicit_valid() {
        let mut config = LocalConfig::default();
        config
            .repos
            .insert("myrepo".to_string(), "~/my-dots".to_string());

        let (label, path) = config.resolve_repo(Some("myrepo")).expect("should resolve");
        assert_eq!(label, "myrepo");
        assert_eq!(path, expand_tilde("~/my-dots"));
    }

    #[test]
    fn test_resolve_repo_explicit_unknown() {
        let config = LocalConfig::default();
        let err = config
            .resolve_repo(Some("missing"))
            .expect_err("should fail");
        assert!(matches!(err, ConfigError::UnknownRepoLabel { label } if label == "missing"));
    }

    #[test]
    fn test_resolve_repo_default_configured() {
        let mut config = LocalConfig::default();
        config
            .repos
            .insert("repo1".to_string(), "~/dots1".to_string());
        config
            .repos
            .insert("repo2".to_string(), "~/dots2".to_string());
        config.default_repo = Some("repo2".to_string());

        let (label, path) = config.resolve_repo(None).expect("should resolve default");
        assert_eq!(label, "repo2");
        assert_eq!(path, expand_tilde("~/dots2"));
    }

    #[test]
    fn test_resolve_repo_single_repo_auto_inference() {
        let mut config = LocalConfig::default();
        config
            .repos
            .insert("only-one".to_string(), "~/only-dots".to_string());

        let (label, path) = config
            .resolve_repo(None)
            .expect("single repo should auto-resolve");
        assert_eq!(label, "only-one");
        assert_eq!(path, expand_tilde("~/only-dots"));
    }

    #[test]
    fn test_resolve_repo_ambiguous_when_multiple_and_no_default() {
        let mut config = LocalConfig::default();
        config
            .repos
            .insert("repo1".to_string(), "~/dots1".to_string());
        config
            .repos
            .insert("repo2".to_string(), "~/dots2".to_string());

        let err = config
            .resolve_repo(None)
            .expect_err("ambiguous repos must fail");
        assert!(matches!(err, ConfigError::AmbiguousDefaultRepo));
    }

    #[test]
    fn test_resolve_repo_no_repos_configured() {
        let config = LocalConfig::default();
        let err = config
            .resolve_repo(None)
            .expect_err("empty repos must fail");
        assert!(matches!(err, ConfigError::NoReposConfigured));
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
