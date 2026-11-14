use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::ConfigError;

pub use crate::config::cascade::{OsInfo, RECOGNIZED_OS_KEYS, resolve_group_target_path};
pub use crate::config::path_security::{
    WalkDir, WalkEntry, is_symlink, validate_dir_no_symlinks, validate_os_dir_path,
    validate_os_target_path, validate_path_security, validate_rule_pattern,
};
pub use crate::config::selection::{
    SelectionMode, SelectionRule, evaluate_selection, parse_selection_rules,
    rules_have_effective_encryption,
};
pub use crate::config::template::{render_home_template, unrender_home_template};

pub const ROOT_VAULT_KEYS: &[&str] = &["vault_id", "password_slot", "recovery_slot", "vault_hint"];

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RepoConfig {
    pub vault: Option<VaultConfig>,
    pub groups: BTreeMap<String, GroupConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultConfig {
    pub vault_id: String,
    pub password_slot: String,
    pub recovery_slot: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault_hint: Option<String>,
}

fn build_vault_from_lookup<'a>(
    get: impl Fn(&str) -> Option<&'a str>,
) -> Result<VaultConfig, ConfigError> {
    let required = |key: &str| {
        get(key)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or(ConfigError::MissingVaultConfig)
            .map(str::to_string)
    };
    Ok(VaultConfig {
        vault_id: get("vault_id").map(str::trim).unwrap_or("").to_string(),
        password_slot: required("password_slot")?,
        recovery_slot: required("recovery_slot")?,
        vault_hint: get("vault_hint")
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
    })
}

impl VaultConfig {
    /// Parses external vault metadata from a TOML manifest or JSON payload,
    /// ignoring any unrelated group tables or extra keys.
    pub fn parse_external_payload(raw: &str) -> Result<Self, ConfigError> {
        if let Ok(table) = toml::from_str::<toml::Table>(raw) {
            return build_vault_from_lookup(|k| table.get(k).and_then(|v| v.as_str()));
        }

        match serde_json::from_str::<serde_json::Value>(raw) {
            Ok(serde_json::Value::Object(map)) => {
                build_vault_from_lookup(|k| map.get(k).and_then(|v| v.as_str()))
            }
            _ => {
                let err = toml::from_str::<toml::Table>(raw).unwrap_err();
                Err(ConfigError::TomlSyntaxError(err.to_string()))
            }
        }
    }
}

impl Serialize for RepoConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        let vault_field_count = match &self.vault {
            Some(v) => {
                if v.vault_hint.is_some() {
                    4
                } else {
                    3
                }
            }
            None => 0,
        };
        let mut map = serializer.serialize_map(Some(vault_field_count + self.groups.len()))?;
        if let Some(ref v) = self.vault {
            map.serialize_entry("vault_id", &v.vault_id)?;
            map.serialize_entry("password_slot", &v.password_slot)?;
            map.serialize_entry("recovery_slot", &v.recovery_slot)?;
            if let Some(ref h) = v.vault_hint {
                map.serialize_entry("vault_hint", h)?;
            }
        }
        for (group_name, group_cfg) in &self.groups {
            map.serialize_entry(group_name, group_cfg)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for RepoConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let mut table = toml::Table::deserialize(deserializer)?;

        let has_any_vault_key = ROOT_VAULT_KEYS.iter().any(|k| {
            table
                .get(*k)
                .is_some_and(|v| !matches!(v, toml::Value::Table(_)))
        });

        let vault = if has_any_vault_key {
            let mut vault_table = toml::Table::new();
            for &k in ROOT_VAULT_KEYS {
                if let Some(v) = table.remove(k) {
                    vault_table.insert(k.to_string(), v);
                }
            }
            let cfg = VaultConfig::deserialize(toml::Value::Table(vault_table))
                .map_err(serde::de::Error::custom)?;
            Some(cfg)
        } else {
            None
        };

        let mut groups = BTreeMap::new();
        for (key, value) in table {
            if ROOT_VAULT_KEYS.contains(&key.as_str()) {
                return Err(serde::de::Error::custom(format!(
                    "'{key}' is a reserved root vault key and cannot be used as a group section"
                )));
            }
            match value {
                toml::Value::Table(group_table) => {
                    let group = GroupConfig::deserialize(toml::Value::Table(group_table))
                        .map_err(serde::de::Error::custom)?;
                    groups.insert(key, group);
                }
                _ => {
                    return Err(serde::de::Error::custom(format!(
                        "unknown field `{key}`, expected `vault_id`, `password_slot`, `recovery_slot`, `vault_hint`, or a `[<group>]` section"
                    )));
                }
            }
        }

        Ok(RepoConfig { vault, groups })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct GroupConfig {
    #[serde(default)]
    pub files: String,
    #[serde(flatten)]
    pub paths: BTreeMap<String, String>,
}

impl RepoConfig {
    pub fn parse(content: &str) -> Result<Self, ConfigError> {
        let repo: RepoConfig = toml::from_str(content).map_err(|e| {
            let msg = e.to_string();
            if msg.contains("unknown field") {
                ConfigError::UnknownField {
                    field: msg.clone(),
                    hint: "Check dotler.toml for unexpected root keys or group fields.".to_string(),
                }
            } else {
                ConfigError::TomlSyntaxError(msg)
            }
        })?;

        repo.validate()?;
        Ok(repo)
    }

    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        if is_symlink(path) {
            return Err(ConfigError::HardBlockedPath {
                path: path.display().to_string(),
                reason: "symbolic links are prohibited inside a dotler repository".to_string(),
            });
        }
        let content = fs::read_to_string(path)?;
        Self::parse(&content)
    }

    pub fn load_without_vault_check(path: &Path) -> Result<Self, ConfigError> {
        if is_symlink(path) {
            return Err(ConfigError::HardBlockedPath {
                path: path.display().to_string(),
                reason: "symbolic links are prohibited inside a dotler repository".to_string(),
            });
        }
        let content = fs::read_to_string(path)?;
        let repo: RepoConfig = toml::from_str(&content).map_err(|e| {
            let msg = e.to_string();
            if msg.contains("unknown field") {
                ConfigError::UnknownField {
                    field: msg.clone(),
                    hint: "Check dotler.toml for unexpected root keys or group fields.".to_string(),
                }
            } else {
                ConfigError::TomlSyntaxError(msg)
            }
        })?;
        repo.validate_inner(false)?;
        Ok(repo)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        self.validate_inner(true)
    }

    fn validate_inner(&self, require_vault: bool) -> Result<(), ConfigError> {
        let mut has_encrypted_rules = false;

        for (group_name, group) in &self.groups {
            if ROOT_VAULT_KEYS.contains(&group_name.as_str()) {
                return Err(ConfigError::InvalidDeviceName {
                    device: group_name.clone(),
                    reason: format!(
                        "'{group_name}' is a reserved root vault key and cannot be a group"
                    ),
                });
            }

            for (key, path) in &group.paths {
                if key.starts_with("os-") && !RECOGNIZED_OS_KEYS.contains(&key.as_str()) {
                    return Err(ConfigError::UnknownOsKey {
                        key: key.clone(),
                        hint: format!("Allowed OS keys are: {}", RECOGNIZED_OS_KEYS.join(", ")),
                    });
                }

                validate_path_security(path)?;
            }

            let rules = parse_selection_rules(&group.files)?;
            if rules_have_effective_encryption(&rules) {
                has_encrypted_rules = true;
            }
            for rule in &rules {
                // Cross-validate resolved target path against path security policy
                for path in group.paths.values() {
                    let combined = format!("{}/{}", path.trim_end_matches('/'), rule.pattern);
                    validate_path_security(&combined)?;
                }
            }
        }

        if require_vault && has_encrypted_rules && self.vault.is_none() {
            return Err(ConfigError::MissingVaultConfig);
        }

        Ok(())
    }

    pub fn save_atomic(&self, path: &Path) -> Result<(), ConfigError> {
        self.validate()?;
        if path.is_file()
            && let Ok(existing_str) = fs::read_to_string(path)
            && let Ok(existing_cfg) = toml::from_str::<RepoConfig>(&existing_str)
            && existing_cfg.groups == self.groups
        {
            match (&existing_cfg.vault, &self.vault) {
                (Some(old_v), Some(new_v)) => {
                    let updated = update_vault_manifest_section(&existing_str, old_v, new_v);
                    return write_config_file(path, updated.as_bytes());
                }
                (None, Some(new_v)) => {
                    let manifest_str = insert_vault_root_keys(&existing_str, new_v);
                    return write_config_file(path, manifest_str.as_bytes());
                }
                _ => {}
            }
        }

        let body = toml::to_string_pretty(self)
            .map_err(|e| ConfigError::TomlSyntaxError(e.to_string()))?;
        let serialized = format!(
            "{}\n\n{}",
            crate::agent::briefing::DOTLER_TOML_AI_HINT.trim_end(),
            body
        );
        write_config_file(path, serialized.as_bytes())
    }
}

fn write_config_file(path: &Path, bytes: &[u8]) -> Result<(), ConfigError> {
    crate::config::lock::write_file_safe(path, bytes).map_err(|e| match e {
        crate::config::StateError::Io(io) => ConfigError::IoError(io),
        other => ConfigError::AtomicRenameFailed(other.to_string()),
    })
}

pub fn format_vault_root_keys(vault: &VaultConfig) -> String {
    let mut out = format!(
        "vault_id = \"{}\"\npassword_slot = \"{}\"\nrecovery_slot = \"{}\"\n",
        vault.vault_id, vault.password_slot, vault.recovery_slot
    );
    if let Some(ref h) = vault.vault_hint {
        let escaped = toml::Value::String(h.clone()).to_string();
        out.push_str(&format!("vault_hint = {escaped}\n"));
    }
    out
}

pub fn insert_vault_root_keys(existing_str: &str, new_v: &VaultConfig) -> String {
    let vault_block = format_vault_root_keys(new_v);
    let mut header_end_byte = 0;
    let mut saw_comment = false;

    for line in existing_str.split_inclusive('\n') {
        let trimmed = line.trim();
        if !saw_comment && trimmed.is_empty() {
            header_end_byte += line.len();
            continue;
        }
        if trimmed.starts_with('#') {
            saw_comment = true;
            header_end_byte += line.len();
        } else {
            break;
        }
    }

    let header = existing_str[..header_end_byte].trim_end();
    let rest = existing_str[header_end_byte..].trim_start_matches(['\r', '\n']);

    match (!header.is_empty(), !rest.is_empty()) {
        (true, true) => format!("{header}\n\n{vault_block}\n{rest}"),
        (true, false) => format!("{header}\n\n{vault_block}"),
        (false, true) => format!("{vault_block}\n{rest}"),
        (false, false) => vault_block,
    }
}

pub fn update_vault_manifest_section(
    manifest_str: &str,
    old_cfg: &VaultConfig,
    new_cfg: &VaultConfig,
) -> String {
    let mut updated = manifest_str.replace(
        &format!("password_slot = \"{}\"", old_cfg.password_slot),
        &format!("password_slot = \"{}\"", new_cfg.password_slot),
    );
    updated = updated.replace(
        &format!("recovery_slot = \"{}\"", old_cfg.recovery_slot),
        &format!("recovery_slot = \"{}\"", new_cfg.recovery_slot),
    );
    if new_cfg.vault_hint != old_cfg.vault_hint {
        match (&old_cfg.vault_hint, &new_cfg.vault_hint) {
            (Some(old_h), Some(new_h)) => {
                let old_val = toml::Value::String(old_h.clone()).to_string();
                let new_val = toml::Value::String(new_h.clone()).to_string();
                updated = updated.replace(
                    &format!("vault_hint = {old_val}"),
                    &format!("vault_hint = {new_val}"),
                );
            }
            (None, Some(new_h)) => {
                let new_val = toml::Value::String(new_h.clone()).to_string();
                let target = format!("recovery_slot = \"{}\"", new_cfg.recovery_slot);
                updated = updated.replace(&target, &format!("{target}\nvault_hint = {new_val}"));
            }
            (Some(old_h), None) => {
                let old_val = toml::Value::String(old_h.clone()).to_string();
                updated = updated.replace(&format!("vault_hint = {old_val}\n"), "");
                updated = updated.replace(&format!("vault_hint = {old_val}"), "");
            }
            (None, None) => {}
        }
    }
    updated
}

/// Creates a lazy [`Resource`] for `<repo>/dotler.toml`.
pub fn get_repo_config(manifest_path: PathBuf) -> crate::config::Resource<RepoConfig, ConfigError> {
    let load_path = manifest_path.clone();
    let save_path = manifest_path;
    crate::config::Resource::new(
        move || RepoConfig::load(&load_path),
        move |cfg: &RepoConfig| cfg.save_atomic(&save_path),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_repo_config_parsing_with_vault() {
        let content = r#"
vault_id = "0123456789abcdef"
password_slot = "cGFzc3dvcmRfc2xvdF9wbGFjZWhvbGRlcg=="
recovery_slot = "cmVjb3Zlcnlfc2xvdF9wbGFjZWhvbGRlcg=="
vault_hint = "optional hint"

[nvim]
files = """
init.lua
lua/*
"""
laptop = "~/.config/nvim"
os-nux = "~/.config/nvim"

[vault]
files = "config.hcl"
os-nux = "~/.config/vault"
"#;
        let config =
            RepoConfig::parse(content).expect("repo config with root vault keys should parse");
        assert!(config.vault.is_some());
        let vault = config.vault.unwrap();
        assert_eq!(vault.vault_id, "0123456789abcdef");
        assert_eq!(vault.vault_hint.as_deref(), Some("optional hint"));
        assert_eq!(config.groups.len(), 2);
        assert!(config.groups.contains_key("nvim"));
        assert!(config.groups.contains_key("vault"));
    }

    #[test]
    fn test_insert_vault_root_keys_below_header_comment() {
        let initial = format!(
            "{}\n\n# [bash]\n# os-nux = \"~\"\n",
            crate::agent::briefing::DOTLER_TOML_AI_HINT.trim_end()
        );
        let vault = VaultConfig {
            vault_id: "0123456789abcdef".to_string(),
            password_slot: "cGFzc3dvcmQ=".to_string(),
            recovery_slot: "cmVjb3Zlcnk=".to_string(),
            vault_hint: Some("pet name".to_string()),
        };
        let inserted = insert_vault_root_keys(&initial, &vault);
        let banner_end = inserted
            .find("# ──────────────────────────────────────────────────────────────────")
            .unwrap();
        let vault_pos = inserted.find("vault_id = \"0123456789abcdef\"").unwrap();
        let hint_pos = inserted.find("vault_hint = \"pet name\"").unwrap();
        let bash_pos = inserted.find("# [bash]").unwrap();
        assert!(banner_end < vault_pos);
        assert!(vault_pos < hint_pos);
        assert!(hint_pos < bash_pos);
    }

    #[test]
    fn test_repo_config_parsing_without_vault() {
        let content = r#"
[git]
files = "config"
os-nux = "~/.config/git"
"#;
        let config = RepoConfig::parse(content).expect("repo config without vault should parse");
        assert!(config.vault.is_none());
        assert!(config.groups.contains_key("git"));
    }

    #[test]
    fn test_vault_config_deny_unknown_fields() {
        let content = r#"
vault_id = "0123456789abcdef"
password_slot = "cGFzc3dvcmQ="
recovery_slot = "cmVjb3Zlcnk="
extra_field = "unexpected"
"#;
        let err = RepoConfig::parse(content).expect_err("unknown root field must fail");
        assert!(matches!(
            err,
            ConfigError::UnknownField { .. } | ConfigError::TomlSyntaxError(_)
        ));
    }

    #[test]
    fn test_overridden_encrypt_rule_does_not_require_vault() {
        let content = r#"
[bash]
os-nux = "~"
os-mac = "~"
os-win = "~"
os-bsd = "~"
files = """
!*
.bashrc enc
.bashrc
"""
"#;
        let config = RepoConfig::parse(content)
            .expect("overridden enc rule must not require [vault] section");
        let rules = parse_selection_rules(&config.groups["bash"].files).unwrap();
        assert!(!rules_have_effective_encryption(&rules));
        assert_eq!(
            evaluate_selection(&rules, ".bashrc"),
            Some(SelectionMode::PlaintextInclude)
        );
    }

    #[test]
    fn test_vault_required_when_encrypted_rule_present() {
        for toml in [
            "[secrets]\nfiles = \"id_rsa enc\"\nos-nux = \"~/.ssh\"\n",
            "[secrets]\nfiles = \"credentials.toml enc tmpl\"\nos-nux = \"~/.config/app\"\n",
        ] {
            let err = RepoConfig::parse(toml).expect_err("enc rule without vault must fail");
            assert!(matches!(err, ConfigError::MissingVaultConfig));
        }
    }

    #[test]
    fn test_load_without_vault_check_allows_encrypted_rules_before_vault_init() {
        let dir = tempfile::tempdir().unwrap();
        let manifest_path = dir.path().join("dotler.toml");
        fs::write(
            &manifest_path,
            "[shell]\nos-nux = \"~\"\nfiles = \"secret.txt enc\"\n",
        )
        .unwrap();

        assert!(matches!(
            RepoConfig::load(&manifest_path),
            Err(ConfigError::MissingVaultConfig)
        ));
        let loaded = RepoConfig::load_without_vault_check(&manifest_path)
            .expect("load_without_vault_check must allow encrypted rules before vault init");
        assert!(loaded.vault.is_none());
        assert!(loaded.groups.contains_key("shell"));
    }
}
