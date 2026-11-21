use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::ConfigError;

pub use crate::config::cascade::{OsInfo, RECOGNIZED_OS_KEYS, resolve_group_target_path};
pub use crate::config::path_security::{
    WalkDir, WalkEntry, is_cwd_group_path, is_home_group_path, is_symlink, prune_empty_parent_dirs,
    validate_dir_no_symlinks, validate_os_dir_path, validate_os_dir_path_with_home,
    validate_os_target_path, validate_os_target_path_with_home, validate_path_security,
    validate_repo_target_disjointness, validate_rule_pattern,
};
pub use crate::config::selection::{
    SelectionMode, SelectionRule, evaluate_selection, find_literal_full_enc_rules,
    parse_selection_rules, rules_have_effective_encryption, rules_have_effective_full_encryption,
};
pub use crate::config::template::{render_home_template, unrender_home_template};

pub const ROOT_VAULT_KEYS: &[&str] = &["vault_id", "password_slot", "recovery_slot", "vault_hint"];

/// Returns `true` if `group_name` is a dot-separated hierarchical sub-group (`parent.child`).
pub fn is_sub_group_name(group_name: &str) -> bool {
    group_name.contains('.')
}

/// Splits a canonical group name into its top-level root group name and optional slash-separated subpath.
pub fn split_group_root_and_subpath(group_name: &str) -> (&str, Option<String>) {
    match group_name.split_once('.') {
        Some((root, rest)) => (root, Some(rest.replace('.', "/"))),
        None => (group_name, None),
    }
}

/// Converts a dot-separated canonical group name (`vault.sleep`) into its relative repository directory (`vault/sleep`).
pub fn group_repo_rel_path(group_name: &str) -> PathBuf {
    let mut rel = PathBuf::new();
    for seg in group_name.split('.') {
        rel.push(seg);
    }
    rel
}

/// Resolves the repository storage directory (`<repo_dir>/vault/sleep`) for `group_name`.
pub fn group_repo_dir(repo_dir: &Path, group_name: &str) -> PathBuf {
    repo_dir.join(group_repo_rel_path(group_name))
}

/// Returns `true` if `group_name` equals `filter` or resides in `filter`'s dot-separated subtree (`<filter>.*`).
pub fn group_matches_filter(group_name: &str, filter: &str) -> bool {
    group_name == filter
        || group_name
            .strip_prefix(filter)
            .is_some_and(|rest| rest.starts_with('.'))
}

/// Returns `true` if `rel_path` (relative to an ancestor group) falls inside any delegated child sub-group directory.
pub fn is_delegated_to_subgroup(rel_path: &str, descendant_subpaths: &[String]) -> bool {
    let clean = rel_path.trim_start_matches("./").trim_matches('/');
    if clean.is_empty() {
        return false;
    }
    descendant_subpaths.iter().any(|sub| {
        clean == sub
            || clean
                .strip_prefix(sub.as_str())
                .is_some_and(|rest| rest.starts_with('/'))
    })
}

pub(crate) fn join_derived_group_path(root_path: &str, subpath: &str) -> String {
    let trimmed = root_path.trim_end_matches('/');
    let clean_sub = subpath.trim_matches('/');
    if clean_sub.is_empty() {
        return trimmed.to_string();
    }
    if trimmed == "~" {
        format!("~/{clean_sub}")
    } else if trimmed == "." {
        format!("./{clean_sub}")
    } else {
        format!("{trimmed}/{clean_sub}")
    }
}

fn validate_group_segment(seg: &str, full_name: &str, is_root: bool) -> Result<(), ConfigError> {
    if seg.is_empty() {
        return Err(ConfigError::InvalidGroupHierarchy {
            group: full_name.to_string(),
            reason: "group name segment cannot be empty".to_string(),
        });
    }
    if seg == "."
        || seg == ".."
        || seg == ".git"
        || seg.contains('/')
        || seg.contains('\\')
        || seg.contains('$')
        || seg.contains('%')
        || seg.contains('\0')
    {
        return Err(ConfigError::HardBlockedPath {
            path: full_name.to_string(),
            reason: "group name contains prohibited path separator, traversal, or reserved segment"
                .to_string(),
        });
    }
    if seg.contains('.') {
        return Err(ConfigError::InvalidGroupHierarchy {
            group: full_name.to_string(),
            reason: "quoted dots in group names are prohibited; use unquoted TOML table syntax '[parent.child]'"
                .to_string(),
        });
    }
    if is_root && ROOT_VAULT_KEYS.contains(&seg) {
        return Err(ConfigError::InvalidDeviceName {
            device: full_name.to_string(),
            reason: format!("'{seg}' is a reserved root vault key and cannot be a group"),
        });
    }
    if !is_root && (seg == "files" || seg.starts_with("os-")) {
        return Err(ConfigError::InvalidGroupHierarchy {
            group: full_name.to_string(),
            reason: format!(
                "sub-group segment '{seg}' conflicts with reserved group field or OS key prefix"
            ),
        });
    }
    Ok(())
}

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

        let mut root_tables: BTreeMap<String, toml::Table> = BTreeMap::new();
        for (group_name, group_cfg) in &self.groups {
            let mut segments = group_name.split('.');
            let Some(root_seg) = segments.next() else {
                continue;
            };
            let rest: Vec<&str> = segments.collect();
            let root_tbl = root_tables.entry(root_seg.to_string()).or_default();

            if rest.is_empty() {
                for (k, v) in &group_cfg.paths {
                    root_tbl.insert(k.clone(), toml::Value::String(v.clone()));
                }
                if !group_cfg.files.is_empty() || !self.has_subgroups(root_seg) {
                    root_tbl.insert(
                        "files".to_string(),
                        toml::Value::String(group_cfg.files.clone()),
                    );
                }
            } else {
                let mut curr = root_tbl;
                for seg in rest {
                    let entry = curr
                        .entry(seg.to_string())
                        .or_insert_with(|| toml::Value::Table(toml::Table::new()));
                    curr = match entry {
                        toml::Value::Table(t) => t,
                        _ => {
                            unreachable!("validated group segments never collide with scalar keys")
                        }
                    };
                }
                curr.insert(
                    "files".to_string(),
                    toml::Value::String(group_cfg.files.clone()),
                );
            }
        }

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
        let mut map = serializer.serialize_map(Some(vault_field_count + root_tables.len()))?;
        if let Some(ref v) = self.vault {
            map.serialize_entry("vault_id", &v.vault_id)?;
            map.serialize_entry("password_slot", &v.password_slot)?;
            map.serialize_entry("recovery_slot", &v.recovery_slot)?;
            if let Some(ref h) = v.vault_hint {
                map.serialize_entry("vault_hint", h)?;
            }
        }
        for (root_name, tbl) in &root_tables {
            map.serialize_entry(root_name, tbl)?;
        }
        map.end()
    }
}

fn collect_group_tables_recursive(
    root_name: &str,
    current_name: &str,
    table: toml::Table,
    is_root: bool,
    groups: &mut BTreeMap<String, GroupConfig>,
) -> Result<(), ConfigError> {
    let mut files_opt: Option<String> = None;
    let mut paths: BTreeMap<String, String> = BTreeMap::new();
    let mut sub_tables: Vec<(String, toml::Table)> = Vec::new();

    for (k, v) in table {
        match v {
            toml::Value::Table(sub_tbl) => {
                sub_tables.push((k, sub_tbl));
            }
            toml::Value::String(s) => {
                if k == "files" {
                    files_opt = Some(s);
                } else if is_root {
                    paths.insert(k, s);
                } else {
                    return Err(ConfigError::InvalidGroupHierarchy {
                        group: current_name.to_string(),
                        reason: format!(
                            "target path key '{k}' cannot be defined on a sub-group; define device and OS paths only on top-level group '[{root_name}]'"
                        ),
                    });
                }
            }
            other => {
                return Err(ConfigError::TomlSyntaxError(format!(
                    "invalid type '{}' for key '{k}' in '[{current_name}]', expected a string or sub-group table",
                    other.type_str()
                )));
            }
        }
    }

    if is_root {
        groups.insert(
            current_name.to_string(),
            GroupConfig {
                files: files_opt.unwrap_or_default(),
                paths,
            },
        );
    } else if let Some(files) = files_opt {
        groups.insert(
            current_name.to_string(),
            GroupConfig {
                files,
                paths: BTreeMap::new(),
            },
        );
    } else if sub_tables.is_empty() {
        return Err(ConfigError::InvalidGroupHierarchy {
            group: current_name.to_string(),
            reason: format!("sub-group '[{current_name}]' must define a 'files' selection block"),
        });
    }

    for (child_seg, child_tbl) in sub_tables {
        let child_full = format!("{current_name}.{child_seg}");
        validate_group_segment(&child_seg, &child_full, false)?;
        collect_group_tables_recursive(root_name, &child_full, child_tbl, false, groups)?;
    }

    Ok(())
}

impl RepoConfig {
    fn from_toml_table(mut table: toml::Table) -> Result<Self, ConfigError> {
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
                .map_err(|e| ConfigError::TomlSyntaxError(e.to_string()))?;
            Some(cfg)
        } else {
            None
        };

        let mut groups = BTreeMap::new();
        for (key, value) in table {
            if ROOT_VAULT_KEYS.contains(&key.as_str()) {
                return Err(ConfigError::InvalidDeviceName {
                    device: key.clone(),
                    reason: format!(
                        "'{key}' is a reserved root vault key and cannot be used as a group section"
                    ),
                });
            }
            match value {
                toml::Value::Table(group_table) => {
                    validate_group_segment(&key, &key, true)?;
                    collect_group_tables_recursive(&key, &key, group_table, true, &mut groups)?;
                }
                _ => {
                    return Err(ConfigError::UnknownField {
                        field: format!(
                            "unknown field `{key}`, expected `vault_id`, `password_slot`, `recovery_slot`, `vault_hint`, or a `[<group>]` section"
                        ),
                        hint: "Check dotler.toml for unexpected root keys or group fields."
                            .to_string(),
                    });
                }
            }
        }

        Ok(RepoConfig { vault, groups })
    }
}

impl<'de> Deserialize<'de> for RepoConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let table = toml::Table::deserialize(deserializer)?;
        RepoConfig::from_toml_table(table).map_err(serde::de::Error::custom)
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
    /// Returns `true` if any configured sub-group exists under `group_name` (`<group_name>.*`).
    pub fn has_subgroups(&self, group_name: &str) -> bool {
        let prefix = format!("{group_name}.");
        self.groups.keys().any(|k| k.starts_with(&prefix))
    }

    /// Returns `true` if `group_name` is a root group that only defines base paths for sub-groups
    /// and declares no `files` rules of its own.
    pub fn is_anchor_only_group(&self, group_name: &str) -> bool {
        !is_sub_group_name(group_name)
            && self.has_subgroups(group_name)
            && self
                .groups
                .get(group_name)
                .is_some_and(|g| g.files.trim().is_empty())
    }

    /// Returns the effective device/OS target path map for `group_name`, deriving subpaths from
    /// the top-level group when `group_name` is a dot-separated sub-group.
    pub fn effective_group_paths(&self, group_name: &str) -> BTreeMap<String, String> {
        let (root_name, subpath_opt) = split_group_root_and_subpath(group_name);
        let Some(root_group) = self.groups.get(root_name) else {
            return BTreeMap::new();
        };
        match subpath_opt {
            None => root_group.paths.clone(),
            Some(subpath) => root_group
                .paths
                .iter()
                .map(|(k, p)| (k.clone(), join_derived_group_path(p, &subpath)))
                .collect(),
        }
    }

    /// Resolves the active target base path for `group_name` across `devices` and `os_info`,
    /// deriving nested subpaths from the top-level group when needed.
    pub fn resolve_target_path(
        &self,
        group_name: &str,
        devices: &[String],
        os_info: &OsInfo,
    ) -> Option<String> {
        let (root_name, subpath_opt) = split_group_root_and_subpath(group_name);
        let root_group = self.groups.get(root_name)?;
        let root_target = resolve_group_target_path(root_group, devices, os_info)?;
        match subpath_opt {
            None => Some(root_target),
            Some(subpath) => Some(join_derived_group_path(&root_target, &subpath)),
        }
    }

    /// Returns slash-separated relative subpaths (relative to `group_name`) owned by configured
    /// descendant sub-groups of `group_name`.
    pub fn descendant_subpaths(&self, group_name: &str) -> Vec<String> {
        let prefix = format!("{group_name}.");
        self.groups
            .keys()
            .filter_map(|k| k.strip_prefix(&prefix).map(|rest| rest.replace('.', "/")))
            .collect()
    }

    /// Resolves the most-specific group owning `rel_path` (relative to `start_group`) along with
    /// the corresponding relative path inside that owning group.
    pub fn resolve_owning_group<'a>(
        &'a self,
        start_group: &'a str,
        rel_path: &str,
    ) -> (&'a str, String) {
        let clean = rel_path
            .trim_start_matches("./")
            .trim_start_matches('/')
            .to_string();
        let prefix = format!("{start_group}.");
        let mut best: Option<(&str, usize, String)> = None;

        for candidate in self.groups.keys() {
            if let Some(sub_dot) = candidate.strip_prefix(&prefix) {
                let subpath = sub_dot.replace('.', "/");
                if let Some(rest) = clean
                    .strip_prefix(subpath.as_str())
                    .and_then(|r| r.strip_prefix('/'))
                    && !rest.is_empty()
                    && best
                        .as_ref()
                        .is_none_or(|(_, prev_len, _)| subpath.len() > *prev_len)
                {
                    best = Some((candidate.as_str(), subpath.len(), rest.to_string()));
                }
            }
        }

        match best {
            Some((owner, _, sub_rel)) => (owner, sub_rel),
            None => (start_group, clean),
        }
    }

    /// Expands `filters` using subtree prefix matching (`vault` matches `vault` and `vault.*`),
    /// returning deduplicated canonical group names in deterministic order or the first unmatched filter.
    pub fn matching_groups<'a>(&'a self, filters: &[String]) -> Result<Vec<&'a str>, String> {
        if filters.is_empty() {
            return Ok(self.groups.keys().map(String::as_str).collect());
        }
        for f in filters {
            if !self.groups.keys().any(|g| group_matches_filter(g, f)) {
                return Err(f.clone());
            }
        }
        Ok(self
            .groups
            .keys()
            .filter(|g| filters.iter().any(|f| group_matches_filter(g, f)))
            .map(String::as_str)
            .collect())
    }

    pub fn parse(content: &str) -> Result<Self, ConfigError> {
        let table: toml::Table =
            toml::from_str(content).map_err(|e| ConfigError::TomlSyntaxError(e.to_string()))?;
        let repo = Self::from_toml_table(table)?;
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
        let table: toml::Table =
            toml::from_str(&content).map_err(|e| ConfigError::TomlSyntaxError(e.to_string()))?;
        let repo = Self::from_toml_table(table)?;
        repo.validate_inner(false)?;
        Ok(repo)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        self.validate_inner(true)
    }

    pub(crate) fn validate_inner_for_clone(&self) -> Result<(), ConfigError> {
        self.validate_inner(false)
    }

    fn validate_inner(&self, require_vault: bool) -> Result<(), ConfigError> {
        let mut has_encrypted_rules = false;

        for (group_name, group) in &self.groups {
            for (idx, seg) in group_name.split('.').enumerate() {
                validate_group_segment(seg, group_name, idx == 0)?;
            }

            let (root_name, subpath_opt) = split_group_root_and_subpath(group_name);
            if subpath_opt.is_some() {
                if !group.paths.is_empty() {
                    return Err(ConfigError::InvalidGroupHierarchy {
                        group: group_name.clone(),
                        reason: format!(
                            "sub-group '[{group_name}]' cannot define target paths; define device and OS paths only on top-level group '[{root_name}]'"
                        ),
                    });
                }
                let root_has_paths = self
                    .groups
                    .get(root_name)
                    .is_some_and(|rg| !rg.paths.is_empty());
                if !root_has_paths {
                    return Err(ConfigError::InvalidGroupHierarchy {
                        group: group_name.clone(),
                        reason: format!(
                            "top-level group '[{root_name}]' must define at least one device or OS target path for sub-group '[{group_name}]'"
                        ),
                    });
                }
            } else {
                for key in group.paths.keys() {
                    if key.starts_with("os-") && !RECOGNIZED_OS_KEYS.contains(&key.as_str()) {
                        return Err(ConfigError::UnknownOsKey {
                            key: key.clone(),
                            hint: format!("Allowed OS keys are: {}", RECOGNIZED_OS_KEYS.join(", ")),
                        });
                    }
                }
            }

            let effective_paths = self.effective_group_paths(group_name);
            for path in effective_paths.values() {
                validate_path_security(path)?;
            }

            let rules = parse_selection_rules(&group.files)?;
            if rules_have_effective_encryption(&rules) {
                has_encrypted_rules = true;
            }
            for rule in &rules {
                // Cross-validate resolved target path against path security policy
                for path in effective_paths.values() {
                    let combined = format!("{}/{}", path.trim_end_matches('/'), rule.pattern);
                    validate_path_security(&combined)?;
                }
            }
        }

        if require_vault
            && has_encrypted_rules
            && self
                .vault
                .as_ref()
                .is_none_or(|v| v.vault_id.trim().is_empty())
        {
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
        &format!("vault_id = \"{}\"", old_cfg.vault_id),
        &format!("vault_id = \"{}\"", new_cfg.vault_id),
    );
    updated = updated.replace(
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
            "[secrets]\nfiles = \"credentials.toml enc tpl\"\nos-nux = \"~/.config/app\"\n",
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

    #[test]
    fn test_nested_group_hierarchy_parsing_derivation_and_roundtrip() {
        let content = r#"
vault_id = "0123456789abcdef"
password_slot = "cGFzc3dvcmQ="
recovery_slot = "cmVjb3Zlcnk="

[vault]
laptop = "~/my-notes"
os-nux = "./notes"
os-mac = "./notes"
files = "* enc=full"

[vault.sleep]
files = "* enc=full"

[vault.problems.work]
files = "*.md enc"
"#;
        let cfg = RepoConfig::parse(content).expect("nested hierarchy should parse");
        assert!(cfg.groups.contains_key("vault"));
        assert!(cfg.groups.contains_key("vault.sleep"));
        assert!(cfg.groups.contains_key("vault.problems.work"));
        assert!(!cfg.groups.contains_key("vault.problems"));

        let os = OsInfo::new("arch", "nux");
        assert_eq!(
            cfg.resolve_target_path("vault.sleep", &[], &os).as_deref(),
            Some("./notes/sleep")
        );
        assert_eq!(
            cfg.resolve_target_path("vault.problems.work", &["laptop".to_string()], &os)
                .as_deref(),
            Some("~/my-notes/problems/work")
        );
        assert_eq!(
            cfg.resolve_owning_group("vault", "problems/work/secret.md"),
            ("vault.problems.work", "secret.md".to_string())
        );
        assert_eq!(
            cfg.resolve_owning_group("vault", "problems/general.md"),
            ("vault", "problems/general.md".to_string())
        );
        assert_eq!(
            cfg.matching_groups(&["vault".to_string()]).unwrap(),
            vec!["vault", "vault.problems.work", "vault.sleep"]
        );

        let serialized = toml::to_string_pretty(&cfg).expect("serialize nested groups");
        assert!(serialized.contains("[vault]"));
        assert!(serialized.contains("[vault.sleep]"));
        assert!(serialized.contains("[vault.problems.work]"));
        assert!(!serialized.contains("[\"vault.sleep\"]"));
        let reparsed = RepoConfig::parse(&serialized).expect("reparse serialized nested groups");
        assert_eq!(reparsed, cfg);
    }

    #[test]
    fn test_nested_group_anchor_only_root_and_validation_errors() {
        let anchor_toml = r#"
[config]
os-nux = "~/.config"

[config.nvim]
files = "init.lua"
"#;
        let anchor_cfg = RepoConfig::parse(anchor_toml).expect("anchor root should parse");
        assert!(anchor_cfg.is_anchor_only_group("config"));
        let serialized = toml::to_string_pretty(&anchor_cfg).unwrap();
        let reparsed = RepoConfig::parse(&serialized).unwrap();
        assert_eq!(reparsed, anchor_cfg);

        // Path keys inside sub-group must fail.
        let sub_with_path = "[vault]\nos-nux = \"./notes\"\n[vault.sleep]\nos-nux = \"./notes/sleep\"\nfiles = \"*\"\n";
        assert!(matches!(
            RepoConfig::parse(sub_with_path),
            Err(ConfigError::InvalidGroupHierarchy { .. })
        ));

        // Empty leaf sub-group without files must fail.
        let empty_leaf = "[vault]\nos-nux = \"./notes\"\n[vault.sleep]\n";
        assert!(matches!(
            RepoConfig::parse(empty_leaf),
            Err(ConfigError::InvalidGroupHierarchy { .. })
        ));

        // Sub-group whose root defines no paths must fail.
        let missing_root_paths = "[vault.sleep]\nfiles = \"*\"\n";
        assert!(matches!(
            RepoConfig::parse(missing_root_paths),
            Err(ConfigError::InvalidGroupHierarchy { .. })
        ));

        // Quoted slash, traversal, or quoted dot in group segment must fail.
        assert!(matches!(
            RepoConfig::parse("[\"vault/sleep\"]\nos-nux = \"./notes\"\nfiles = \"*\"\n"),
            Err(ConfigError::HardBlockedPath { .. })
        ));
        assert!(matches!(
            RepoConfig::parse("[\"../escape\"]\nos-nux = \"./notes\"\nfiles = \"*\"\n"),
            Err(ConfigError::HardBlockedPath { .. })
        ));
        assert!(matches!(
            RepoConfig::parse("[\"vault.sleep\"]\nos-nux = \"./notes\"\nfiles = \"*\"\n"),
            Err(ConfigError::InvalidGroupHierarchy { .. })
        ));
    }
}
