use std::collections::BTreeMap;
use std::fs;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::ConfigError;

pub const RECOGNIZED_OS_KEYS: &[&str] = &[
    "os-arch",
    "os-debian",
    "os-ubuntu",
    "os-fedora",
    "os-nixos",
    "os-alpine",
    "os-freebsd",
    "os-openbsd",
    "os-nux",
    "os-mac",
    "os-win",
    "os-bsd",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RepoConfig {
    #[serde(default)]
    pub vault: Option<VaultConfig>,
    #[serde(flatten)]
    pub groups: BTreeMap<String, GroupConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultConfig {
    pub vault_id: String,
    pub password_slot: String,
    pub recovery_slot: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct GroupConfig {
    #[serde(default)]
    pub files: String,
    #[serde(flatten)]
    pub paths: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionMode {
    PlaintextInclude,
    EncryptedInclude,
    Exclude,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectionRule {
    pub pattern: String,
    pub mode: SelectionMode,
    pub line_no: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsInfo {
    pub distro: String,
    pub family: String,
}

impl OsInfo {
    pub fn new(distro: impl Into<String>, family: impl Into<String>) -> Self {
        let family_raw = family.into().to_lowercase();
        let family = match family_raw.as_str() {
            "linux" => "nux".to_string(),
            "macos" => "mac".to_string(),
            "windows" => "win".to_string(),
            _ => family_raw,
        };
        Self {
            distro: distro.into().to_lowercase(),
            family,
        }
    }

    pub fn detect() -> Self {
        let family = if cfg!(target_os = "linux") {
            "nux".to_string()
        } else if cfg!(target_os = "macos") {
            "mac".to_string()
        } else if cfg!(target_os = "windows") {
            "win".to_string()
        } else if cfg!(any(
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd"
        )) {
            "bsd".to_string()
        } else {
            std::env::consts::OS.to_lowercase()
        };

        let mut distro = "unknown".to_string();
        if family == "nux" {
            if let Ok(content) = fs::read_to_string("/etc/os-release")
                .or_else(|_| fs::read_to_string("/usr/lib/os-release"))
            {
                for line in content.lines() {
                    let trimmed = line.trim();
                    if let Some(val) = trimmed.strip_prefix("ID=") {
                        distro = val.trim_matches('"').trim_matches('\'').to_lowercase();
                        break;
                    }
                }
            }
        } else if family == "bsd" {
            distro = std::env::consts::OS.to_lowercase();
        } else {
            distro = family.clone();
        }

        Self { distro, family }
    }
}

pub fn validate_path_security(path: &str) -> Result<(), ConfigError> {
    if path != "~" && !path.starts_with("~/") {
        return Err(ConfigError::HardBlockedPath {
            path: path.to_string(),
            reason: "path must start with '~' or '~/'".to_string(),
        });
    }

    if path.contains("..") {
        return Err(ConfigError::HardBlockedPath {
            path: path.to_string(),
            reason: "directory traversal ('..') is prohibited".to_string(),
        });
    }

    if path.contains('$') || path.contains('%') {
        return Err(ConfigError::HardBlockedPath {
            path: path.to_string(),
            reason: "environment variable expansion is prohibited".to_string(),
        });
    }

    if path.contains('\\') {
        return Err(ConfigError::HardBlockedPath {
            path: path.to_string(),
            reason: "backslash path separators are prohibited".to_string(),
        });
    }

    let trimmed = path.trim_end_matches('/');

    if trimmed == "~/.config/dotler" || trimmed.starts_with("~/.config/dotler/") {
        return Err(ConfigError::HardBlockedPath {
            path: path.to_string(),
            reason: "path cannot point inside ~/.config/dotler".to_string(),
        });
    }

    if trimmed.split('/').any(|segment| segment == ".git") {
        return Err(ConfigError::HardBlockedPath {
            path: path.to_string(),
            reason: "path cannot target .git directories".to_string(),
        });
    }

    Ok(())
}

/// Returns true if `path` itself is a symbolic link (including broken/dangling links).
pub fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
}

/// Rejects any symbolic link (file, directory, or broken link) inside a repository directory.
pub fn validate_dir_no_symlinks(dir: &Path) -> Result<(), ConfigError> {
    if is_symlink(dir) {
        return Err(ConfigError::HardBlockedPath {
            path: dir.display().to_string(),
            reason: "symbolic links are prohibited inside a dotler repository".to_string(),
        });
    }
    if !dir.exists() {
        return Ok(());
    }
    for entry in crate::config::local::WalkDir::new(dir) {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let p = entry.path();
        if p.components().any(|c| c.as_os_str() == ".git") {
            continue;
        }
        if entry.file_type().is_symlink() || is_symlink(p) {
            return Err(ConfigError::HardBlockedPath {
                path: p.display().to_string(),
                reason: "symbolic links are prohibited inside a dotler repository".to_string(),
            });
        }
    }
    Ok(())
}

fn normalize_lexical_path(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn resolve_with_existing_ancestors(path: &Path) -> PathBuf {
    let lexical = normalize_lexical_path(path);
    let mut current = lexical.as_path();
    while let Some(parent) = current.parent() {
        if current.exists() {
            if let Ok(canon) = fs::canonicalize(current)
                && let Ok(tail) = lexical.strip_prefix(current)
            {
                if tail.as_os_str().is_empty() {
                    return canon;
                }
                return normalize_lexical_path(&canon.join(tail));
            }
            break;
        }
        if parent == current {
            break;
        }
        current = parent;
    }
    lexical
}

fn check_within_home_and_unprotected(
    original_path: &Path,
    resolved_path: &Path,
    canonical_home: &Path,
    canonical_dotler_dir: &Path,
) -> Result<(), ConfigError> {
    if !resolved_path.starts_with(canonical_home) {
        return Err(ConfigError::HardBlockedPath {
            path: original_path.display().to_string(),
            reason: format!(
                "symbolic link target '{}' escapes home directory ('~')",
                resolved_path.display()
            ),
        });
    }
    if resolved_path == canonical_dotler_dir || resolved_path.starts_with(canonical_dotler_dir) {
        return Err(ConfigError::HardBlockedPath {
            path: original_path.display().to_string(),
            reason: "symbolic link target cannot point inside ~/.config/dotler".to_string(),
        });
    }
    if let Ok(rel) = resolved_path.strip_prefix(canonical_home)
        && rel.components().any(|c| c.as_os_str() == ".git")
    {
        return Err(ConfigError::HardBlockedPath {
            path: original_path.display().to_string(),
            reason: "symbolic link target cannot point inside a .git directory".to_string(),
        });
    }
    Ok(())
}

/// Validates that an OS target directory (and its existing ancestors) stays within `home_dir`.
pub fn validate_os_dir_path(target_dir: &Path, home_dir: &Path) -> Result<(), ConfigError> {
    let canonical_home =
        fs::canonicalize(home_dir).unwrap_or_else(|_| normalize_lexical_path(home_dir));
    let canonical_dotler_dir = canonical_home.join(".config").join("dotler");

    let mut curr_opt = Some(target_dir);
    while let Some(curr) = curr_opt {
        if is_symlink(curr) && !curr.exists() {
            return Err(ConfigError::HardBlockedPath {
                path: target_dir.display().to_string(),
                reason: format!(
                    "directory path '{}' is a broken symbolic link",
                    curr.display()
                ),
            });
        }
        if curr.exists() {
            let canonical_curr = fs::canonicalize(curr)?;
            check_within_home_and_unprotected(
                target_dir,
                &canonical_curr,
                &canonical_home,
                &canonical_dotler_dir,
            )?;
            if !canonical_curr.is_dir() {
                return Err(ConfigError::HardBlockedPath {
                    path: target_dir.display().to_string(),
                    reason: format!(
                        "target directory path '{}' is not a directory",
                        curr.display()
                    ),
                });
            }
            break;
        }
        curr_opt = curr.parent();
    }
    Ok(())
}

/// Validates that an OS target file path (and its ancestors) does not escape `home_dir`
/// or enter protected directories via symbolic links.
pub fn validate_os_target_path(target_os_path: &Path, home_dir: &Path) -> Result<(), ConfigError> {
    let canonical_home =
        fs::canonicalize(home_dir).unwrap_or_else(|_| normalize_lexical_path(home_dir));
    let canonical_dotler_dir = canonical_home.join(".config").join("dotler");

    if let Some(parent) = target_os_path.parent() {
        validate_os_dir_path(parent, home_dir)?;
    }

    if is_symlink(target_os_path) {
        if target_os_path.exists() {
            let canonical_target = fs::canonicalize(target_os_path)?;
            check_within_home_and_unprotected(
                target_os_path,
                &canonical_target,
                &canonical_home,
                &canonical_dotler_dir,
            )?;
            if !canonical_target.is_file() {
                return Err(ConfigError::HardBlockedPath {
                    path: target_os_path.display().to_string(),
                    reason: "symbolic link at target file path must point to a regular file"
                        .to_string(),
                });
            }
        } else {
            let link_target = fs::read_link(target_os_path)?;
            let parent = target_os_path.parent().unwrap_or(home_dir);
            let canonical_parent =
                fs::canonicalize(parent).unwrap_or_else(|_| normalize_lexical_path(parent));
            let joined = if link_target.is_absolute() {
                link_target
            } else {
                canonical_parent.join(link_target)
            };
            let resolved = resolve_with_existing_ancestors(&joined);
            check_within_home_and_unprotected(
                target_os_path,
                &resolved,
                &canonical_home,
                &canonical_dotler_dir,
            )?;
        }
    }

    Ok(())
}

pub fn validate_rule_pattern(pattern: &str) -> Result<(), ConfigError> {
    if pattern.is_empty() {
        return Err(ConfigError::HardBlockedPath {
            path: pattern.to_string(),
            reason: "selection pattern cannot be empty".to_string(),
        });
    }

    if pattern.starts_with('/') || pattern.starts_with('~') {
        return Err(ConfigError::HardBlockedPath {
            path: pattern.to_string(),
            reason: "selection pattern must be a relative path and cannot start with '/' or '~'"
                .to_string(),
        });
    }

    if pattern.contains("..") {
        return Err(ConfigError::HardBlockedPath {
            path: pattern.to_string(),
            reason: "directory traversal ('..') is prohibited".to_string(),
        });
    }

    if pattern.contains('$') || pattern.contains('%') {
        return Err(ConfigError::HardBlockedPath {
            path: pattern.to_string(),
            reason: "environment variable expansion is prohibited".to_string(),
        });
    }

    if pattern.contains('\\') {
        return Err(ConfigError::HardBlockedPath {
            path: pattern.to_string(),
            reason: "backslash path separators are prohibited".to_string(),
        });
    }

    let trimmed = pattern.trim_end_matches('/');

    if trimmed == ".config/dotler" || trimmed.starts_with(".config/dotler/") {
        return Err(ConfigError::HardBlockedPath {
            path: pattern.to_string(),
            reason: "selection pattern cannot target internal dotler configuration directory ('~/.config/dotler')".to_string(),
        });
    }

    if trimmed.split('/').any(|segment| segment == ".git") {
        return Err(ConfigError::HardBlockedPath {
            path: pattern.to_string(),
            reason: "selection pattern cannot target .git directories".to_string(),
        });
    }

    Ok(())
}

pub fn parse_selection_rules(files_content: &str) -> Result<Vec<SelectionRule>, ConfigError> {
    let mut rules = Vec::new();

    for (idx, line) in files_content.lines().enumerate() {
        let line_no = idx + 1;
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if let Some(stripped) = trimmed.strip_prefix('!') {
            let tokens: Vec<&str> = stripped.split_whitespace().collect();
            match tokens.len() {
                0 => {
                    return Err(ConfigError::InvalidSelectionAttribute {
                        attribute: trimmed.to_string(),
                        line_no,
                        hint: "Pattern cannot be empty after prefix '!'.".to_string(),
                    });
                }
                1 => {
                    let pattern = tokens[0].to_string();
                    validate_rule_pattern(&pattern)?;
                    rules.push(SelectionRule {
                        pattern,
                        mode: SelectionMode::Exclude,
                        line_no,
                    });
                }
                _ => {
                    let trailing = tokens[1..].join(" ");
                    let hint = if tokens[1] == "encrypt" {
                        "Exclusion prefix '!' already specifies selection mode; trailing attribute is redundant."
                            .to_string()
                    } else if tokens[1] == "encrpyt" || tokens[1].contains("encr") {
                        "Supported selection attribute is 'encrypt'. Check for typos.".to_string()
                    } else {
                        "Expected single pattern after prefix '!' with no trailing attributes."
                            .to_string()
                    };
                    return Err(ConfigError::InvalidSelectionAttribute {
                        attribute: trailing,
                        line_no,
                        hint,
                    });
                }
            }
        } else {
            let tokens: Vec<&str> = trimmed.split_whitespace().collect();
            match tokens.len() {
                1 => {
                    let pattern = tokens[0].to_string();
                    validate_rule_pattern(&pattern)?;
                    rules.push(SelectionRule {
                        pattern,
                        mode: SelectionMode::PlaintextInclude,
                        line_no,
                    });
                }
                2 => {
                    let pattern = tokens[0].to_string();
                    validate_rule_pattern(&pattern)?;
                    let attribute = tokens[1];
                    if attribute == "encrypt" {
                        rules.push(SelectionRule {
                            pattern,
                            mode: SelectionMode::EncryptedInclude,
                            line_no,
                        });
                    } else {
                        return Err(ConfigError::InvalidSelectionAttribute {
                            attribute: attribute.to_string(),
                            line_no,
                            hint: "Supported selection attribute is 'encrypt'. Check for typos."
                                .to_string(),
                        });
                    }
                }
                _ => {
                    return Err(ConfigError::InvalidSelectionAttribute {
                        attribute: tokens[1..].join(" "),
                        line_no,
                        hint: "Expected format: '<pattern>', '<pattern> encrypt', or '!<pattern>'."
                            .to_string(),
                    });
                }
            }
        }
    }

    Ok(rules)
}

pub fn evaluate_selection(rules: &[SelectionRule], relative_path: &str) -> Option<SelectionMode> {
    let mut last_mode = None;

    for rule in rules {
        if matches_pattern(&rule.pattern, relative_path) {
            last_mode = Some(rule.mode);
        }
    }

    last_mode
}

pub fn rules_have_effective_encryption(rules: &[SelectionRule]) -> bool {
    rules.iter().any(|rule| {
        rule.mode == SelectionMode::EncryptedInclude
            && evaluate_selection(rules, &rule.pattern) == Some(SelectionMode::EncryptedInclude)
    })
}

fn matches_pattern(pattern: &str, path: &str) -> bool {
    if pattern == path || pattern == "*" {
        return true;
    }

    if let Ok(glob_pattern) = glob::Pattern::new(pattern) {
        glob_pattern.matches(path)
    } else {
        pattern == path
    }
}

pub fn resolve_group_target_path(
    group: &GroupConfig,
    devices: &[String],
    os_info: &OsInfo,
) -> Option<String> {
    // 1. Custom Device Cascade
    for dev in devices {
        if let Some(path) = group.paths.get(dev) {
            return Some(path.clone());
        }
    }

    // 2. Specific Distro Cascade
    let distro_key = format!("os-{}", os_info.distro);
    if let Some(path) = group.paths.get(&distro_key) {
        return Some(path.clone());
    }

    // 3. OS Family Cascade
    let family_key = format!("os-{}", os_info.family);
    if let Some(path) = group.paths.get(&family_key) {
        return Some(path.clone());
    }

    None
}

impl RepoConfig {
    pub fn parse(content: &str) -> Result<Self, ConfigError> {
        let repo: RepoConfig = toml::from_str(content).map_err(|e| {
            let msg = e.to_string();
            if msg.contains("unknown field") {
                ConfigError::UnknownField {
                    field: msg.clone(),
                    hint:
                        "Check dotler.toml for unexpected fields in [vault] or group definitions."
                            .to_string(),
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
                    hint:
                        "Check dotler.toml for unexpected fields in [vault] or group definitions."
                            .to_string(),
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
            if group_name == "vault" {
                return Err(ConfigError::InvalidDeviceName {
                    device: group_name.clone(),
                    reason: "'vault' is a reserved section name and cannot be a group".to_string(),
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

    pub fn detect_cross_group_collisions(
        &self,
        devices: &[String],
        os_info: &OsInfo,
    ) -> Result<(), ConfigError> {
        struct ActiveGroup<'a> {
            name: &'a str,
            base: String,
            rules: Vec<SelectionRule>,
            concrete_files: Vec<String>,
            wildcard_rules: Vec<SelectionRule>,
            has_no_rules: bool,
        }

        let mut active_groups = Vec::new();

        for (group_name, group) in &self.groups {
            if let Some(target_base) = resolve_group_target_path(group, devices, os_info) {
                let rules = parse_selection_rules(&group.files)?;
                let normalized_base = target_base.trim_end_matches('/').to_string();

                let mut concrete_files = Vec::new();
                let mut wildcard_rules = Vec::new();
                let has_no_rules = rules.is_empty();

                if has_no_rules {
                    concrete_files.push(normalized_base.clone());
                } else {
                    for rule in &rules {
                        let clean_pattern = rule
                            .pattern
                            .trim_start_matches("./")
                            .trim_start_matches('/');
                        if clean_pattern.is_empty() {
                            continue;
                        }

                        if clean_pattern.contains('*')
                            || clean_pattern.contains('?')
                            || clean_pattern.contains('[')
                        {
                            if rule.mode != SelectionMode::Exclude {
                                wildcard_rules.push(rule.clone());
                            }
                        } else if matches!(evaluate_selection(&rules, clean_pattern), Some(m) if m != SelectionMode::Exclude)
                        {
                            let target_file = format!("{}/{}", normalized_base, clean_pattern);
                            if !concrete_files.contains(&target_file) {
                                concrete_files.push(target_file);
                            }
                        }
                    }
                }

                active_groups.push(ActiveGroup {
                    name: group_name.as_str(),
                    base: normalized_base,
                    rules,
                    concrete_files,
                    wildcard_rules,
                    has_no_rules,
                });
            }
        }

        let rel_to_base = |target_path: &str, base: &str| -> Option<String> {
            if target_path == base {
                Some(String::new())
            } else if base == "~" {
                target_path.strip_prefix("~/").map(|s| s.to_string())
            } else {
                let prefix = format!("{}/", base);
                if target_path.starts_with(&prefix) {
                    Some(target_path[prefix.len()..].to_string())
                } else {
                    None
                }
            }
        };

        for i in 0..active_groups.len() {
            for j in (i + 1)..active_groups.len() {
                let g1 = &active_groups[i];
                let g2 = &active_groups[j];

                // Check empty rule base claims
                if g1.has_no_rules && g2.has_no_rules && g1.base == g2.base {
                    return Err(ConfigError::CrossGroupFileCollision {
                        path: g1.base.clone(),
                        group1: g1.name.to_string(),
                        group2: g2.name.to_string(),
                    });
                }

                if g1.has_no_rules {
                    for file2 in &g2.concrete_files {
                        if rel_to_base(file2, &g1.base).is_some() {
                            return Err(ConfigError::CrossGroupFileCollision {
                                path: file2.clone(),
                                group1: g1.name.to_string(),
                                group2: g2.name.to_string(),
                            });
                        }
                    }
                    for w2 in &g2.wildcard_rules {
                        let p2 = w2.pattern.trim_start_matches("./").trim_start_matches('/');
                        let target2 = format!("{}/{}", g2.base, p2);
                        if rel_to_base(&target2, &g1.base).is_some() {
                            return Err(ConfigError::CrossGroupFileCollision {
                                path: target2,
                                group1: g1.name.to_string(),
                                group2: g2.name.to_string(),
                            });
                        }
                    }
                }

                if g2.has_no_rules {
                    for file1 in &g1.concrete_files {
                        if rel_to_base(file1, &g2.base).is_some() {
                            return Err(ConfigError::CrossGroupFileCollision {
                                path: file1.clone(),
                                group1: g1.name.to_string(),
                                group2: g2.name.to_string(),
                            });
                        }
                    }
                    for w1 in &g1.wildcard_rules {
                        let p1 = w1.pattern.trim_start_matches("./").trim_start_matches('/');
                        let target1 = format!("{}/{}", g1.base, p1);
                        if rel_to_base(&target1, &g2.base).is_some() {
                            return Err(ConfigError::CrossGroupFileCollision {
                                path: target1,
                                group1: g1.name.to_string(),
                                group2: g2.name.to_string(),
                            });
                        }
                    }
                }

                // 1. Concrete vs Concrete collision
                for file1 in &g1.concrete_files {
                    if g2.concrete_files.contains(file1) {
                        return Err(ConfigError::CrossGroupFileCollision {
                            path: file1.clone(),
                            group1: g1.name.to_string(),
                            group2: g2.name.to_string(),
                        });
                    }
                }

                // 2. Wildcard in Group 1 vs Concrete in Group 2
                for file2 in &g2.concrete_files {
                    if let Some(rel) = rel_to_base(file2, &g1.base)
                        && !rel.is_empty()
                        && matches!(evaluate_selection(&g1.rules, &rel), Some(m) if m != SelectionMode::Exclude)
                    {
                        return Err(ConfigError::CrossGroupFileCollision {
                            path: file2.clone(),
                            group1: g1.name.to_string(),
                            group2: g2.name.to_string(),
                        });
                    }
                }

                // 3. Wildcard in Group 2 vs Concrete in Group 1
                for file1 in &g1.concrete_files {
                    if let Some(rel) = rel_to_base(file1, &g2.base)
                        && !rel.is_empty()
                        && matches!(evaluate_selection(&g2.rules, &rel), Some(m) if m != SelectionMode::Exclude)
                    {
                        return Err(ConfigError::CrossGroupFileCollision {
                            path: file1.clone(),
                            group1: g1.name.to_string(),
                            group2: g2.name.to_string(),
                        });
                    }
                }

                // 4. Identical Wildcard Target Collision
                for w1 in &g1.wildcard_rules {
                    let p1 = w1.pattern.trim_start_matches("./").trim_start_matches('/');
                    let target1 = format!("{}/{}", g1.base, p1);

                    for w2 in &g2.wildcard_rules {
                        let p2 = w2.pattern.trim_start_matches("./").trim_start_matches('/');
                        let target2 = format!("{}/{}", g2.base, p2);

                        if target1 == target2 {
                            return Err(ConfigError::CrossGroupFileCollision {
                                path: target1,
                                group1: g1.name.to_string(),
                                group2: g2.name.to_string(),
                            });
                        }
                    }
                }
            }
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
                    return crate::config::state::write_file_safe(path, updated.as_bytes())
                        .map_err(|e| match e {
                            crate::config::StateError::Io(io) => ConfigError::IoError(io),
                            other => ConfigError::AtomicRenameFailed(other.to_string()),
                        });
                }
                (None, Some(new_v)) => {
                    let mut manifest_str = existing_str;
                    manifest_str.push_str(&format!(
                        "\n[vault]\nvault_id = \"{}\"\npassword_slot = \"{}\"\nrecovery_slot = \"{}\"\n",
                        new_v.vault_id, new_v.password_slot, new_v.recovery_slot
                    ));
                    if let Some(ref h) = new_v.hint {
                        let escaped = toml::Value::String(h.clone()).to_string();
                        manifest_str.push_str(&format!("hint = {escaped}\n"));
                    }
                    return crate::config::state::write_file_safe(path, manifest_str.as_bytes())
                        .map_err(|e| match e {
                            crate::config::StateError::Io(io) => ConfigError::IoError(io),
                            other => ConfigError::AtomicRenameFailed(other.to_string()),
                        });
                }
                _ => {}
            }
        }

        let serialized = toml::to_string_pretty(self)
            .map_err(|e| ConfigError::TomlSyntaxError(e.to_string()))?;
        crate::config::state::write_file_safe(path, serialized.as_bytes()).map_err(|e| match e {
            crate::config::StateError::Io(io) => ConfigError::IoError(io),
            other => ConfigError::AtomicRenameFailed(other.to_string()),
        })
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
    if new_cfg.hint != old_cfg.hint {
        match (&old_cfg.hint, &new_cfg.hint) {
            (Some(old_h), Some(new_h)) => {
                let old_val = toml::Value::String(old_h.clone()).to_string();
                let new_val = toml::Value::String(new_h.clone()).to_string();
                updated =
                    updated.replace(&format!("hint = {old_val}"), &format!("hint = {new_val}"));
            }
            (None, Some(new_h)) => {
                let new_val = toml::Value::String(new_h.clone()).to_string();
                let target = format!("recovery_slot = \"{}\"", new_cfg.recovery_slot);
                updated = updated.replace(&target, &format!("{target}\nhint = {new_val}"));
            }
            (Some(old_h), None) => {
                let old_val = toml::Value::String(old_h.clone()).to_string();
                updated = updated.replace(&format!("hint = {old_val}\n"), "");
                updated = updated.replace(&format!("hint = {old_val}"), "");
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
[vault]
vault_id = "0123456789abcdef"
password_slot = "cGFzc3dvcmRfc2xvdF9wbGFjZWhvbGRlcg=="
recovery_slot = "cmVjb3Zlcnlfc2xvdF9wbGFjZWhvbGRlcg=="

[nvim]
files = """
init.lua
lua/*
"""
laptop = "~/.config/nvim"
os-nux = "~/.config/nvim"
"#;
        let config = RepoConfig::parse(content).expect("repo config with vault should parse");
        assert!(config.vault.is_some());
        let vault = config.vault.unwrap();
        assert_eq!(vault.vault_id, "0123456789abcdef");
        assert_eq!(config.groups.len(), 1);
        assert!(config.groups.contains_key("nvim"));
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
[vault]
vault_id = "0123456789abcdef"
password_slot = "cGFzc3dvcmQ="
recovery_slot = "cmVjb3Zlcnk="
extra_field = "unexpected"
"#;
        let err = RepoConfig::parse(content).expect_err("unknown field in vault must fail");
        assert!(matches!(
            err,
            ConfigError::UnknownField { .. } | ConfigError::TomlSyntaxError(_)
        ));
    }

    #[test]
    fn test_selection_rules_parsing_standard_syntax() {
        let content = r#"
# Plaintext include
config.json
# Encrypted include
id_ed25519 encrypt
# Exclusion
!temp*
"#;
        let rules = parse_selection_rules(content).expect("rules should parse cleanly");
        assert_eq!(rules.len(), 3);
        assert_eq!(
            rules[0],
            SelectionRule {
                pattern: "config.json".to_string(),
                mode: SelectionMode::PlaintextInclude,
                line_no: 3,
            }
        );
        assert_eq!(
            rules[1],
            SelectionRule {
                pattern: "id_ed25519".to_string(),
                mode: SelectionMode::EncryptedInclude,
                line_no: 5,
            }
        );
        assert_eq!(
            rules[2],
            SelectionRule {
                pattern: "temp*".to_string(),
                mode: SelectionMode::Exclude,
                line_no: 7,
            }
        );
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
.bashrc encrypt
.bashrc
"""
"#;
        let config = RepoConfig::parse(content)
            .expect("overridden encrypt rule must not require [vault] section");
        let rules = parse_selection_rules(&config.groups["bash"].files).unwrap();
        assert!(!rules_have_effective_encryption(&rules));
        assert_eq!(
            evaluate_selection(&rules, ".bashrc"),
            Some(SelectionMode::PlaintextInclude)
        );
    }

    #[test]
    fn test_selection_rules_invalid_attribute_error_with_line_number() {
        let content = "item1\nitem2\nitem3 encrpyt\nitem4";
        let err = parse_selection_rules(content).expect_err("misspelled attribute must fail");
        match err {
            ConfigError::InvalidSelectionAttribute {
                attribute,
                line_no,
                hint,
            } => {
                assert_eq!(attribute, "encrpyt");
                assert_eq!(line_no, 3);
                assert!(hint.contains("encrypt"));
            }
            other => panic!("expected InvalidSelectionAttribute, got {other:?}"),
        }
    }

    #[test]
    fn test_selection_rules_last_match_wins_precedence() {
        let content = r#"
* encrypt
*.pub
!known_hosts*
"#;
        let rules = parse_selection_rules(content).expect("rules should parse");

        let mode_key = evaluate_selection(&rules, "id_ed25519");
        assert_eq!(mode_key, Some(SelectionMode::EncryptedInclude));

        let mode_pub = evaluate_selection(&rules, "id_ed25519.pub");
        assert_eq!(mode_pub, Some(SelectionMode::PlaintextInclude));

        let mode_known = evaluate_selection(&rules, "known_hosts.old");
        assert_eq!(mode_known, Some(SelectionMode::Exclude));

        let mode_other = evaluate_selection(&rules, "other.file");
        assert_eq!(mode_other, Some(SelectionMode::EncryptedInclude));
    }

    #[test]
    fn test_device_os_cascading_custom_device_first() {
        let mut group = GroupConfig::default();
        group
            .paths
            .insert("laptop".to_string(), "~/laptop/path".to_string());
        group
            .paths
            .insert("os-arch".to_string(), "~/arch/path".to_string());
        group
            .paths
            .insert("os-nux".to_string(), "~/linux/path".to_string());

        let devices = vec!["laptop".to_string()];
        let os_info = OsInfo::new("arch", "nux");

        let resolved = resolve_group_target_path(&group, &devices, &os_info);
        assert_eq!(resolved.as_deref(), Some("~/laptop/path"));
    }

    #[test]
    fn test_device_os_cascading_distro_fallback() {
        let mut group = GroupConfig::default();
        group
            .paths
            .insert("desktop".to_string(), "~/desktop/path".to_string());
        group
            .paths
            .insert("os-arch".to_string(), "~/arch/path".to_string());
        group
            .paths
            .insert("os-nux".to_string(), "~/linux/path".to_string());

        let devices = vec!["laptop".to_string()];
        let os_info = OsInfo::new("arch", "nux");

        let resolved = resolve_group_target_path(&group, &devices, &os_info);
        assert_eq!(resolved.as_deref(), Some("~/arch/path"));
    }

    #[test]
    fn test_device_os_cascading_family_fallback() {
        let mut group = GroupConfig::default();
        group
            .paths
            .insert("desktop".to_string(), "~/desktop/path".to_string());
        group
            .paths
            .insert("os-debian".to_string(), "~/debian/path".to_string());
        group
            .paths
            .insert("os-nux".to_string(), "~/linux/path".to_string());

        let devices = vec!["laptop".to_string()];
        let os_info = OsInfo::new("arch", "nux");

        let resolved = resolve_group_target_path(&group, &devices, &os_info);
        assert_eq!(resolved.as_deref(), Some("~/linux/path"));
    }

    #[test]
    fn test_device_os_cascading_skip_when_unmatched() {
        let mut group = GroupConfig::default();
        group
            .paths
            .insert("workstation".to_string(), "~/work/path".to_string());
        group
            .paths
            .insert("os-mac".to_string(), "~/mac/path".to_string());

        let devices = vec!["laptop".to_string()];
        let os_info = OsInfo::new("arch", "nux");

        let resolved = resolve_group_target_path(&group, &devices, &os_info);
        assert_eq!(resolved, None);
    }

    #[test]
    fn test_reject_unknown_os_key() {
        let content = r#"
[shell]
files = "zshrc"
os-ubntu = "~/.zshrc"
"#;
        let err = RepoConfig::parse(content).expect_err("typo in OS key must fail");
        assert!(matches!(err, ConfigError::UnknownOsKey { key, .. } if key == "os-ubntu"));
    }

    #[test]
    fn test_path_security_checks() {
        assert!(validate_path_security("~/.config/app").is_ok());
        assert!(validate_path_security("~/").is_ok());
        assert!(validate_path_security("~").is_ok());

        assert!(matches!(
            validate_path_security("/etc/app").unwrap_err(),
            ConfigError::HardBlockedPath { .. }
        ));
        assert!(matches!(
            validate_path_security("~/app/../secret").unwrap_err(),
            ConfigError::HardBlockedPath { .. }
        ));
        assert!(matches!(
            validate_path_security("~/app/$HOME").unwrap_err(),
            ConfigError::HardBlockedPath { .. }
        ));
        assert!(matches!(
            validate_path_security("~/app/%USERPROFILE%").unwrap_err(),
            ConfigError::HardBlockedPath { .. }
        ));
        assert!(matches!(
            validate_path_security("~\\app\\conf").unwrap_err(),
            ConfigError::HardBlockedPath { .. }
        ));
    }

    #[test]
    fn test_vault_required_when_encrypted_rule_present() {
        let content = r#"
[secrets]
files = "id_rsa encrypt"
os-nux = "~/.ssh"
"#;
        let err = RepoConfig::parse(content).expect_err("encrypt rule without vault must fail");
        assert!(matches!(err, ConfigError::MissingVaultConfig));
    }

    #[test]
    fn test_detect_cross_group_file_collision() {
        let content = r#"
[nvim]
files = "conf"
os-nux = "~/.config/app"

[vim]
files = "conf"
os-nux = "~/.config/app"
"#;
        let repo = RepoConfig::parse(content).expect("valid syntax");
        let devices = vec![];
        let os_info = OsInfo::new("arch", "nux");
        let err = repo
            .detect_cross_group_collisions(&devices, &os_info)
            .expect_err("collision must be detected");
        match err {
            ConfigError::CrossGroupFileCollision {
                path,
                group1,
                group2,
            } => {
                assert_eq!(path, "~/.config/app/conf");
                assert_eq!(group1, "nvim");
                assert_eq!(group2, "vim");
            }
            other => panic!("expected CrossGroupFileCollision, got {other:?}"),
        }
    }

    #[test]
    fn test_detect_cross_group_shared_home_distinct_files_allowed() {
        let content = r#"
[zsh]
files = ".zshrc"
os-nux = "~"

[git]
files = ".gitconfig"
os-nux = "~"
"#;
        let repo = RepoConfig::parse(content).expect("valid syntax");
        let os_info = OsInfo::new("arch", "nux");
        assert!(
            repo.detect_cross_group_collisions(&[], &os_info).is_ok(),
            "groups sharing '~' with distinct files must be allowed"
        );
    }

    #[test]
    fn test_detect_cross_group_wildcard_overlaps_concrete_file() {
        let content = r#"
[all_conf]
files = "*.conf"
os-nux = "~/.config/app"

[app_conf]
files = "custom.conf"
os-nux = "~/.config/app"
"#;
        let repo = RepoConfig::parse(content).expect("valid syntax");
        let os_info = OsInfo::new("arch", "nux");
        let err = repo
            .detect_cross_group_collisions(&[], &os_info)
            .expect_err("wildcard overlapping concrete file must collide");
        match err {
            ConfigError::CrossGroupFileCollision { path, .. } => {
                assert_eq!(path, "~/.config/app/custom.conf");
            }
            other => panic!("expected CrossGroupFileCollision, got {other:?}"),
        }
    }

    #[test]
    fn test_detect_cross_group_wildcard_with_exclusion_allows_separate_group() {
        let content = r#"
[all_conf]
files = """
*.conf
!custom.conf
"""
os-nux = "~/.config/app"

[app_conf]
files = "custom.conf"
os-nux = "~/.config/app"
"#;
        let repo = RepoConfig::parse(content).expect("valid syntax");
        let os_info = OsInfo::new("arch", "nux");
        assert!(
            repo.detect_cross_group_collisions(&[], &os_info).is_ok(),
            "excluded file from wildcard group must allow another group to claim it"
        );
    }

    #[test]
    fn test_path_security_checks_protects_internal_paths() {
        assert!(validate_path_security("~/.config/dotler").is_err());
        assert!(validate_path_security("~/.config/dotler/state.db").is_err());
        assert!(validate_path_security("~/.git").is_err());
        assert!(validate_path_security("~/.git/hooks").is_err());

        // Allowed dotfiles that contain git as substring
        assert!(validate_path_security("~/.gitconfig").is_ok());
        assert!(validate_path_security("~/.gitignore").is_ok());
        assert!(validate_path_security("~/.github").is_ok());
    }

    #[test]
    fn test_rule_pattern_security_checks() {
        assert!(validate_rule_pattern("").is_err());
        assert!(validate_rule_pattern("../secret").is_err());
        assert!(validate_rule_pattern("/etc/shadow").is_err());
        assert!(validate_rule_pattern("~/file").is_err());
        assert!(validate_rule_pattern("$HOME/file").is_err());
        assert!(validate_rule_pattern("%USER%/file").is_err());
        assert!(validate_rule_pattern("folder\\file").is_err());
        assert!(validate_rule_pattern(".config/dotler").is_err());
        assert!(validate_rule_pattern(".git").is_err());
        assert!(validate_rule_pattern(".git/hooks").is_err());

        assert!(validate_rule_pattern(".gitconfig").is_ok());
        assert!(validate_rule_pattern("custom.conf").is_ok());
        assert!(validate_rule_pattern("*.conf").is_ok());
    }

    #[test]
    fn test_load_without_vault_check_allows_encrypted_rules_before_vault_init() {
        let dir = tempfile::tempdir().unwrap();
        let manifest_path = dir.path().join("dotler.toml");
        fs::write(
            &manifest_path,
            "[shell]\nos-nux = \"~\"\nfiles = \"secret.txt encrypt\"\n",
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
