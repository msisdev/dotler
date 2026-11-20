use std::fs;
use std::path::{Path, PathBuf};

use crate::config::ConfigError;
use crate::config::path_security::{normalize_lexical_path, resolve_with_existing_ancestors};
use crate::config::repo::{GroupConfig, RepoConfig, is_delegated_to_subgroup};
use crate::config::selection::{
    SelectionMode, SelectionRule, evaluate_selection, parse_selection_rules,
};

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

struct ActiveGroup<'a> {
    name: &'a str,
    base: String,
    rules: Vec<SelectionRule>,
    delegated_subpaths: Vec<String>,
    concrete_files: Vec<String>,
    wildcard_rules: Vec<SelectionRule>,
    has_no_rules: bool,
}

fn collision(path: impl Into<String>, group1: &str, group2: &str) -> ConfigError {
    ConfigError::CrossGroupFileCollision {
        path: path.into(),
        group1: group1.to_string(),
        group2: group2.to_string(),
    }
}

fn clean_rule_pattern(rule: &SelectionRule) -> &str {
    rule.pattern
        .trim_start_matches("./")
        .trim_start_matches('/')
}

fn is_included(rules: &[SelectionRule], path: &str) -> bool {
    matches!(evaluate_selection(rules, path), Some(m) if m != SelectionMode::Exclude)
}

fn is_effectively_included(group: &ActiveGroup<'_>, path: &str) -> bool {
    !is_delegated_to_subgroup(path, &group.delegated_subpaths) && is_included(&group.rules, path)
}

fn normalize_group_base(raw: &str) -> String {
    let trimmed = raw.trim_end_matches('/');
    if trimmed.is_empty() {
        return String::new();
    }
    if trimmed == "~" || trimmed.starts_with("~/") {
        return trimmed.to_string();
    }
    if trimmed == "." {
        return ".".to_string();
    }
    if let Some(mut rest) = trimmed.strip_prefix("./") {
        while let Some(next) = rest.strip_prefix("./") {
            rest = next;
        }
        let clean = rest.trim_start_matches('/');
        if clean.is_empty() || clean == "." {
            return ".".to_string();
        }
        return format!("./{clean}");
    }
    trimmed.to_string()
}

fn expand_normalized_root_base(raw: &str, home_root: &Path, cwd_root: &Path) -> String {
    let norm = normalize_group_base(raw);
    let expanded = if norm == "~" {
        home_root.to_path_buf()
    } else if let Some(rest) = norm.strip_prefix("~/") {
        home_root.join(rest)
    } else if norm == "." {
        cwd_root.to_path_buf()
    } else if let Some(rest) = norm.strip_prefix("./") {
        cwd_root.join(rest)
    } else {
        PathBuf::from(&norm)
    };
    let normalized = normalize_lexical_path(&expanded);
    let s = normalized.to_string_lossy().replace('\\', "/");
    if s.len() > 1 {
        s.trim_end_matches('/').to_string()
    } else {
        s
    }
}

fn join_base_and_pattern(base: &str, rel: &str) -> String {
    if base == "/" {
        format!("/{rel}")
    } else {
        format!("{base}/{rel}")
    }
}

fn rel_to_base(target_path: &str, base: &str) -> Option<String> {
    if target_path == base {
        Some(String::new())
    } else if base == "~" {
        target_path.strip_prefix("~/").map(str::to_string)
    } else if base == "." {
        target_path.strip_prefix("./").map(str::to_string)
    } else if base == "/" {
        target_path.strip_prefix('/').map(str::to_string)
    } else {
        target_path
            .strip_prefix(base)
            .and_then(|rest| rest.strip_prefix('/'))
            .map(str::to_string)
    }
}

fn check_no_rules_against(
    empty: &ActiveGroup<'_>,
    other: &ActiveGroup<'_>,
    g1: &str,
    g2: &str,
) -> Result<(), ConfigError> {
    if !empty.has_no_rules {
        return Ok(());
    }
    for file in &other.concrete_files {
        if let Some(rel) = rel_to_base(file, &empty.base)
            && !is_delegated_to_subgroup(&rel, &empty.delegated_subpaths)
        {
            return Err(collision(file.clone(), g1, g2));
        }
    }
    for w in &other.wildcard_rules {
        let p = clean_rule_pattern(w);
        if is_delegated_to_subgroup(p, &other.delegated_subpaths) {
            continue;
        }
        let target = join_base_and_pattern(&other.base, p);
        if let Some(rel) = rel_to_base(&target, &empty.base)
            && !is_delegated_to_subgroup(&rel, &empty.delegated_subpaths)
        {
            return Err(collision(target, g1, g2));
        }
    }
    Ok(())
}

fn check_wildcard_vs_concrete(
    wc_group: &ActiveGroup<'_>,
    concrete_group: &ActiveGroup<'_>,
    g1: &str,
    g2: &str,
) -> Result<(), ConfigError> {
    for file in &concrete_group.concrete_files {
        if let Some(rel) = rel_to_base(file, &wc_group.base)
            && !rel.is_empty()
            && is_effectively_included(wc_group, &rel)
        {
            return Err(collision(file.clone(), g1, g2));
        }
    }
    Ok(())
}

fn check_wildcard_target_overlap(
    src: &ActiveGroup<'_>,
    dst: &ActiveGroup<'_>,
    g1: &str,
    g2: &str,
) -> Result<(), ConfigError> {
    for w in &src.wildcard_rules {
        let p = clean_rule_pattern(w);
        if !is_effectively_included(src, p) {
            continue;
        }
        let target = join_base_and_pattern(&src.base, p);
        if let Some(rel) = rel_to_base(&target, &dst.base)
            && !rel.is_empty()
            && is_effectively_included(dst, &rel)
        {
            return Err(collision(target, g1, g2));
        }
    }
    Ok(())
}

impl RepoConfig {
    pub fn detect_cross_group_collisions(
        &self,
        devices: &[String],
        os_info: &OsInfo,
    ) -> Result<(), ConfigError> {
        self.detect_cross_group_collisions_with_mapper(devices, os_info, normalize_group_base)
    }

    /// Detects cross-group target file collisions after expanding `~` against `home_dir`
    /// and `.` against `cwd`.
    pub fn detect_cross_group_collisions_with_roots(
        &self,
        devices: &[String],
        os_info: &OsInfo,
        home_dir: &Path,
        cwd: &Path,
    ) -> Result<(), ConfigError> {
        let home_root = resolve_with_existing_ancestors(home_dir);
        let cwd_root = resolve_with_existing_ancestors(cwd);
        self.detect_cross_group_collisions_with_mapper(devices, os_info, |raw| {
            expand_normalized_root_base(raw, &home_root, &cwd_root)
        })
    }

    fn detect_cross_group_collisions_with_mapper(
        &self,
        devices: &[String],
        os_info: &OsInfo,
        mut map_base: impl FnMut(&str) -> String,
    ) -> Result<(), ConfigError> {
        let mut active_groups = Vec::new();

        for (group_name, group) in &self.groups {
            if self.is_anchor_only_group(group_name) {
                continue;
            }
            let Some(target_base) = self.resolve_target_path(group_name, devices, os_info) else {
                continue;
            };
            let rules = parse_selection_rules(&group.files)?;
            let delegated_subpaths = self.descendant_subpaths(group_name);
            let normalized_base = map_base(&target_base);
            let mut concrete_files = Vec::new();
            let mut wildcard_rules = Vec::new();
            let has_no_rules = rules.is_empty();

            if has_no_rules {
                concrete_files.push(normalized_base.clone());
            } else {
                for rule in &rules {
                    let raw_pattern = clean_rule_pattern(rule);
                    let is_dir_slash = raw_pattern.ends_with('/');
                    let clean_pattern = raw_pattern.trim_end_matches('/');
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
                    } else if is_dir_slash {
                        let probe = format!("{clean_pattern}/*");
                        if rule.mode != SelectionMode::Exclude
                            && !is_delegated_to_subgroup(&probe, &delegated_subpaths)
                            && is_included(&rules, &probe)
                        {
                            wildcard_rules.push(SelectionRule {
                                pattern: probe,
                                mode: rule.mode,
                                line_no: rule.line_no,
                            });
                        }
                    } else if !is_delegated_to_subgroup(clean_pattern, &delegated_subpaths)
                        && is_included(&rules, clean_pattern)
                    {
                        let target_file = join_base_and_pattern(&normalized_base, clean_pattern);
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
                delegated_subpaths,
                concrete_files,
                wildcard_rules,
                has_no_rules,
            });
        }

        for i in 0..active_groups.len() {
            for j in (i + 1)..active_groups.len() {
                let (g1, g2) = (&active_groups[i], &active_groups[j]);

                if g1.has_no_rules && g2.has_no_rules && g1.base == g2.base {
                    return Err(collision(g1.base.clone(), g1.name, g2.name));
                }
                check_no_rules_against(g1, g2, g1.name, g2.name)?;
                check_no_rules_against(g2, g1, g1.name, g2.name)?;

                for file1 in &g1.concrete_files {
                    if g2.concrete_files.contains(file1) {
                        return Err(collision(file1.clone(), g1.name, g2.name));
                    }
                }
                check_wildcard_vs_concrete(g1, g2, g1.name, g2.name)?;
                check_wildcard_vs_concrete(g2, g1, g1.name, g2.name)?;
                check_wildcard_target_overlap(g1, g2, g1.name, g2.name)?;
                check_wildcard_target_overlap(g2, g1, g1.name, g2.name)?;

                for w1 in &g1.wildcard_rules {
                    let p1 = clean_rule_pattern(w1);
                    if !is_effectively_included(g1, p1) {
                        continue;
                    }
                    let target1 = join_base_and_pattern(&g1.base, p1);
                    for w2 in &g2.wildcard_rules {
                        let p2 = clean_rule_pattern(w2);
                        if !is_effectively_included(g2, p2) {
                            continue;
                        }
                        let target2 = join_base_and_pattern(&g2.base, p2);
                        if target1 == target2 {
                            return Err(collision(target1, g1.name, g2.name));
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::selection::rules_have_effective_encryption;

    fn resolve_with_paths(paths: &[(&str, &str)]) -> Option<String> {
        let mut group = GroupConfig::default();
        for &(k, v) in paths {
            group.paths.insert(k.to_string(), v.to_string());
        }
        resolve_group_target_path(&group, &["laptop".to_string()], &OsInfo::new("arch", "nux"))
    }

    #[test]
    fn test_device_os_cascading_custom_device_first() {
        let res = resolve_with_paths(&[
            ("laptop", "~/laptop/path"),
            ("os-arch", "~/arch/path"),
            ("os-nux", "~/linux/path"),
        ]);
        assert_eq!(res.as_deref(), Some("~/laptop/path"));
    }

    #[test]
    fn test_device_os_cascading_distro_fallback() {
        let res = resolve_with_paths(&[
            ("desktop", "~/desktop/path"),
            ("os-arch", "~/arch/path"),
            ("os-nux", "~/linux/path"),
        ]);
        assert_eq!(res.as_deref(), Some("~/arch/path"));
    }

    #[test]
    fn test_device_os_cascading_family_fallback() {
        let res = resolve_with_paths(&[
            ("desktop", "~/desktop/path"),
            ("os-debian", "~/debian/path"),
            ("os-nux", "~/linux/path"),
        ]);
        assert_eq!(res.as_deref(), Some("~/linux/path"));
    }

    #[test]
    fn test_device_os_cascading_skip_when_unmatched() {
        assert_eq!(
            resolve_with_paths(&[("workstation", "~/work/path"), ("os-mac", "~/mac/path")]),
            None
        );
    }

    #[test]
    fn test_reject_unknown_os_key() {
        let err = RepoConfig::parse("[shell]\nfiles = \"zshrc\"\nos-ubntu = \"~/.zshrc\"\n")
            .expect_err("typo in OS key must fail");
        assert!(matches!(err, ConfigError::UnknownOsKey { key, .. } if key == "os-ubntu"));
    }

    #[test]
    fn test_detect_cross_group_file_collision() {
        let repo = RepoConfig::parse(
            "[nvim]\nfiles = \"conf\"\nos-nux = \"~/.config/app\"\n[vim]\nfiles = \"conf\"\nos-nux = \"~/.config/app\"\n",
        ).expect("valid syntax");
        let err = repo
            .detect_cross_group_collisions(&[], &OsInfo::new("arch", "nux"))
            .expect_err("collision must be detected");
        assert!(matches!(
            err,
            ConfigError::CrossGroupFileCollision { path, group1, group2 }
                if path == "~/.config/app/conf" && group1 == "nvim" && group2 == "vim"
        ));
    }

    #[test]
    fn test_detect_cross_group_shared_home_distinct_files_allowed() {
        let repo = RepoConfig::parse(
            "[zsh]\nfiles = \".zshrc\"\nos-nux = \"~\"\n[git]\nfiles = \".gitconfig\"\nos-nux = \"~\"\n",
        ).expect("valid syntax");
        assert!(
            repo.detect_cross_group_collisions(&[], &OsInfo::new("arch", "nux"))
                .is_ok()
        );
    }

    #[test]
    fn test_detect_cross_group_wildcard_overlaps_concrete_file() {
        let repo = RepoConfig::parse(
            "[all_conf]\nfiles = \"*.conf\"\nos-nux = \"~/.config/app\"\n[app_conf]\nfiles = \"custom.conf\"\nos-nux = \"~/.config/app\"\n",
        ).expect("valid syntax");
        let err = repo
            .detect_cross_group_collisions(&[], &OsInfo::new("arch", "nux"))
            .expect_err("overlap must collide");
        assert!(
            matches!(err, ConfigError::CrossGroupFileCollision { path, .. } if path == "~/.config/app/custom.conf")
        );
    }

    #[test]
    fn test_detect_cross_group_wildcard_with_exclusion_allows_separate_group() {
        let repo = RepoConfig::parse(
            "[all_conf]\nfiles = \"*.conf\\n!custom.conf\"\nos-nux = \"~/.config/app\"\n[app_conf]\nfiles = \"custom.conf\"\nos-nux = \"~/.config/app\"\n",
        ).expect("valid syntax");
        assert!(
            repo.detect_cross_group_collisions(&[], &OsInfo::new("arch", "nux"))
                .is_ok()
        );
    }

    #[test]
    fn test_standalone_directory_include_rule_and_cross_group_collision() {
        let os_info = OsInfo::new("arch", "nux");
        let rules = parse_selection_rules("lua\nlua/plugins/").expect("rules should parse");
        assert_eq!(
            evaluate_selection(&rules, "lua/init.lua"),
            Some(SelectionMode::PlaintextInclude)
        );
        assert_eq!(
            evaluate_selection(&rules, "lua/plugins/lsp.lua"),
            Some(SelectionMode::PlaintextInclude)
        );
        assert_eq!(evaluate_selection(&rules, "other/file.lua"), None);

        for toml in [
            "[g1]\nos-nux = \"~/.config/nvim\"\nfiles = \"lua\"\n[g2]\nos-nux = \"~/.config/nvim\"\nfiles = \"lua/init.lua\"\n",
            "[g1]\nos-nux = \"~/.config/nvim\"\nfiles = \"lua\"\n[g2]\nos-nux = \"~/.config/nvim\"\nfiles = \"lua/*\"\n",
            "[g1]\nos-nux = \"~/.config/nvim\"\nfiles = \"lua\"\n[g2]\nos-nux = \"~/.config/nvim/lua\"\nfiles = \"*\"\n",
        ] {
            let repo = RepoConfig::parse(toml).expect("valid syntax");
            assert!(matches!(
                repo.detect_cross_group_collisions(&[], &os_info),
                Err(ConfigError::CrossGroupFileCollision { .. })
            ));
        }

        let sep = RepoConfig::parse(
            "[g1]\nos-nux = \"~/.config/nvim\"\nfiles = \"*\\n!lua/*\"\n[g2]\nos-nux = \"~/.config/nvim\"\nfiles = \"lua/\"\n",
        ).expect("valid syntax");
        assert!(sep.detect_cross_group_collisions(&[], &os_info).is_ok());

        let overridden = parse_selection_rules("secrets enc\n!secrets/*").unwrap();
        assert!(!rules_have_effective_encryption(&overridden));
    }

    #[test]
    fn test_cross_group_collision_cwd_paths_and_roots() {
        let os_info = OsInfo::new("arch", "nux");

        // Same file under `.` and `./` collides statically.
        let cwd_same = RepoConfig::parse(
            "[g1]\nos-nux = \".\"\nfiles = \".env\"\n[g2]\nos-nux = \"./\"\nfiles = \".env\"\n",
        )
        .unwrap();
        assert!(matches!(
            cwd_same.detect_cross_group_collisions(&[], &os_info),
            Err(ConfigError::CrossGroupFileCollision { .. })
        ));

        // `.` + `config/app.toml` vs `./config` + `app.toml` collides statically.
        let cwd_nested = RepoConfig::parse(
            "[g1]\nos-nux = \".\"\nfiles = \"config/app.toml\"\n[g2]\nos-nux = \"./config\"\nfiles = \"app.toml\"\n",
        )
        .unwrap();
        assert!(matches!(
            cwd_nested.detect_cross_group_collisions(&[], &os_info),
            Err(ConfigError::CrossGroupFileCollision { .. })
        ));

        // `~` + `.env` vs `.` + `.env` only collides when `cwd == home_dir`.
        let mixed = RepoConfig::parse(
            "[home_grp]\nos-nux = \"~\"\nfiles = \".env\"\n[cwd_grp]\nos-nux = \".\"\nfiles = \".env\"\n",
        )
        .unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let home_dir = tmp.path().join("home");
        let project_dir = tmp.path().join("project");
        fs::create_dir_all(&home_dir).unwrap();
        fs::create_dir_all(&project_dir).unwrap();

        assert!(
            mixed
                .detect_cross_group_collisions_with_roots(&[], &os_info, &home_dir, &project_dir)
                .is_ok()
        );
        assert!(matches!(
            mixed.detect_cross_group_collisions_with_roots(&[], &os_info, &home_dir, &home_dir),
            Err(ConfigError::CrossGroupFileCollision { .. })
        ));
    }

    #[test]
    fn test_nested_subgroup_delegation_avoids_parent_collision_while_catching_peer_overlap() {
        let os_info = OsInfo::new("arch", "nux");
        let valid_hierarchy = r#"
vault_id = "0123456789abcdef"
password_slot = "cGFzc3dvcmQ="
recovery_slot = "cmVjb3Zlcnk="

[vault]
os-nux = "./notes"
files = "* enc=full"

[vault.sleep]
files = "* enc=full"

[vault.problems]
files = "* enc=full"
"#;
        let cfg = RepoConfig::parse(valid_hierarchy).unwrap();
        assert!(cfg.detect_cross_group_collisions(&[], &os_info).is_ok());

        let peer_overlap =
            format!("{valid_hierarchy}\n[rogue]\nos-nux = \"./notes/goals\"\nfiles = \"*\"\n");
        let cfg_rogue = RepoConfig::parse(&peer_overlap).unwrap();
        assert!(matches!(
            cfg_rogue.detect_cross_group_collisions(&[], &os_info),
            Err(ConfigError::CrossGroupFileCollision { .. })
        ));

        let peer_sub_overlap = format!(
            "{valid_hierarchy}\n[rogue_sleep]\nos-nux = \"./notes/sleep\"\nfiles = \"log.md\"\n"
        );
        let cfg_rogue_sub = RepoConfig::parse(&peer_sub_overlap).unwrap();
        assert!(matches!(
            cfg_rogue_sub.detect_cross_group_collisions(&[], &os_info),
            Err(ConfigError::CrossGroupFileCollision { .. })
        ));
    }
}
