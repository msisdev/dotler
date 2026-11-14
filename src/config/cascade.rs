use std::fs;

use crate::config::ConfigError;
use crate::config::repo::{GroupConfig, RepoConfig};
use crate::config::selection::{SelectionMode, SelectionRule, evaluate_selection, parse_selection_rules};

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
    rule.pattern.trim_start_matches("./").trim_start_matches('/')
}

fn is_included(rules: &[SelectionRule], path: &str) -> bool {
    matches!(evaluate_selection(rules, path), Some(m) if m != SelectionMode::Exclude)
}

fn rel_to_base(target_path: &str, base: &str) -> Option<String> {
    if target_path == base {
        Some(String::new())
    } else if base == "~" {
        target_path.strip_prefix("~/").map(str::to_string)
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
        if rel_to_base(file, &empty.base).is_some() {
            return Err(collision(file.clone(), g1, g2));
        }
    }
    for w in &other.wildcard_rules {
        let target = format!("{}/{}", other.base, clean_rule_pattern(w));
        if rel_to_base(&target, &empty.base).is_some() {
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
            && is_included(&wc_group.rules, &rel)
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
        let target = format!("{}/{}", src.base, p);
        if let Some(rel) = rel_to_base(&target, &dst.base)
            && !rel.is_empty()
            && is_included(&src.rules, p)
            && is_included(&dst.rules, &rel)
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
        let mut active_groups = Vec::new();

        for (group_name, group) in &self.groups {
            let Some(target_base) = resolve_group_target_path(group, devices, os_info) else {
                continue;
            };
            let rules = parse_selection_rules(&group.files)?;
            let normalized_base = target_base.trim_end_matches('/').to_string();
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
                        if rule.mode != SelectionMode::Exclude && is_included(&rules, &probe) {
                            wildcard_rules.push(SelectionRule {
                                pattern: probe,
                                mode: rule.mode,
                                line_no: rule.line_no,
                            });
                        }
                    } else if is_included(&rules, clean_pattern) {
                        let target_file = format!("{normalized_base}/{clean_pattern}");
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
                    let target1 = format!("{}/{}", g1.base, clean_rule_pattern(w1));
                    for w2 in &g2.wildcard_rules {
                        let target2 = format!("{}/{}", g2.base, clean_rule_pattern(w2));
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
        let res = resolve_with_paths(&[("laptop", "~/laptop/path"), ("os-arch", "~/arch/path"), ("os-nux", "~/linux/path")]);
        assert_eq!(res.as_deref(), Some("~/laptop/path"));
    }

    #[test]
    fn test_device_os_cascading_distro_fallback() {
        let res = resolve_with_paths(&[("desktop", "~/desktop/path"), ("os-arch", "~/arch/path"), ("os-nux", "~/linux/path")]);
        assert_eq!(res.as_deref(), Some("~/arch/path"));
    }

    #[test]
    fn test_device_os_cascading_family_fallback() {
        let res = resolve_with_paths(&[("desktop", "~/desktop/path"), ("os-debian", "~/debian/path"), ("os-nux", "~/linux/path")]);
        assert_eq!(res.as_deref(), Some("~/linux/path"));
    }

    #[test]
    fn test_device_os_cascading_skip_when_unmatched() {
        assert_eq!(resolve_with_paths(&[("workstation", "~/work/path"), ("os-mac", "~/mac/path")]), None);
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
        let err = repo.detect_cross_group_collisions(&[], &OsInfo::new("arch", "nux")).expect_err("collision must be detected");
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
        assert!(repo.detect_cross_group_collisions(&[], &OsInfo::new("arch", "nux")).is_ok());
    }

    #[test]
    fn test_detect_cross_group_wildcard_overlaps_concrete_file() {
        let repo = RepoConfig::parse(
            "[all_conf]\nfiles = \"*.conf\"\nos-nux = \"~/.config/app\"\n[app_conf]\nfiles = \"custom.conf\"\nos-nux = \"~/.config/app\"\n",
        ).expect("valid syntax");
        let err = repo.detect_cross_group_collisions(&[], &OsInfo::new("arch", "nux")).expect_err("overlap must collide");
        assert!(matches!(err, ConfigError::CrossGroupFileCollision { path, .. } if path == "~/.config/app/custom.conf"));
    }

    #[test]
    fn test_detect_cross_group_wildcard_with_exclusion_allows_separate_group() {
        let repo = RepoConfig::parse(
            "[all_conf]\nfiles = \"*.conf\\n!custom.conf\"\nos-nux = \"~/.config/app\"\n[app_conf]\nfiles = \"custom.conf\"\nos-nux = \"~/.config/app\"\n",
        ).expect("valid syntax");
        assert!(repo.detect_cross_group_collisions(&[], &OsInfo::new("arch", "nux")).is_ok());
    }

    #[test]
    fn test_standalone_directory_include_rule_and_cross_group_collision() {
        let os_info = OsInfo::new("arch", "nux");
        let rules = parse_selection_rules("lua\nlua/plugins/").expect("rules should parse");
        assert_eq!(evaluate_selection(&rules, "lua/init.lua"), Some(SelectionMode::PlaintextInclude));
        assert_eq!(evaluate_selection(&rules, "lua/plugins/lsp.lua"), Some(SelectionMode::PlaintextInclude));
        assert_eq!(evaluate_selection(&rules, "other/file.lua"), None);

        for toml in [
            "[g1]\nos-nux = \"~/.config/nvim\"\nfiles = \"lua\"\n[g2]\nos-nux = \"~/.config/nvim\"\nfiles = \"lua/init.lua\"\n",
            "[g1]\nos-nux = \"~/.config/nvim\"\nfiles = \"lua\"\n[g2]\nos-nux = \"~/.config/nvim\"\nfiles = \"lua/*\"\n",
            "[g1]\nos-nux = \"~/.config/nvim\"\nfiles = \"lua\"\n[g2]\nos-nux = \"~/.config/nvim/lua\"\nfiles = \"*\"\n",
        ] {
            let repo = RepoConfig::parse(toml).expect("valid syntax");
            assert!(matches!(repo.detect_cross_group_collisions(&[], &os_info), Err(ConfigError::CrossGroupFileCollision { .. })));
        }

        let sep = RepoConfig::parse(
            "[g1]\nos-nux = \"~/.config/nvim\"\nfiles = \"*\\n!lua/*\"\n[g2]\nos-nux = \"~/.config/nvim\"\nfiles = \"lua/\"\n",
        ).expect("valid syntax");
        assert!(sep.detect_cross_group_collisions(&[], &os_info).is_ok());

        let overridden = parse_selection_rules("secrets enc\n!secrets/*").unwrap();
        assert!(!rules_have_effective_encryption(&overridden));
    }
}
