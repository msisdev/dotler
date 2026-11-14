use dotler::config::ConfigError;
use dotler::config::repo::{
    GroupConfig, OsInfo, RepoConfig, parse_selection_rules, resolve_group_target_path,
};

// ---------------------------------------------------------------------------
// Suite 4: Device & OS Cascading Resolution Under Simulated Environments
// ---------------------------------------------------------------------------

#[test]
fn test_cascading_resolution_device_beats_distro_and_family() {
    let mut group = GroupConfig::default();
    group
        .paths
        .insert("dev-laptop".to_string(), "~/laptop".to_string());
    group
        .paths
        .insert("os-arch".to_string(), "~/arch".to_string());
    group
        .paths
        .insert("os-nux".to_string(), "~/linux".to_string());

    let devices = vec!["dev-laptop".to_string()];
    let os_info = OsInfo::new("arch", "linux");

    let resolved = resolve_group_target_path(&group, &devices, &os_info);
    assert_eq!(resolved.as_deref(), Some("~/laptop"));
}

#[test]
fn test_cascading_resolution_distro_beats_family_when_no_device() {
    let mut group = GroupConfig::default();
    group
        .paths
        .insert("os-arch".to_string(), "~/arch".to_string());
    group
        .paths
        .insert("os-nux".to_string(), "~/linux".to_string());

    let os_info = OsInfo::new("arch", "linux");

    let resolved = resolve_group_target_path(&group, &[], &os_info);
    assert_eq!(resolved.as_deref(), Some("~/arch"));
}

#[test]
fn test_cascading_resolution_family_fallback_when_distro_unmatched() {
    let mut group = GroupConfig::default();
    group
        .paths
        .insert("os-debian".to_string(), "~/debian".to_string());
    group
        .paths
        .insert("os-nux".to_string(), "~/linux".to_string());

    let os_info = OsInfo::new("arch", "linux");

    let resolved = resolve_group_target_path(&group, &[], &os_info);
    assert_eq!(resolved.as_deref(), Some("~/linux"));
}

#[test]
fn test_cascading_resolution_macos_simulation() {
    let mut group = GroupConfig::default();
    group
        .paths
        .insert("os-nux".to_string(), "~/linux".to_string());
    group
        .paths
        .insert("os-mac".to_string(), "~/macos".to_string());

    let os_info = OsInfo::new("macos", "macos");

    let resolved = resolve_group_target_path(&group, &[], &os_info);
    assert_eq!(resolved.as_deref(), Some("~/macos"));
}

#[test]
fn test_cascading_resolution_bsd_distro_and_family() {
    let mut group = GroupConfig::default();
    group
        .paths
        .insert("os-freebsd".to_string(), "~/freebsd".to_string());
    group
        .paths
        .insert("os-bsd".to_string(), "~/bsd".to_string());

    let freebsd_info = OsInfo::new("freebsd", "bsd");
    assert_eq!(
        resolve_group_target_path(&group, &[], &freebsd_info).as_deref(),
        Some("~/freebsd")
    );

    let openbsd_info = OsInfo::new("openbsd", "bsd");
    assert_eq!(
        resolve_group_target_path(&group, &[], &openbsd_info).as_deref(),
        Some("~/bsd")
    );
}

#[test]
fn test_cascading_resolution_multi_device_order_precedence() {
    let mut group = GroupConfig::default();
    group
        .paths
        .insert("device-b".to_string(), "~/b".to_string());
    group
        .paths
        .insert("device-c".to_string(), "~/c".to_string());

    let devices = vec![
        "device-a".to_string(),
        "device-c".to_string(),
        "device-b".to_string(),
    ];
    let os_info = OsInfo::new("arch", "linux");

    let resolved = resolve_group_target_path(&group, &devices, &os_info);
    assert_eq!(
        resolved.as_deref(),
        Some("~/c"),
        "device-c should win because it appears before device-b in the priority list"
    );
}

#[test]
fn test_cascading_resolution_unmatched_environment_returns_none() {
    let mut group = GroupConfig::default();
    group
        .paths
        .insert("workstation".to_string(), "~/work".to_string());
    group
        .paths
        .insert("os-win".to_string(), "~/win".to_string());

    let os_info = OsInfo::new("arch", "linux");
    let resolved = resolve_group_target_path(&group, &["laptop".to_string()], &os_info);
    assert_eq!(resolved, None);
}

// ---------------------------------------------------------------------------
// Suite 5: Empirical Remediation Stress Verification Suite
// ---------------------------------------------------------------------------

#[test]
fn test_empirical_shared_base_directories_nested_and_distinct() {
    let manifest = r#"
[group_home_zsh]
files = ".zshrc"
os-nux = "~"

[group_home_bash]
files = ".bashrc"
os-nux = "~"

[group_config_nvim]
files = "init.lua"
os-nux = "~/.config/nvim"

[group_config_alacritty]
files = "alacritty.toml"
os-nux = "~/.config/alacritty"

[group_config_base]
files = "tmux/tmux.conf"
os-nux = "~/.config"

[group_home_nested_direct]
files = ".config/helix/config.toml"
os-nux = "~"
"#;
    let repo = RepoConfig::parse(manifest).expect("valid configuration syntax");
    let os_info = OsInfo::new("arch", "linux");
    assert!(
        repo.detect_cross_group_collisions(&[], &os_info).is_ok(),
        "Multiple active groups sharing base directories (~ and ~/.config) with distinct targets must not collide"
    );
}

#[test]
fn test_empirical_collision_different_bases_resolving_to_same_target() {
    let manifest = r#"
[group_base_home]
files = ".config/app/settings.toml"
os-nux = "~"

[group_base_config]
files = "app/settings.toml"
os-nux = "~/.config"
"#;
    let repo = RepoConfig::parse(manifest).expect("valid configuration syntax");
    let os_info = OsInfo::new("arch", "linux");
    let err = repo
        .detect_cross_group_collisions(&[], &os_info)
        .expect_err("groups resolving to identical target path from different bases must collide");
    match err {
        ConfigError::CrossGroupFileCollision {
            path,
            group1,
            group2,
        } => {
            assert_eq!(path, "~/.config/app/settings.toml");
            assert!(
                (group1 == "group_base_home" && group2 == "group_base_config")
                    || (group1 == "group_base_config" && group2 == "group_base_home")
            );
        }
        other => panic!("expected CrossGroupFileCollision, got: {other:?}"),
    }
}

#[test]
fn test_empirical_collision_cross_base_wildcard_overlap() {
    let manifest = r#"
[group_wildcard_parent]
files = "nvim/*.lua"
os-nux = "~/.config"

[group_concrete_child]
files = "init.lua"
os-nux = "~/.config/nvim"
"#;
    let repo = RepoConfig::parse(manifest).expect("valid configuration syntax");
    let os_info = OsInfo::new("arch", "linux");
    let err = repo
        .detect_cross_group_collisions(&[], &os_info)
        .expect_err("parent wildcard must detect collision with child concrete file");
    match err {
        ConfigError::CrossGroupFileCollision { path, .. } => {
            assert_eq!(path, "~/.config/nvim/init.lua");
        }
        other => panic!("expected CrossGroupFileCollision, got: {other:?}"),
    }
}

#[test]
fn test_empirical_collision_empty_files_directory_takeover() {
    let manifest = r#"
[group_directory_owner]
files = ""
os-nux = "~/.config/app"

[group_file_owner]
files = "config.toml"
os-nux = "~/.config/app"
"#;
    let repo = RepoConfig::parse(manifest).expect("valid configuration syntax");
    let os_info = OsInfo::new("arch", "linux");
    let err = repo
        .detect_cross_group_collisions(&[], &os_info)
        .expect_err("empty files claiming directory must collide with file owner");
    assert!(matches!(err, ConfigError::CrossGroupFileCollision { .. }));
}

#[test]
fn test_empirical_path_traversal_and_malicious_patterns_with_prefixes() {
    let malicious_cases = [
        ("!../../../../etc/shadow", 3),
        ("$HOME/.bashrc enc", 3),
        ("folder\\traversal", 3),
        ("!/etc/shadow", 3),
        (".config/dotler enc", 3),
        (".config/dotler/state.db enc", 3),
        ("!.git", 3),
        ("../relative_escape", 3),
        ("~/.secret enc", 3),
        ("!%APPDATA%/secret", 3),
    ];

    for (malicious_rule, expected_exit) in malicious_cases {
        let manifest = format!(
            r#"
vault_id = "0123456789abcdef"
password_slot = "cGFzc3dvcmQ="
recovery_slot = "cmVjb3Zlcnk="

[exploit]
files = '{malicious_rule}'
os-nux = "~/.config/app"
"#
        );
        let err =
            RepoConfig::parse(&manifest).expect_err(&format!("rule '{malicious_rule}' must fail"));
        assert!(
            matches!(err, ConfigError::HardBlockedPath { .. }),
            "rule '{malicious_rule}' must produce HardBlockedPath, got: {err:?}"
        );
        assert_eq!(
            err.exit_code(),
            expected_exit,
            "rule '{malicious_rule}' exit code mismatch"
        );
    }
}

#[test]
fn test_empirical_selection_rule_typos_and_malformed_tokens() {
    let typo_cases = [
        ("!config.toml typo", "typo", 1, None),
        (
            "!file.txt enc",
            "enc",
            1,
            Some("already specifies selection mode"),
        ),
        (
            "!file.txt encrypt",
            "encrypt",
            1,
            Some("already specifies selection mode"),
        ),
        ("!secret.key encrpyt", "encrpyt", 1, Some("enc")),
        ("regular_file.txt encrpyt", "encrpyt", 1, Some("enc")),
        ("regular_file.txt encrypt", "encrypt", 1, Some("enc")),
        ("regular_file.txt template", "template", 1, Some("tmpl")),
        ("regular_file.txt tmp", "tmp", 1, Some("tmpl")),
        (
            "regular_file.txt extra attribute tokens",
            "extra attribute tokens",
            1,
            None,
        ),
    ];

    for (rule_line, expected_attr, expected_line, expected_hint_part) in typo_cases {
        let err =
            parse_selection_rules(rule_line).expect_err(&format!("rule '{rule_line}' must fail"));
        match err {
            ConfigError::InvalidSelectionAttribute {
                attribute,
                line_no,
                hint,
            } => {
                assert_eq!(attribute, expected_attr, "for rule: {rule_line}");
                assert_eq!(line_no, expected_line, "for rule: {rule_line}");
                if let Some(expected_part) = expected_hint_part {
                    assert!(
                        hint.contains(expected_part),
                        "hint '{hint}' should mention '{expected_part}' for rule: {rule_line}"
                    );
                }
            }
            other => panic!("expected InvalidSelectionAttribute for '{rule_line}', got: {other:?}"),
        }
    }

    // Also verify empty pattern after '!' prefix fails
    let err = parse_selection_rules("!").expect_err("empty prefix '!' must fail");
    assert!(
        matches!(err, ConfigError::InvalidSelectionAttribute { .. }),
        "empty prefix '!' must produce InvalidSelectionAttribute, got: {err:?}"
    );
}
