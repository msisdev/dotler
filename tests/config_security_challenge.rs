use dotler::config::ConfigError;
use dotler::config::local::LocalConfig;
use dotler::config::repo::{
    GroupConfig, OsInfo, RepoConfig, parse_selection_rules, resolve_group_target_path,
    validate_path_security,
};

// ---------------------------------------------------------------------------
// Suite 1: Malformed Syntax, Unknown Attributes & Line-Numbered Error Reporting
// ---------------------------------------------------------------------------

#[test]
fn test_selection_rule_typo_encrpyt_reports_exact_line() {
    let content = "item1\n# comment line\nitem2\nitem3 encrpyt\nitem4";
    let err = parse_selection_rules(content).expect_err("attribute typo 'encrpyt' must fail");
    match err {
        ConfigError::InvalidSelectionAttribute {
            attribute,
            line_no,
            hint,
        } => {
            assert_eq!(attribute, "encrpyt");
            assert_eq!(line_no, 4);
            assert!(
                hint.contains("encrypt"),
                "hint should suggest the correct attribute 'encrypt'"
            );
        }
        other => panic!("expected InvalidSelectionAttribute, got: {other:?}"),
    }
}

#[test]
fn test_selection_rule_multiple_trailing_tokens_reports_error_and_line() {
    let content = "\n\nconfig.toml encrypt unexpected_token";
    let err = parse_selection_rules(content).expect_err("multiple tokens must fail");
    match err {
        ConfigError::InvalidSelectionAttribute { line_no, .. } => {
            assert_eq!(line_no, 3);
        }
        other => panic!("expected InvalidSelectionAttribute, got: {other:?}"),
    }
}

#[test]
fn test_selection_rule_rejects_typos_in_attribute() {
    let content = "secret.key encrpyt";
    let err = parse_selection_rules(content).expect_err("misspelled attribute must fail");
    match err {
        ConfigError::InvalidSelectionAttribute {
            attribute,
            line_no,
            hint,
        } => {
            assert_eq!(attribute, "encrpyt");
            assert_eq!(line_no, 1);
            assert!(hint.contains("encrypt"));
        }
        other => panic!("expected InvalidSelectionAttribute, got: {other:?}"),
    }
}

#[test]
fn test_local_config_deny_unknown_fields_with_hint() {
    let content = r#"
encrpyt = true
default_repo = "main"
"#;
    let err = LocalConfig::parse(content).expect_err("unknown field 'encrpyt' must be rejected");
    match err {
        ConfigError::UnknownField { field, hint } => {
            assert!(field.contains("encrpyt"));
            assert!(!hint.is_empty());
        }
        other => panic!("expected UnknownField, got: {other:?}"),
    }
}

#[test]
fn test_vault_config_deny_unknown_fields() {
    let content = r#"
vault_id = "0123456789abcdef"
password_slot = "cGFzc3dvcmQ="
recovery_slot = "cmVjb3Zlcnk="
encrpyt_algorithm = "argon2id"
"#;
    let err = RepoConfig::parse(content).expect_err("unknown root field must fail");
    assert!(matches!(
        err,
        ConfigError::UnknownField { .. } | ConfigError::TomlSyntaxError(_)
    ));
}

#[test]
fn test_repo_config_rejects_unknown_os_key_with_allowed_list() {
    let content = r#"
[shell]
files = "zshrc"
os-archlinux = "~/.zshrc"
"#;
    let err = RepoConfig::parse(content).expect_err("unknown OS key 'os-archlinux' must fail");
    match err {
        ConfigError::UnknownOsKey { key, hint } => {
            assert_eq!(key, "os-archlinux");
            assert!(hint.contains("os-arch"));
            assert!(hint.contains("os-nux"));
        }
        other => panic!("expected UnknownOsKey, got: {other:?}"),
    }
}

#[test]
fn test_repo_config_allows_vault_as_group_name_and_rejects_reserved_root_key_group() {
    let valid_vault_group = r#"
[vault]
files = "secret"
os-nux = "~/.secret"
"#;
    let cfg = RepoConfig::parse(valid_vault_group).expect("[vault] can be used as a group name");
    assert!(cfg.groups.contains_key("vault"));

    let reserved_root_key_group = r#"
[vault_id]
files = "secret"
os-nux = "~/.secret"
"#;
    let err = RepoConfig::parse(reserved_root_key_group)
        .expect_err("reserved root vault key cannot be used as a group name");
    assert!(
        matches!(
            err,
            ConfigError::UnknownField { .. }
                | ConfigError::InvalidDeviceName { .. }
                | ConfigError::TomlSyntaxError(_)
        ),
        "got: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Suite 2: 3-Tier Security Path Validation
// ---------------------------------------------------------------------------

#[test]
fn test_security_path_validation_rejects_traversal() {
    let cases = &[
        "~/..",
        "~/../etc/shadow",
        "~/.config/../secret",
        "~/foo/bar/../../baz",
    ];
    for path in cases {
        let err = validate_path_security(path)
            .expect_err(&format!("path '{path}' should fail validation"));
        assert!(
            matches!(err, ConfigError::HardBlockedPath { .. }),
            "path '{path}' must produce HardBlockedPath, got: {err:?}"
        );
    }
}

#[test]
fn test_security_path_validation_rejects_non_home_absolute_paths() {
    let cases = &[
        "/etc/shadow",
        "/var/log",
        "/root/.bashrc",
        "C:\\Windows\\System32",
        "relative/path/without/tilde",
    ];
    for path in cases {
        let err = validate_path_security(path)
            .expect_err(&format!("path '{path}' should fail validation"));
        assert!(
            matches!(err, ConfigError::HardBlockedPath { .. }),
            "path '{path}' must produce HardBlockedPath, got: {err:?}"
        );
    }
}

#[test]
fn test_security_path_validation_rejects_env_vars() {
    let cases = &[
        "~/$HOME",
        "~/$USER/data",
        "~/%USERPROFILE%",
        "~/%APPDATA%/config",
    ];
    for path in cases {
        let err = validate_path_security(path)
            .expect_err(&format!("path '{path}' should fail validation"));
        assert!(
            matches!(err, ConfigError::HardBlockedPath { .. }),
            "path '{path}' must produce HardBlockedPath, got: {err:?}"
        );
    }
}

#[test]
fn test_security_path_validation_rejects_backslashes() {
    let cases = &["~\\AppData", "~/.config\\app", "~/folder\\nested\\file"];
    for path in cases {
        let err = validate_path_security(path)
            .expect_err(&format!("path '{path}' should fail validation"));
        assert!(
            matches!(err, ConfigError::HardBlockedPath { .. }),
            "path '{path}' must produce HardBlockedPath, got: {err:?}"
        );
    }
}

#[test]
fn test_local_config_repos_rejects_security_violations() {
    let mut config = LocalConfig::default();
    config
        .repos
        .insert("test".to_string(), "~/../etc/shadow".to_string());
    assert!(matches!(
        config.validate().unwrap_err(),
        ConfigError::HardBlockedPath { .. }
    ));

    let mut config2 = LocalConfig::default();
    config2
        .repos
        .insert("test".to_string(), "/etc/shadow".to_string());
    assert!(matches!(
        config2.validate().unwrap_err(),
        ConfigError::InvalidHomePath { .. }
    ));

    let mut config3 = LocalConfig::default();
    config3
        .repos
        .insert("test".to_string(), "~/$HOME/repo".to_string());
    assert!(matches!(
        config3.validate().unwrap_err(),
        ConfigError::HardBlockedPath { .. }
    ));

    // ~/repo\nested starts with ~/ but contains \ -> HardBlockedPath
    let mut config4 = LocalConfig::default();
    config4
        .repos
        .insert("test".to_string(), "~/repo\\nested".to_string());
    assert!(matches!(
        config4.validate().unwrap_err(),
        ConfigError::HardBlockedPath { .. }
    ));
}

// EMPIRICAL CHALLENGE: Verify whether 'files' rules can inject directory traversal
// or environment variables into RepoConfig without detection
#[test]
fn test_challenge_files_rules_path_security_bypass() {
    let malicious_files = [
        "../../../../etc/shadow",
        "../.bashrc",
        "/etc/shadow",
        "$HOME/.bashrc",
        "%USERPROFILE%/secret",
        "folder\\traversal",
    ];

    for malicious_pattern in &malicious_files {
        let manifest = format!(
            r#"
[exploit]
files = '{malicious_pattern}'
os-nux = "~/.config/app"
"#
        );
        let parse_result = RepoConfig::parse(&manifest);
        assert!(
            parse_result.is_err(),
            "Malicious pattern '{malicious_pattern}' must be rejected by path security"
        );
        let err = parse_result.unwrap_err();
        assert!(
            matches!(err, ConfigError::HardBlockedPath { .. }),
            "Malicious pattern '{malicious_pattern}' must produce HardBlockedPath, got: {err:?}"
        );
        assert_eq!(
            err.exit_code(),
            3,
            "HardBlockedPath must return exit code 3"
        );
    }
}

// ---------------------------------------------------------------------------
// Suite 3: Cross-Group Collisions
// ---------------------------------------------------------------------------

#[test]
fn test_cross_group_collision_same_file_detected() {
    let content = r#"
[group_a]
files = "shared.conf"
os-nux = "~/.config/common"

[group_b]
files = "shared.conf"
os-nux = "~/.config/common"
"#;
    let repo = RepoConfig::parse(content).expect("syntax valid");
    let os_info = OsInfo::new("arch", "linux");
    let err = repo
        .detect_cross_group_collisions(&[], &os_info)
        .expect_err("collision on shared.conf must be detected");
    assert!(matches!(err, ConfigError::CrossGroupFileCollision { .. }));
}

#[test]
fn test_cross_group_collision_inactive_group_does_not_collide() {
    let content = r#"
[linux_app]
files = "config.toml"
os-nux = "~/.config/app"

[mac_app]
files = "config.toml"
os-mac = "~/.config/app"
"#;
    let repo = RepoConfig::parse(content).expect("syntax valid");
    let linux_info = OsInfo::new("arch", "linux");
    assert!(
        repo.detect_cross_group_collisions(&[], &linux_info).is_ok(),
        "inactive macOS group should not collide with active Linux group"
    );
}

// EMPIRICAL CHALLENGE: Two active groups targeting different files in the home directory
// e.g. group zsh managing ~/.zshrc and group bash managing ~/.bashrc.
// Current implementation erroneously reports a collision on '~'.
#[test]
fn test_challenge_distinct_files_in_home_directory_collision_bug() {
    let content = r#"
[shell_zsh]
files = ".zshrc"
os-nux = "~"

[shell_bash]
files = ".bashrc"
os-nux = "~"
"#;
    let repo = RepoConfig::parse(content).expect("syntax valid");
    let os_info = OsInfo::new("arch", "linux");
    let collision_result = repo.detect_cross_group_collisions(&[], &os_info);
    assert!(
        collision_result.is_ok(),
        "distinct files under '~' must not collide: {collision_result:?}"
    );
}

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
        ("$HOME/.bashrc encrypt", 3),
        ("folder\\traversal", 3),
        ("!/etc/shadow", 3),
        (".config/dotler encrypt", 3),
        (".config/dotler/state.db encrypt", 3),
        ("!.git", 3),
        ("../relative_escape", 3),
        ("~/.secret encrypt", 3),
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
            "!file.txt encrypt",
            "encrypt",
            1,
            Some("already specifies selection mode"),
        ),
        ("!secret.key encrpyt", "encrpyt", 1, Some("encrypt")),
        ("regular_file.txt encrpyt", "encrpyt", 1, Some("encrypt")),
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
