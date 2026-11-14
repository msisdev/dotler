use dotler::config::ConfigError;
use dotler::config::local::LocalConfig;
use dotler::config::repo::{OsInfo, RepoConfig, parse_selection_rules, validate_path_security};

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
                hint.contains("enc") && hint.contains("tmpl"),
                "hint should suggest the correct attributes 'enc' and 'tmpl'"
            );
        }
        other => panic!("expected InvalidSelectionAttribute, got: {other:?}"),
    }
}

#[test]
fn test_selection_rule_multiple_trailing_tokens_reports_error_and_line() {
    let content = "\n\nconfig.toml enc unexpected_token";
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
            assert!(hint.contains("enc") && hint.contains("tmpl"));
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
