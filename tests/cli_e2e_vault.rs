mod common;

use std::fs;
use std::io::Write;
use std::process::Stdio;

use common::E2eSandbox;
use serde_json::Value;

#[test]
fn test_e2e_tidy_default_keep_and_multi_group_filter() {
    let sandbox = E2eSandbox::new();

    let init_out = sandbox
        .cmd()
        .args(["init", "--label", "main"])
        .output()
        .unwrap();
    assert_eq!(init_out.status.code(), Some(0));

    let dir_a = sandbox.home_dir.join(".config").join("app_a");
    let dir_b = sandbox.home_dir.join(".config").join("app_b");
    let dir_c = sandbox.home_dir.join(".config").join("app_c");
    fs::create_dir_all(&dir_a).unwrap();
    fs::create_dir_all(&dir_b).unwrap();
    fs::create_dir_all(&dir_c).unwrap();

    fs::write(dir_a.join("a.conf"), "a\n").unwrap();
    fs::write(dir_b.join("b.conf"), "b\n").unwrap();
    fs::write(dir_c.join("c.conf"), "c\n").unwrap();

    let toml_v1 = r#"[grp_a]
os-nux = "~/.config/app_a"
os-mac = "~/.config/app_a"
os-win = "~/.config/app_a"
files = "*"

[grp_b]
os-nux = "~/.config/app_b"
os-mac = "~/.config/app_b"
os-win = "~/.config/app_b"
files = "*"

[grp_c]
os-nux = "~/.config/app_c"
os-mac = "~/.config/app_c"
os-win = "~/.config/app_c"
files = "*"
"#;
    fs::write(sandbox.repo_dir.join("dotler.toml"), toml_v1).unwrap();

    let imp_out = sandbox.cmd().args(["import", "-y"]).output().unwrap();
    assert_eq!(imp_out.status.code(), Some(0));

    // Exclude all three files so each becomes an orphan in its respective group
    let toml_v2 = r#"[grp_a]
os-nux = "~/.config/app_a"
os-mac = "~/.config/app_a"
os-win = "~/.config/app_a"
files = "!*"

[grp_b]
os-nux = "~/.config/app_b"
os-mac = "~/.config/app_b"
os-win = "~/.config/app_b"
files = "!*"

[grp_c]
os-nux = "~/.config/app_c"
os-mac = "~/.config/app_c"
os-win = "~/.config/app_c"
files = "!*"
"#;
    fs::write(sandbox.repo_dir.join("dotler.toml"), toml_v2).unwrap();

    // Run `dotler tidy grp_a grp_b` with NO --purge flag (must keep OS files and filter both groups)
    let tidy_out = sandbox
        .cmd()
        .args(["tidy", "grp_a", "grp_b", "--json"])
        .output()
        .unwrap();
    assert_eq!(tidy_out.status.code(), Some(0));

    let parsed: Value = serde_json::from_slice(&tidy_out.stdout).unwrap();
    assert_eq!(parsed["ok"], true);
    let kept = parsed["data"]["untracked_kept_orphans"].as_array().unwrap();
    let removed = parsed["data"]["removed_os_orphans"].as_array().unwrap();
    assert_eq!(
        kept.len(),
        2,
        "Both grp_a and grp_b orphans must be untracked while preserving OS files by default"
    );
    assert_eq!(removed.len(), 0);

    // OS files must remain intact under default behavior
    assert!(dir_a.join("a.conf").is_file());
    assert!(dir_b.join("b.conf").is_file());
    assert!(dir_c.join("c.conf").is_file());

    // grp_c was NOT passed to tidy, so running `tidy grp_c --purge` now must find and delete c.conf
    let tidy_c = sandbox
        .cmd()
        .args(["tidy", "grp_c", "--purge", "--json"])
        .output()
        .unwrap();
    assert_eq!(tidy_c.status.code(), Some(0));
    let parsed_c: Value = serde_json::from_slice(&tidy_c.stdout).unwrap();
    assert_eq!(
        parsed_c["data"]["removed_os_orphans"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(!dir_c.join("c.conf").exists());
}

#[test]
fn test_e2e_vault_passwd_rotates_all_matching_registered_repos() {
    let sandbox = E2eSandbox::new();

    let repo_personal = sandbox.home_dir.join("personal-dots");
    let repo_work = sandbox.home_dir.join("work-dots");
    let repo_other = sandbox.home_dir.join("other-dots");
    let repo_plain = sandbox.home_dir.join("plain-dots");

    for (dir, label) in [
        (&repo_personal, "personal"),
        (&repo_work, "work"),
        (&repo_other, "other"),
        (&repo_plain, "plain"),
    ] {
        fs::create_dir_all(dir).unwrap();
        let out = sandbox
            .cmd()
            .current_dir(dir)
            .args(["init", "--label", label])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(0));
    }

    // Initialize personal and work with shared_old_pass, and other with separate_pass
    for (dir, pass) in [
        (&repo_personal, "shared_old_pass_123"),
        (&repo_work, "shared_old_pass_123"),
        (&repo_other, "separate_foreign_pass_456"),
    ] {
        let mut child = sandbox
            .cmd()
            .current_dir(dir)
            .args(["vault", "init", "--password-stdin"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        if let Some(mut stdin) = child.stdin.take() {
            writeln!(stdin, "{pass}").unwrap();
        }
        let out = child.wait_with_output().unwrap();
        assert_eq!(out.status.code(), Some(0));
    }

    let other_before = fs::read_to_string(repo_other.join("dotler.toml")).unwrap();

    // Run `dotler vault passwd` from outside all repo directories (`home_dir`)
    let mut passwd_child = sandbox
        .cmd()
        .env("DOTLER_PASSPHRASE", "shared_old_pass_123")
        .current_dir(&sandbox.home_dir)
        .args(["vault", "passwd", "--password-stdin", "--json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(mut stdin) = passwd_child.stdin.take() {
        writeln!(stdin, "shared_new_pass_789").unwrap();
    }
    let passwd_out = passwd_child.wait_with_output().unwrap();
    assert_eq!(
        passwd_out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&passwd_out.stderr)
    );

    let parsed: Value = serde_json::from_slice(&passwd_out.stdout).unwrap();
    assert_eq!(parsed["ok"], true);
    assert_eq!(
        parsed["data"]["rotated_repos"],
        serde_json::json!(["personal", "work"])
    );
    assert_eq!(
        parsed["data"]["skipped_repos"],
        serde_json::json!(["other", "plain"])
    );

    // `other` repo with separate password must be byte-for-byte untouched
    let other_after = fs::read_to_string(repo_other.join("dotler.toml")).unwrap();
    assert_eq!(other_before, other_after);

    // Subsequent rotation using `shared_new_pass_789` must succeed on both `personal` and `work`
    let mut passwd_child2 = sandbox
        .cmd()
        .env("DOTLER_PASSPHRASE", "shared_new_pass_789")
        .current_dir(&sandbox.home_dir)
        .args(["vault", "passwd", "--password-stdin", "--json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(mut stdin) = passwd_child2.stdin.take() {
        writeln!(stdin, "shared_final_pass_000").unwrap();
    }
    let passwd_out2 = passwd_child2.wait_with_output().unwrap();
    assert_eq!(passwd_out2.status.code(), Some(0));
    let parsed2: Value = serde_json::from_slice(&passwd_out2.stdout).unwrap();
    assert_eq!(
        parsed2["data"]["rotated_repos"],
        serde_json::json!(["personal", "work"])
    );
}

#[test]
fn test_e2e_ancestor_dotler_toml_detection_and_vault_init_with_encrypt_rule() {
    let sandbox = E2eSandbox::new();

    // 1. Initialize repository
    let init_out = sandbox.cmd().args(["init", "--json"]).output().unwrap();
    assert_eq!(init_out.status.code(), Some(0));

    // 2. Write dotler.toml with `enc` BEFORE `dotler vault init`
    let toml_with_enc = r#"[shell]
os-nux = "~"
os-mac = "~"
os-win = "~"
files = """
secret.txt enc
"""
"#;
    fs::write(sandbox.repo_dir.join("dotler.toml"), toml_with_enc).unwrap();
    fs::write(sandbox.home_dir.join("secret.txt"), "top-secret\n").unwrap();

    // 3. Running `dotler import` before `dotler vault init` must fail with code 2 and hint 'dotler vault init'
    let subdir = sandbox.repo_dir.join("shell").join("nested");
    fs::create_dir_all(&subdir).unwrap();

    let import_before_vault = sandbox
        .cmd()
        .current_dir(&subdir)
        .args(["import", "--json"])
        .output()
        .unwrap();
    assert_eq!(import_before_vault.status.code(), Some(2));
    let err_json: Value = serde_json::from_slice(&import_before_vault.stdout).unwrap();
    assert!(
        err_json["hint"]
            .as_str()
            .unwrap_or_default()
            .contains("dotler vault init"),
        "hint must instruct user to run 'dotler vault init': {err_json}"
    );

    // 4. Running `dotler vault init` from nested subdirectory must detect ancestor dotler.toml
    //    AND succeed even though `encrypt` rule is already in dotler.toml!
    let mut vault_child = sandbox
        .cmd()
        .current_dir(&subdir)
        .args(["vault", "init", "--password-stdin", "--json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(mut stdin) = vault_child.stdin.take() {
        writeln!(stdin, "ancestor_vault_pass_123").unwrap();
    }
    let vault_out = vault_child.wait_with_output().unwrap();
    assert_eq!(
        vault_out.status.code(),
        Some(0),
        "vault init must succeed when encrypt rule is already present: {}",
        String::from_utf8_lossy(&vault_out.stdout)
    );

    // 5. Running `dotler import` from nested subdirectory now succeeds using ancestor dotler.toml
    let import_after = sandbox
        .cmd()
        .env("DOTLER_PASSPHRASE", "ancestor_vault_pass_123")
        .current_dir(&subdir)
        .args(["import", "--json"])
        .output()
        .unwrap();
    assert_eq!(import_after.status.code(), Some(0));
    assert!(
        sandbox
            .repo_dir
            .join("shell")
            .join("secret.txt.enc")
            .is_file()
    );
}

#[test]
fn test_e2e_vault_hint_and_use_keyring_optout() {
    let sandbox = E2eSandbox::new();

    // 1. Initialize repo and set `use_keyring = false` in local config.toml
    let init_out = sandbox.cmd().args(["init", "--json"]).output().unwrap();
    assert_eq!(init_out.status.code(), Some(0));

    let config_toml_path = sandbox.dotler_dir.join("config.toml");
    let config_raw = fs::read_to_string(&config_toml_path).unwrap();
    assert!(config_raw.contains(
        "# Priority-ordered device profile names for path matching\ndefault_devices = [\"default\"]"
    ));
    assert!(
        config_raw
            .contains("# Default repository label used when --repo is omitted\ndefault_repo = ")
    );
    assert!(
        config_raw
            .contains("# Store and retrieve vault passphrases via OS keyring\nuse_keyring = true")
    );
    assert!(
        config_raw.contains("# Registered dotfile repositories (<label> = \"~/path\")\n[repos]")
    );
    let updated_config = config_raw.replace("use_keyring = true", "use_keyring = false");
    fs::write(&config_toml_path, updated_config).unwrap();

    // 2. Initialize vault with `--hint`
    let mut vault_init = sandbox
        .cmd()
        .args([
            "vault",
            "init",
            "--hint",
            "first pet name",
            "--password-stdin",
            "--json",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(mut stdin) = vault_init.stdin.take() {
        writeln!(stdin, "pass_init_111").unwrap();
    }
    let vault_init_out = vault_init.wait_with_output().unwrap();
    assert_eq!(vault_init_out.status.code(), Some(0));
    let init_json: Value = serde_json::from_slice(&vault_init_out.stdout).unwrap();
    let mnemonic = init_json["data"]["mnemonic"].as_str().unwrap().to_string();

    let dotler_toml = fs::read_to_string(sandbox.repo_dir.join("dotler.toml")).unwrap();
    assert!(
        dotler_toml.contains("vault_hint = \"first pet name\""),
        "dotler.toml should contain initial vault_hint: {dotler_toml}"
    );
    let banner_end = dotler_toml
        .find("# ──────────────────────────────────────────────────────────────────")
        .unwrap();
    let vault_id_pos = dotler_toml.find("vault_id = ").unwrap();
    let bash_comment_pos = dotler_toml.find("# [bash]").unwrap();
    assert!(
        banner_end < vault_id_pos && vault_id_pos < bash_comment_pos,
        "vault root keys must be inserted right below header comment banner and above group comments: {dotler_toml}"
    );

    // 3. Rotate passphrase with `--hint` updated
    let mut passwd_child = sandbox
        .cmd()
        .env("DOTLER_PASSPHRASE", "pass_init_111")
        .args([
            "vault",
            "passwd",
            "--hint",
            "second pet name",
            "--password-stdin",
            "--json",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(mut stdin) = passwd_child.stdin.take() {
        writeln!(stdin, "pass_rot_222").unwrap();
    }
    let passwd_out = passwd_child.wait_with_output().unwrap();
    assert_eq!(passwd_out.status.code(), Some(0));

    let dotler_toml_after_passwd =
        fs::read_to_string(sandbox.repo_dir.join("dotler.toml")).unwrap();
    assert!(
        dotler_toml_after_passwd.contains("vault_hint = \"second pet name\""),
        "dotler.toml should contain updated vault_hint: {dotler_toml_after_passwd}"
    );

    // 4. Recover vault with `--hint` updated
    let mut recover_child = sandbox
        .cmd()
        .args([
            "vault",
            "recover",
            "--mnemonic",
            &mnemonic,
            "--hint",
            "recovered hint",
            "--password-stdin",
            "--json",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(mut stdin) = recover_child.stdin.take() {
        writeln!(stdin, "pass_rec_333").unwrap();
    }
    let recover_out = recover_child.wait_with_output().unwrap();
    assert_eq!(recover_out.status.code(), Some(0));

    let dotler_toml_after_recover =
        fs::read_to_string(sandbox.repo_dir.join("dotler.toml")).unwrap();
    assert!(
        dotler_toml_after_recover.contains("vault_hint = \"recovered hint\""),
        "dotler.toml should contain recovered vault_hint: {dotler_toml_after_recover}"
    );

    // Ensure local config still has use_keyring = false
    let final_local_cfg = fs::read_to_string(&config_toml_path).unwrap();
    assert!(final_local_cfg.contains("use_keyring = false"));
}
