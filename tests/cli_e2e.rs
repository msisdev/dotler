//! End-to-End integration tests for the Dotler CLI interface:
//! 12 subcommands, JSON envelope output invariants, deterministic exit codes (0..4),
//! dry-run zero-mutation guarantee, and flag conflict validation.

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use serde_json::Value;
use tempfile::TempDir;

struct E2eSandbox {
    _root: TempDir,
    home_dir: PathBuf,
    dotler_dir: PathBuf,
    repo_dir: PathBuf,
    bare_git_dir: PathBuf,
}

impl E2eSandbox {
    fn new() -> Self {
        let root =
            tempfile::tempdir().expect("Failed to create temporary directory for E2E sandbox");
        let root_path = root.path();
        let home_dir = root_path.join("home");
        let dotler_dir = home_dir.join(".config").join("dotler");
        let repo_dir = home_dir.join("dotfiles");
        let bare_git_dir = root_path.join("bare_repo.git");

        fs::create_dir_all(&dotler_dir).expect("Failed to create ~/.config/dotler");
        fs::create_dir_all(&repo_dir).expect("Failed to create dotfiles repository");

        // Seed a working Git repo with a dotler.toml, then clone --bare
        let worktree = root_path.join("worktree");
        fs::create_dir_all(&worktree).unwrap();
        Command::new("git")
            .args(["init", worktree.to_str().unwrap()])
            .status()
            .unwrap();

        let seed_toml = r#"[shell]
os-nux = "~"
os-mac = "~"
os-win = "~"
os-bsd = "~"
files = """
*
"""
"#;
        fs::write(worktree.join("dotler.toml"), seed_toml).unwrap();
        fs::create_dir_all(worktree.join("shell")).unwrap();
        fs::write(
            worktree.join("shell").join("sample.sh"),
            "#!/bin/sh\necho ok\n",
        )
        .unwrap();

        Command::new("git")
            .args([
                "-C",
                worktree.to_str().unwrap(),
                "config",
                "user.name",
                "Tester",
            ])
            .status()
            .unwrap();
        Command::new("git")
            .args([
                "-C",
                worktree.to_str().unwrap(),
                "config",
                "user.email",
                "test@example.com",
            ])
            .status()
            .unwrap();
        Command::new("git")
            .args(["-C", worktree.to_str().unwrap(), "add", "."])
            .status()
            .unwrap();
        Command::new("git")
            .args([
                "-C",
                worktree.to_str().unwrap(),
                "commit",
                "-m",
                "Seed remote repo",
            ])
            .status()
            .unwrap();
        Command::new("git")
            .args([
                "clone",
                "--bare",
                worktree.to_str().unwrap(),
                bare_git_dir.to_str().unwrap(),
            ])
            .status()
            .unwrap();

        Self {
            _root: root,
            home_dir,
            dotler_dir,
            repo_dir,
            bare_git_dir,
        }
    }

    fn cmd(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_dotler"));
        cmd.env("HOME", &self.home_dir)
            .env("DOTLER_MOCK_KEYRING", "1")
            .env_remove("DOTLER_PASSPHRASE")
            .current_dir(&self.repo_dir)
            .stdin(Stdio::null());
        cmd
    }

    fn _cmd_with_passphrase(&self, pass: &str) -> Command {
        let mut cmd = self.cmd();
        cmd.env("DOTLER_PASSPHRASE", pass);
        cmd
    }
}

#[test]
fn test_e2e_json_output_envelope_invariant() {
    let sandbox = E2eSandbox::new();

    // 1. Success output must be pure JsonEnvelope with zero ANSI escape codes
    let out = sandbox
        .cmd()
        .args(["init", "--label", "work", "--json"])
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert!(
        !stdout.contains("\x1b["),
        "Zero-ANSI Invariant: stdout must not contain ANSI escape codes: {}",
        stdout
    );

    let parsed: Value =
        serde_json::from_str(&stdout).expect("Stdout must be parseable as valid JSON envelope");

    assert_eq!(parsed["ok"], true);
    assert_eq!(parsed["command"], "init");
    assert!(parsed.get("data").is_some());

    // 2. Error output under --json must be pure JsonErrorPayload
    let err_out = sandbox
        .cmd()
        .args(["check", "--group", "non_existent_group", "--json"])
        .output()
        .unwrap();

    assert_ne!(err_out.status.code(), Some(0));
    let err_stdout = String::from_utf8_lossy(&err_out.stdout);

    assert!(
        !err_stdout.contains("\x1b["),
        "Zero-ANSI Invariant on error: stdout must not contain ANSI codes: {}",
        err_stdout
    );

    let err_parsed: Value = serde_json::from_str(&err_stdout)
        .expect("Stdout must be parseable as valid JsonErrorPayload");

    assert_eq!(err_parsed["ok"], false);
    assert!(err_parsed["error_code"].is_string());
    assert!(err_parsed["message"].is_string());
    assert!(err_parsed["hint"].is_string());
}

#[test]
fn test_e2e_exit_codes_0_to_4_comprehensive() {
    let sandbox = E2eSandbox::new();

    // Setup base repo
    let init_out = sandbox
        .cmd()
        .args(["init", "--label", "main_repo"])
        .output()
        .unwrap();
    assert_eq!(init_out.status.code(), Some(0));

    // Code 0 (EXIT_SUCCESS): Valid check command
    let code0_out = sandbox.cmd().arg("check").output().unwrap();
    assert_eq!(
        code0_out.status.code(),
        Some(0),
        "Valid check must exit with 0"
    );

    // Code 2 (EXIT_CONFIG_OR_ARGS_ERROR): Invalid CLI arguments or syntax error
    let code2_out = sandbox
        .cmd()
        .args(["tidy", "--unknown-flag"])
        .output()
        .unwrap();
    assert_eq!(
        code2_out.status.code(),
        Some(2),
        "Invalid CLI flag must exit with code 2"
    );

    // Code 3 (EXIT_SECURITY_BLOCKED): Path traversal attempt in dotler.toml
    let evil_toml = r#"[evil]
path = "~/../../etc"
files = "*"
"#;
    fs::write(sandbox.repo_dir.join("dotler.toml"), evil_toml).unwrap();
    let code3_out = sandbox.cmd().arg("check").output().unwrap();
    assert_eq!(
        code3_out.status.code(),
        Some(3),
        "Path traversal security violation must exit with code 3"
    );

    // Restore clean dotler.toml
    let clean_toml = r#"[shell]
os-nux = "~"
os-mac = "~"
files = """
*
"""
"#;
    fs::write(sandbox.repo_dir.join("dotler.toml"), clean_toml).unwrap();

    // Code 1 (EXIT_SYNC_CONFLICT): Local edit conflict during export without --force
    let local_file = sandbox.home_dir.join("shell_file.txt");
    fs::write(&local_file, "original content\n").unwrap();
    fs::create_dir_all(sandbox.repo_dir.join("shell")).unwrap();
    fs::write(
        sandbox.repo_dir.join("shell").join("shell_file.txt"),
        "repo content\n",
    )
    .unwrap();

    // Import first to establish base state
    let imp_out = sandbox.cmd().args(["import", "-y"]).output().unwrap();
    assert_eq!(imp_out.status.code(), Some(0));

    // Modify local file on OS
    fs::write(&local_file, "modified locally on OS\n").unwrap();
    // Also modify in repo so hashes conflict
    fs::write(
        sandbox.repo_dir.join("shell").join("shell_file.txt"),
        "newer repo content\n",
    )
    .unwrap();

    // Export without --force must encounter local conflict and exit with code 1
    let code1_out = sandbox.cmd().arg("export").output().unwrap();
    assert_eq!(
        code1_out.status.code(),
        Some(1),
        "Export with local conflict without --force must exit with code 1"
    );

    // Code 4 (EXIT_AUTH_OR_LOCK_ERROR): Lock timeout
    // Hold lock externally
    let lock_path = sandbox.dotler_dir.join("dotler.lock");
    let lock = dotler::config::state::DotlerLock::new(lock_path.clone());
    let lock_guard = lock
        .acquire(
            std::time::Duration::from_millis(100),
            std::time::Duration::from_millis(10),
        )
        .unwrap();

    // Running a command while lock is held must timeout and exit with code 4
    let code4_out = sandbox.cmd().arg("status").output().unwrap();
    assert_eq!(
        code4_out.status.code(),
        Some(4),
        "Lock contention timeout must exit with code 4"
    );

    drop(lock_guard);
}

#[test]
fn test_e2e_dry_run_zero_mutation_guarantee() {
    let sandbox = E2eSandbox::new();

    let init_out = sandbox
        .cmd()
        .args(["init", "--label", "primary"])
        .output()
        .unwrap();
    assert_eq!(init_out.status.code(), Some(0));

    let toml_content = r#"[shell]
os-nux = "~"
os-mac = "~"
os-win = "~"
os-bsd = "~"
files = "*"
"#;
    fs::write(sandbox.repo_dir.join("dotler.toml"), toml_content).unwrap();

    let target_file = sandbox.home_dir.join("dry_test.txt");
    fs::write(&target_file, "hello dry run\n").unwrap();

    // Snapshot repo directory before import --dry-run
    let repo_entries_before: Vec<_> = fs::read_dir(&sandbox.repo_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();

    // Run import --dry-run
    let out = sandbox
        .cmd()
        .args(["import", "--dry-run"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));

    let repo_entries_after: Vec<_> = fs::read_dir(&sandbox.repo_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(
        repo_entries_before, repo_entries_after,
        "import --dry-run must NOT mutate the repository directory"
    );

    // Run export --dry-run
    let export_out = sandbox
        .cmd()
        .args(["export", "--dry-run"])
        .output()
        .unwrap();
    assert_eq!(export_out.status.code(), Some(0));

    // Verify target file was not modified
    let content = fs::read_to_string(&target_file).unwrap();
    assert_eq!(content, "hello dry run\n");
}

#[test]
fn test_e2e_all_12_subcommands_clean_execution() {
    let sandbox = E2eSandbox::new();

    // 1. init
    let out_init = sandbox
        .cmd()
        .args(["init", "--label", "main"])
        .output()
        .unwrap();
    assert_eq!(out_init.status.code(), Some(0), "init must succeed");

    // 2. check
    let out_check = sandbox.cmd().arg("check").output().unwrap();
    assert_eq!(out_check.status.code(), Some(0), "check must succeed");

    // 3. status
    let out_status = sandbox.cmd().arg("status").output().unwrap();
    assert_eq!(out_status.status.code(), Some(0), "status must succeed");

    // 4. import
    let out_import = sandbox.cmd().arg("import").output().unwrap();
    assert_eq!(out_import.status.code(), Some(0), "import must succeed");

    // 5. export
    let out_export = sandbox.cmd().arg("export").output().unwrap();
    assert_eq!(out_export.status.code(), Some(0), "export must succeed");

    // 6. tidy
    let out_tidy = sandbox.cmd().arg("tidy").output().unwrap();
    assert_eq!(out_tidy.status.code(), Some(0), "tidy must succeed");

    // 7. key set & del
    let mut key_child = sandbox
        .cmd()
        .args(["key", "set", "--password-stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(mut stdin) = key_child.stdin.take() {
        writeln!(stdin, "master_password_passphrase_12345").unwrap();
    }
    let key_out = key_child.wait_with_output().unwrap();
    assert_eq!(key_out.status.code(), Some(0), "key set must succeed");

    let out_key_del = sandbox.cmd().args(["key", "del"]).output().unwrap();
    assert_eq!(out_key_del.status.code(), Some(0), "key del must succeed");

    // 8. vault init, passwd, recover
    let mut vault_child = sandbox
        .cmd()
        .args(["vault", "init", "--password-stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(mut stdin) = vault_child.stdin.take() {
        writeln!(stdin, "vault_master_pass_123").unwrap();
    }
    let vault_init_out = vault_child.wait_with_output().unwrap();
    assert_eq!(
        vault_init_out.status.code(),
        Some(0),
        "vault init must succeed"
    );

    // 9. ai
    let out_ai = sandbox.cmd().arg("ai").output().unwrap();
    assert_eq!(out_ai.status.code(), Some(0), "ai must succeed");

    // 10. update
    let out_update = sandbox.cmd().args(["update", "--check"]).output().unwrap();
    assert_eq!(
        out_update.status.code(),
        Some(0),
        "update --check must succeed"
    );

    // 11. git ls
    let bare_url = format!("file://{}", sandbox.bare_git_dir.display());
    let out_git_ls = sandbox
        .cmd()
        .args(["git", "ls", &bare_url])
        .output()
        .unwrap();
    assert_eq!(out_git_ls.status.code(), Some(0), "git ls must succeed");

    // 12. git clone
    let out_git_clone = sandbox
        .cmd()
        .args(["git", "clone", &bare_url, "shell", "-y"])
        .current_dir(&sandbox.home_dir)
        .output()
        .unwrap();
    assert_eq!(
        out_git_clone.status.code(),
        Some(0),
        "git clone must succeed"
    );
}

#[test]
fn test_e2e_non_interactive_no_hang() {
    let sandbox = E2eSandbox::new();

    // Spawning a command with stdin closed (null) must not hang
    let output = sandbox
        .cmd()
        .args(["init", "--label", "test"])
        .output()
        .expect("Command must finish without hanging");

    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn test_e2e_encryption_mismatch_export_and_check_exit_code_1() {
    let sandbox = E2eSandbox::new();

    // 1. Initialize repo and vault
    let init_out = sandbox
        .cmd()
        .args(["init", "--label", "main"])
        .output()
        .unwrap();
    assert_eq!(init_out.status.code(), Some(0));

    let mut vault_child = sandbox
        .cmd()
        .args(["vault", "init", "--password-stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(mut stdin) = vault_child.stdin.take() {
        writeln!(stdin, "secretpass123").unwrap();
    }
    let vault_out = vault_child.wait_with_output().unwrap();
    assert_eq!(vault_out.status.code(), Some(0));

    // 2. Configure a group with encrypted rule
    let toml_content = r#"[sec]
os-nux = "~"
os-mac = "~"
files = "sec.txt encrypt"
"#;
    let mut manifest = fs::read_to_string(sandbox.repo_dir.join("dotler.toml")).unwrap();
    manifest.push_str(&format!("\n{toml_content}"));
    fs::write(sandbox.repo_dir.join("dotler.toml"), manifest).unwrap();

    // 3. Create plaintext file in repo (mismatch: should be sec.txt.enc)
    fs::create_dir_all(sandbox.repo_dir.join("sec")).unwrap();
    fs::write(
        sandbox.repo_dir.join("sec").join("sec.txt"),
        "plaintext content\n",
    )
    .unwrap();
    fs::write(sandbox.home_dir.join("sec.txt"), "local content\n").unwrap();

    // 4. Test dotler check --json
    let check_out = sandbox.cmd().args(["check", "--json"]).output().unwrap();
    assert_eq!(
        check_out.status.code(),
        Some(1),
        "check must exit with code 1 on encryption mismatch"
    );
    let check_stdout = String::from_utf8_lossy(&check_out.stdout);
    assert!(
        !check_stdout.contains("\x1b["),
        "Zero-ANSI Invariant: {}",
        check_stdout
    );
    let check_err: Value = serde_json::from_str(&check_stdout).expect("Valid JSON error payload");
    assert_eq!(check_err["ok"], false);
    assert_eq!(check_err["error_code"], "ENCRYPTION_MISMATCH");
    assert!(check_err["hint"].as_str().unwrap().contains("dotler tidy"));

    // 5. Test dotler export --json (with passphrase set)
    let export_out = sandbox
        .cmd()
        .env("DOTLER_PASSPHRASE", "secretpass123")
        .args(["export", "--json"])
        .output()
        .unwrap();
    assert_eq!(
        export_out.status.code(),
        Some(1),
        "export must exit with code 1 on encryption mismatch"
    );
    let export_stdout = String::from_utf8_lossy(&export_out.stdout);
    assert!(
        !export_stdout.contains("\x1b["),
        "Zero-ANSI Invariant: {}",
        export_stdout
    );
    let export_err: Value = serde_json::from_str(&export_stdout).expect("Valid JSON error payload");
    assert_eq!(export_err["ok"], false);
    assert_eq!(export_err["error_code"], "ENCRYPTION_MISMATCH");
    assert!(export_err["hint"].as_str().unwrap().contains("dotler tidy"));

    // 6. Test human-readable non-json output returns exit code 1
    let export_human_out = sandbox
        .cmd()
        .env("DOTLER_PASSPHRASE", "secretpass123")
        .arg("export")
        .output()
        .unwrap();
    assert_eq!(
        export_human_out.status.code(),
        Some(1),
        "export must exit with code 1 on encryption mismatch without --json"
    );
    let stderr = String::from_utf8_lossy(&export_human_out.stderr);
    assert!(
        stderr.contains("Encryption mismatch") || stderr.contains("conflicts with encryption rule")
    );
}

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

    // 2. Write dotler.toml with `encrypt` BEFORE `dotler vault init`
    let toml_with_enc = r#"[shell]
os-nux = "~"
os-mac = "~"
os-win = "~"
files = """
secret.txt encrypt
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
    let updated_config = format!("use_keyring = false\n{config_raw}");
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
        dotler_toml.contains("hint = \"first pet name\""),
        "dotler.toml should contain initial hint: {dotler_toml}"
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
        dotler_toml_after_passwd.contains("hint = \"second pet name\""),
        "dotler.toml should contain updated hint: {dotler_toml_after_passwd}"
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
        dotler_toml_after_recover.contains("hint = \"recovered hint\""),
        "dotler.toml should contain recovered hint: {dotler_toml_after_recover}"
    );

    // Ensure local config still has use_keyring = false
    let final_local_cfg = fs::read_to_string(&config_toml_path).unwrap();
    assert!(final_local_cfg.contains("use_keyring = false"));
}

#[test]
fn test_e2e_non_json_inline_formats_emoji_rules_and_colored_labels() {
    let sandbox = E2eSandbox::new();

    // 1. init (non-JSON): no sun emoji, colored Hint: label
    let out_init = sandbox
        .cmd()
        .args(["init", "--label", "main"])
        .output()
        .unwrap();
    assert_eq!(out_init.status.code(), Some(0));
    let init_stdout = String::from_utf8_lossy(&out_init.stdout);
    assert!(
        init_stdout.starts_with("Init done. ('main' at '"),
        "unexpected init stdout: {init_stdout}"
    );
    assert!(!init_stdout.contains("☀️"));
    assert!(!init_stdout.trim_start().starts_with('{'));
    assert!(
        init_stdout.contains("\x1b[38;5;12m\x1b[1mHint:\x1b[0m"),
        "Init Hint: label must be styled in Info Blue + Bold: {init_stdout:?}"
    );

    // 2. check (non-JSON): `☀️ Config is ok. (0 groups)` on fresh init
    let out_check = sandbox.cmd().arg("check").output().unwrap();
    assert_eq!(out_check.status.code(), Some(0));
    let check_stdout = String::from_utf8_lossy(&out_check.stdout);
    assert_eq!(check_stdout.trim(), "☀️ Config is ok. (0 groups)");

    // 3. key set & key del (non-JSON): no raw JSON, no emoji
    let mut key_child = sandbox
        .cmd()
        .args(["key", "set", "--password-stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(mut stdin) = key_child.stdin.take() {
        writeln!(stdin, "master_password_passphrase_12345").unwrap();
    }
    let key_out = key_child.wait_with_output().unwrap();
    assert_eq!(key_out.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&key_out.stdout).trim(),
        "Key set done."
    );

    let out_key_del = sandbox.cmd().args(["key", "del"]).output().unwrap();
    assert_eq!(out_key_del.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&out_key_del.stdout).trim(),
        "Key delete done."
    );

    // 4. vault init, passwd, recover (non-JSON)
    let mut vault_child = sandbox
        .cmd()
        .args(["vault", "init", "--password-stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(mut stdin) = vault_child.stdin.take() {
        writeln!(stdin, "vault_pass_111").unwrap();
    }
    let vault_init_out = vault_child.wait_with_output().unwrap();
    assert_eq!(vault_init_out.status.code(), Some(0));
    let vault_init_stdout = String::from_utf8_lossy(&vault_init_out.stdout);
    let vault_init_lines: Vec<&str> = vault_init_stdout.lines().collect();
    assert_eq!(vault_init_lines.len(), 2, "stdout: {vault_init_stdout}");
    assert!(vault_init_lines[0].starts_with("Vault init done. (id: "));
    assert!(!vault_init_lines[0].contains("☀️"));
    assert!(vault_init_lines[1].starts_with("🔑 Recovery mnemonic: "));
    let mnemonic = vault_init_lines[1]
        .strip_prefix("🔑 Recovery mnemonic: ")
        .unwrap()
        .trim()
        .to_string();

    let mut passwd_child = sandbox
        .cmd()
        .env("DOTLER_PASSPHRASE", "vault_pass_111")
        .args(["vault", "passwd", "--password-stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(mut stdin) = passwd_child.stdin.take() {
        writeln!(stdin, "vault_pass_222").unwrap();
    }
    let passwd_out = passwd_child.wait_with_output().unwrap();
    assert_eq!(passwd_out.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&passwd_out.stdout).trim(),
        "☀️ Passphrase rotation done. (1 rotated, 0 skipped)"
    );

    let mut recover_child = sandbox
        .cmd()
        .args([
            "vault",
            "recover",
            "--mnemonic",
            &mnemonic,
            "--password-stdin",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(mut stdin) = recover_child.stdin.take() {
        writeln!(stdin, "vault_pass_333").unwrap();
    }
    let recover_out = recover_child.wait_with_output().unwrap();
    assert_eq!(recover_out.status.code(), Some(0));
    let recover_stdout = String::from_utf8_lossy(&recover_out.stdout);
    let recover_lines: Vec<&str> = recover_stdout.lines().collect();
    assert_eq!(recover_lines.len(), 2, "stdout: {recover_stdout}");
    assert!(recover_lines[0].starts_with("☀️ Vault recovery done. (id: "));
    assert!(recover_lines[1].starts_with("🔑 New recovery mnemonic: "));

    // 5. update --check (non-JSON): no raw JSON, no emoji
    let out_update = sandbox.cmd().args(["update", "--check"]).output().unwrap();
    assert_eq!(out_update.status.code(), Some(0));
    let update_stdout = String::from_utf8_lossy(&out_update.stdout);
    assert!(
        update_stdout
            .trim()
            .starts_with("Update check done. (v"),
        "unexpected update stdout: {update_stdout}"
    );
    assert!(update_stdout.trim().ends_with(", up to date)"));
    assert!(!update_stdout.contains("☀️"));

    // 6. import/export/tidy completion lines vs 0-update & --dry-run suppression
    let toml_content = r#"[shell]
os-nux = "~"
os-mac = "~"
os-win = "~"
files = "hello.txt"
"#;
    fs::write(sandbox.repo_dir.join("dotler.toml"), toml_content).unwrap();
    fs::write(sandbox.home_dir.join("hello.txt"), "hello world\n").unwrap();

    // --dry-run must NOT emit `☀️ Import done.`
    let dry_imp = sandbox
        .cmd()
        .args(["import", "--dry-run"])
        .output()
        .unwrap();
    assert_eq!(dry_imp.status.code(), Some(0));
    let dry_imp_stdout = String::from_utf8_lossy(&dry_imp.stdout);
    assert!(
        !dry_imp_stdout.contains("Import done."),
        "dry-run must not emit completion summary: {dry_imp_stdout}"
    );

    // Real import emits `☀️ Import done. (1 imported, 0 skipped)`
    let imp_out = sandbox.cmd().args(["import", "-y"]).output().unwrap();
    assert_eq!(imp_out.status.code(), Some(0));
    let imp_stdout = String::from_utf8_lossy(&imp_out.stdout);
    assert!(
        imp_stdout.contains("☀️ Import done. (1 imported, 0 skipped)"),
        "expected Import done summary, got: {imp_stdout}"
    );

    // Second import with 0 updates emits only `☀️ All files are ok.` and NOT `☀️ Import done.`
    let imp_noop = sandbox.cmd().args(["import", "-y"]).output().unwrap();
    assert_eq!(imp_noop.status.code(), Some(0));
    let imp_noop_stdout = String::from_utf8_lossy(&imp_noop.stdout);
    assert!(imp_noop_stdout.contains("☀️ All files are ok."));
    assert!(!imp_noop_stdout.contains("Import done."));

    // Modify repo file and run export -> emits `☀️ Export done. (1 exported, 0 skipped)`
    fs::write(
        sandbox.repo_dir.join("shell").join("hello.txt"),
        "updated from repo\n",
    )
    .unwrap();
    let exp_out = sandbox.cmd().args(["export", "-y"]).output().unwrap();
    assert_eq!(exp_out.status.code(), Some(0));
    let exp_stdout = String::from_utf8_lossy(&exp_out.stdout);
    assert!(
        exp_stdout.contains("☀️ Export done. (1 exported, 0 skipped)"),
        "expected Export done summary, got: {exp_stdout}"
    );

    // Error output in non-JSON mode colors `Error:` (Red 9 + Bold) and `Hint:` (Blue 12 + Bold)
    let err_out = sandbox
        .cmd()
        .args(["check", "--group", "nonexistent"])
        .output()
        .unwrap();
    assert_eq!(err_out.status.code(), Some(2));
    let err_stderr = String::from_utf8_lossy(&err_out.stderr);
    assert!(
        err_stderr.contains("\x1b[38;5;9m\x1b[1mError:\x1b[0m"),
        "stderr must contain styled Error: label: {err_stderr:?}"
    );
    assert!(
        err_stderr.contains("\x1b[38;5;12m\x1b[1mHint:\x1b[0m"),
        "stderr must contain styled Hint: label: {err_stderr:?}"
    );
}

