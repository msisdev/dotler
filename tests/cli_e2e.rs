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
path = "~"
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
        .args(["tidy", "--rm", "--keep"])
        .output()
        .unwrap();
    assert_eq!(
        code2_out.status.code(),
        Some(2),
        "Conflicting flags --rm and --keep must exit with code 2"
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
os-linux = "~"
os-macos = "~"
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
    let imp_out = sandbox.cmd().arg("import").output().unwrap();
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
path = "~"
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
    let out_tidy = sandbox.cmd().args(["tidy", "--keep"]).output().unwrap();
    assert_eq!(out_tidy.status.code(), Some(0), "tidy must succeed");

    // 7. key set & del
    let mut key_child = Command::new(env!("CARGO_BIN_EXE_dotler"))
        .env("HOME", &sandbox.home_dir)
        .current_dir(&sandbox.repo_dir)
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
    let mut vault_child = Command::new(env!("CARGO_BIN_EXE_dotler"))
        .env("HOME", &sandbox.home_dir)
        .current_dir(&sandbox.repo_dir)
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
        .args(["git", "clone", &bare_url, "shell"])
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

    let mut vault_child = Command::new(env!("CARGO_BIN_EXE_dotler"))
        .env("HOME", &sandbox.home_dir)
        .current_dir(&sandbox.repo_dir)
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
os-linux = "~"
os-macos = "~"
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
os-linux = "~/.config/app_a"
os-macos = "~/.config/app_a"
os-windows = "~/.config/app_a"
files = "*"

[grp_b]
os-linux = "~/.config/app_b"
os-macos = "~/.config/app_b"
os-windows = "~/.config/app_b"
files = "*"

[grp_c]
os-linux = "~/.config/app_c"
os-macos = "~/.config/app_c"
os-windows = "~/.config/app_c"
files = "*"
"#;
    fs::write(sandbox.repo_dir.join("dotler.toml"), toml_v1).unwrap();

    let imp_out = sandbox.cmd().arg("import").output().unwrap();
    assert_eq!(imp_out.status.code(), Some(0));

    // Exclude all three files so each becomes an orphan in its respective group
    let toml_v2 = r#"[grp_a]
os-linux = "~/.config/app_a"
os-macos = "~/.config/app_a"
os-windows = "~/.config/app_a"
files = "!*"

[grp_b]
os-linux = "~/.config/app_b"
os-macos = "~/.config/app_b"
os-windows = "~/.config/app_b"
files = "!*"

[grp_c]
os-linux = "~/.config/app_c"
os-macos = "~/.config/app_c"
os-windows = "~/.config/app_c"
files = "!*"
"#;
    fs::write(sandbox.repo_dir.join("dotler.toml"), toml_v2).unwrap();

    // Run `dotler tidy grp_a grp_b` with NO --rm/--keep flag (must default to --keep and filter both groups)
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
        "Both grp_a and grp_b orphans must be untracked with --keep default"
    );
    assert_eq!(removed.len(), 0);

    // OS files must remain intact under default --keep
    assert!(dir_a.join("a.conf").is_file());
    assert!(dir_b.join("b.conf").is_file());
    assert!(dir_c.join("c.conf").is_file());

    // grp_c was NOT passed to tidy, so running tidy grp_c --rm now must still find and delete c.conf
    let tidy_c = sandbox
        .cmd()
        .args(["tidy", "grp_c", "--rm", "--json"])
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
