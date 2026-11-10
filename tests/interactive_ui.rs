//! Integration tests for interactive inline preview, confirmation prompt, and progress reporting
//! across the 6 mutating commands (`import`, `export`, `tidy`, `git clone`, `git install`, `git uninstall`).

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use tempfile::TempDir;

fn strip_ansi(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            if chars.peek() == Some(&'[') {
                chars.next();
                for ch in chars.by_ref() {
                    if ch.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

struct InteractiveSandbox {
    _root: TempDir,
    home_dir: PathBuf,
    repo_dir: PathBuf,
    bare_git_dir: PathBuf,
}

impl InteractiveSandbox {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("Failed to create temp sandbox");
        let root_path = root.path();
        let home_dir = root_path.join("home");
        let dotler_dir = home_dir.join(".config").join("dotler");
        let repo_dir = home_dir.join("dotfiles");
        let bare_git_dir = root_path.join("remote_repo.git");

        fs::create_dir_all(&dotler_dir).unwrap();
        fs::create_dir_all(&repo_dir).unwrap();

        let worktree = root_path.join("worktree");
        fs::create_dir_all(worktree.join("nvim")).unwrap();
        Command::new("git")
            .args(["init", worktree.to_str().unwrap()])
            .status()
            .unwrap();

        let remote_toml = r#"[nvim]
default = "~/.config/nvim"
files = "*"
"#;
        fs::write(worktree.join("dotler.toml"), remote_toml).unwrap();
        fs::write(
            worktree.join("nvim").join("init.lua"),
            "-- remote init.lua\n",
        )
        .unwrap();

        for args in [
            vec!["config", "user.name", "Tester"],
            vec!["config", "user.email", "test@example.com"],
            vec!["add", "."],
            vec!["commit", "-m", "Initial remote commit"],
        ] {
            Command::new("git")
                .arg("-C")
                .arg(&worktree)
                .args(args)
                .status()
                .unwrap();
        }
        Command::new("git")
            .args([
                "clone",
                "--bare",
                worktree.to_str().unwrap(),
                bare_git_dir.to_str().unwrap(),
            ])
            .status()
            .unwrap();

        let s = Self {
            _root: root,
            home_dir,
            repo_dir,
            bare_git_dir,
        };

        let init_out = s.cmd().args(["init", "--label", "main"]).output().unwrap();
        assert_eq!(init_out.status.code(), Some(0));

        s
    }

    fn cmd(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_dotler"));
        cmd.env("HOME", &self.home_dir)
            .env("DOTLER_MOCK_KEYRING", "1")
            .env_remove("DOTLER_PASSPHRASE")
            .env_remove("DOTLER_TEST_CONFIRM_INPUT")
            .current_dir(&self.repo_dir)
            .stdin(Stdio::null());
        cmd
    }
}

#[test]
fn test_overwrite_focused_preview_and_summary_footer_counts() {
    let sandbox = InteractiveSandbox::new();

    let nvim_os = sandbox.home_dir.join(".config").join("nvim");
    let bash_os = sandbox.home_dir.join(".config").join("bash");
    fs::create_dir_all(&nvim_os).unwrap();
    fs::create_dir_all(&bash_os).unwrap();

    let toml_str = r#"[nvim]
default = "~/.config/nvim"
files = "*"

[bash]
default = "~/.config/bash"
files = "*"
"#;
    fs::write(sandbox.repo_dir.join("dotler.toml"), toml_str).unwrap();

    // Seed 1 existing file in repo that will be overwritten, and 1 file that is identical (okay)
    fs::create_dir_all(sandbox.repo_dir.join("nvim")).unwrap();
    fs::write(
        sandbox.repo_dir.join("nvim").join("init.lua"),
        "old-repo-content\n",
    )
    .unwrap();
    fs::write(
        sandbox.repo_dir.join("nvim").join("unchanged.lua"),
        "same-content\n",
    )
    .unwrap();

    // OS side: 1 overwrite (init.lua), 1 okay (unchanged.lua), and 3 creates across nvim & bash
    fs::write(nvim_os.join("init.lua"), "new-os-content\n").unwrap();
    fs::write(nvim_os.join("unchanged.lua"), "same-content\n").unwrap();
    fs::write(nvim_os.join("new1.lua"), "create-1\n").unwrap();
    fs::write(bash_os.join("new2.sh"), "create-2\n").unwrap();
    fs::write(bash_os.join("new3.sh"), "create-3\n").unwrap();

    // Default preview (--dry-run, view_all = false)
    let out = sandbox
        .cmd()
        .args(["import", "--dry-run"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));

    let plain = strip_ansi(&String::from_utf8_lossy(&out.stdout));
    // Overwrite group [nvim] and init.lua must be shown with 5-column arrow
    assert!(plain.contains("[nvim]"), "stdout:\n{plain}");
    assert!(plain.contains("init.lua"), "stdout:\n{plain}");
    assert!(plain.contains("───▸ ▐w▌"), "stdout:\n{plain}");

    // Group [bash] has only Create items, so its header and paths must be omitted in default mode
    assert!(!plain.contains("[bash]"), "stdout:\n{plain}");
    assert!(!plain.contains("new1.lua"), "stdout:\n{plain}");
    assert!(!plain.contains("new2.sh"), "stdout:\n{plain}");
    assert!(!plain.contains("unchanged.lua"), "stdout:\n{plain}");

    // Summary footer section must include the <Summary> header and flush-left counts
    assert!(
        plain.contains("<Summary>\n▐c▌create 3   ▐w▌overwrite 1   ▐d▌delete 0   ▐o▌okay 1"),
        "stdout:\n{plain}"
    );
    assert!(!plain.contains("╭"), "stdout:\n{plain}");
    assert!(!plain.contains("╰"), "stdout:\n{plain}");

    // With -a (--all), all groups and files must be displayed
    let out_all = sandbox
        .cmd()
        .args(["import", "-a", "--dry-run"])
        .output()
        .unwrap();
    assert_eq!(out_all.status.code(), Some(0));
    let plain_all = strip_ansi(&String::from_utf8_lossy(&out_all.stdout));
    assert!(plain_all.contains("[nvim]"));
    assert!(plain_all.contains("[bash]"));
    assert!(plain_all.contains("new1.lua"));
    assert!(plain_all.contains("new2.sh"));
    assert!(plain_all.contains("unchanged.lua"));
}

#[test]
fn test_create_only_summary_footer_and_yes_confirmation_or_cancel() {
    let sandbox = InteractiveSandbox::new();

    let nvim_os = sandbox.home_dir.join(".config").join("nvim");
    fs::create_dir_all(&nvim_os).unwrap();
    fs::write(nvim_os.join("first.lua"), "one\n").unwrap();
    fs::write(nvim_os.join("second.lua"), "two\n").unwrap();

    let toml_str = r#"[nvim]
default = "~/.config/nvim"
files = "*"
"#;
    fs::write(sandbox.repo_dir.join("dotler.toml"), toml_str).unwrap();

    // 1. Empty Enter ("") cancels when only creates exist (create 2, overwrite 0)
    let cancel_out = sandbox
        .cmd()
        .env("DOTLER_TEST_CONFIRM_INPUT", "")
        .arg("import")
        .output()
        .unwrap();
    assert_eq!(cancel_out.status.code(), Some(0));
    let cancel_plain = strip_ansi(&String::from_utf8_lossy(&cancel_out.stdout));
    assert!(!cancel_plain.contains("[nvim]"), "stdout:\n{cancel_plain}");
    assert!(!cancel_plain.contains("first.lua"));
    assert!(cancel_plain.contains("<Summary>\n▐c▌create 2"));
    assert!(cancel_plain.contains("▐w▌overwrite 0"));
    assert!(cancel_plain.contains("Do you want to proceed?"));
    assert!(!sandbox.repo_dir.join("nvim").join("first.lua").exists());

    // 2. Partial input ("ye") also cancels with 0 mutations
    let typo_out = sandbox
        .cmd()
        .env("DOTLER_TEST_CONFIRM_INPUT", "ye")
        .arg("import")
        .output()
        .unwrap();
    assert_eq!(typo_out.status.code(), Some(0));
    assert!(!sandbox.repo_dir.join("nvim").join("first.lua").exists());

    // 3. Exact "yes" proceeds and renders 2/2 Done
    let ok_out = sandbox
        .cmd()
        .env("DOTLER_TEST_CONFIRM_INPUT", "yes")
        .arg("import")
        .output()
        .unwrap();
    assert_eq!(ok_out.status.code(), Some(0));
    let ok_plain = strip_ansi(&String::from_utf8_lossy(&ok_out.stdout));
    assert!(ok_plain.contains("2/2  Done"), "stdout:\n{ok_plain}");
    assert!(sandbox.repo_dir.join("nvim").join("first.lua").is_file());
    assert!(sandbox.repo_dir.join("nvim").join("second.lua").is_file());

    // 4. Re-running when 0 updates exist prints "☀️ All files are ok." without prompting
    let noop_out = sandbox.cmd().arg("import").output().unwrap();
    assert_eq!(noop_out.status.code(), Some(0));
    let noop_plain = strip_ansi(&String::from_utf8_lossy(&noop_out.stdout));
    assert!(noop_plain.contains("☀️ All files are ok."));
    assert!(!noop_plain.contains("Do you want to proceed?"));
}

#[test]
fn test_non_tty_without_yes_or_json_blocks_deadlock_with_exit_code_2() {
    let sandbox = InteractiveSandbox::new();

    let nvim_os = sandbox.home_dir.join(".config").join("nvim");
    fs::create_dir_all(&nvim_os).unwrap();
    fs::create_dir_all(sandbox.repo_dir.join("nvim")).unwrap();
    fs::write(
        sandbox.repo_dir.join("nvim").join("init.lua"),
        "repo-version\n",
    )
    .unwrap();

    let toml_str = r#"[nvim]
default = "~/.config/nvim"
files = "*"
"#;
    fs::write(sandbox.repo_dir.join("dotler.toml"), toml_str).unwrap();

    // Non-TTY export without -y or --json must immediately exit with code 2 and actionable Hint
    let out = sandbox.cmd().arg("export").output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("-y"), "stderr:\n{stderr}");
    assert!(stderr.contains("--json"), "stderr:\n{stderr}");
    assert!(!nvim_os.join("init.lua").exists());
}

#[test]
fn test_yes_flag_and_progress_across_all_6_mutating_commands() {
    let sandbox = InteractiveSandbox::new();

    let nvim_os = sandbox.home_dir.join(".config").join("nvim");
    fs::create_dir_all(&nvim_os).unwrap();
    for i in 1..=4 {
        fs::write(nvim_os.join(format!("file{i}.lua")), format!("v{i}\n")).unwrap();
    }

    let toml_str = r#"[nvim]
default = "~/.config/nvim"
files = "*"
"#;
    fs::write(sandbox.repo_dir.join("dotler.toml"), toml_str).unwrap();

    // 1. import -y (4 files)
    let imp_out = sandbox.cmd().args(["import", "-y"]).output().unwrap();
    assert_eq!(imp_out.status.code(), Some(0));
    let imp_plain = strip_ansi(&String::from_utf8_lossy(&imp_out.stdout));
    assert!(imp_plain.contains("▐c▌create 4"));
    assert!(imp_plain.contains("4/4  Done"), "stdout:\n{imp_plain}");

    // 2. export -y -f after modifying repo file
    fs::write(
        sandbox.repo_dir.join("nvim").join("file1.lua"),
        "updated-in-repo\n",
    )
    .unwrap();
    let exp_out = sandbox
        .cmd()
        .args(["export", "-y", "-f"])
        .output()
        .unwrap();
    assert_eq!(exp_out.status.code(), Some(0));
    let exp_plain = strip_ansi(&String::from_utf8_lossy(&exp_out.stdout));
    assert!(exp_plain.contains("◂─── ▐o▌"), "stdout:\n{exp_plain}");
    assert!(exp_plain.contains("1/1  Done"), "stdout:\n{exp_plain}");
    assert_eq!(
        fs::read_to_string(nvim_os.join("file1.lua")).unwrap(),
        "updated-in-repo\n"
    );

    // 3. tidy -y --purge after excluding file4.lua
    let toml_exclude = r#"[nvim]
default = "~/.config/nvim"
files = """
*
!file4.lua
"""
"#;
    fs::write(sandbox.repo_dir.join("dotler.toml"), toml_exclude).unwrap();
    let tidy_out = sandbox
        .cmd()
        .args(["tidy", "-y", "--purge"])
        .output()
        .unwrap();
    assert_eq!(tidy_out.status.code(), Some(0));
    let tidy_plain = strip_ansi(&String::from_utf8_lossy(&tidy_out.stdout));
    assert!(tidy_plain.contains("▐d▌delete 2"), "stdout:\n{tidy_plain}");
    assert!(tidy_plain.contains("2/2  Done"), "stdout:\n{tidy_plain}");
    assert!(!nvim_os.join("file4.lua").exists());
    assert!(!sandbox.repo_dir.join("nvim").join("file4.lua").exists());

    // 4. git install -y & 5. git uninstall -y
    let bare_url = format!("file://{}", sandbox.bare_git_dir.display());
    let inst_out = sandbox
        .cmd()
        .args(["git", "install", &bare_url, "nvim", "-y"])
        .output()
        .unwrap();
    assert_eq!(inst_out.status.code(), Some(0));
    let inst_plain = strip_ansi(&String::from_utf8_lossy(&inst_out.stdout));
    assert!(inst_plain.contains("1/1  Done"), "stdout:\n{inst_plain}");
    assert!(nvim_os.join("init.lua").is_file());

    let uninst_out = sandbox
        .cmd()
        .args(["git", "uninstall", "nvim", "-y"])
        .output()
        .unwrap();
    assert_eq!(uninst_out.status.code(), Some(0));
    let uninst_plain = strip_ansi(&String::from_utf8_lossy(&uninst_out.stdout));
    assert!(uninst_plain.contains("1/1  Done"), "stdout:\n{uninst_plain}");
    assert!(!nvim_os.join("init.lua").exists());

    // 6. git clone -y
    let clone_out = sandbox
        .cmd()
        .current_dir(&sandbox.home_dir)
        .args(["git", "clone", &bare_url, "-y"])
        .output()
        .unwrap();
    assert_eq!(clone_out.status.code(), Some(0));
    let clone_plain = strip_ansi(&String::from_utf8_lossy(&clone_out.stdout));
    assert!(clone_plain.contains("1/1  Done"), "stdout:\n{clone_plain}");
    assert!(sandbox.home_dir.join("remote_repo").join("dotler.toml").is_file());
}

#[test]
fn test_git_clone_interactive_cancel_cleans_staging_and_group_alias_renames() {
    let sandbox = InteractiveSandbox::new();
    let bare_url = format!("file://{}", sandbox.bare_git_dir.display());
    let config_toml = sandbox.home_dir.join(".config").join("dotler").join("config.toml");
    let before_cfg = fs::read_to_string(&config_toml).unwrap();

    // 1. Cancel git clone ("no") -> staging directory must be cleaned up, destination absent, config.toml untouched
    let cancel_out = sandbox
        .cmd()
        .current_dir(&sandbox.home_dir)
        .env("DOTLER_TEST_CONFIRM_INPUT", "no")
        .args(["git", "clone", &bare_url])
        .output()
        .unwrap();
    assert_eq!(cancel_out.status.code(), Some(0));
    assert!(!sandbox.home_dir.join("remote_repo").exists());
    let after_cfg = fs::read_to_string(&config_toml).unwrap();
    assert_eq!(before_cfg, after_cfg);
    for entry in fs::read_dir(&sandbox.home_dir).unwrap() {
        let name = entry.unwrap().file_name().to_string_lossy().to_string();
        assert!(
            !name.starts_with(".dotler-tmp-clone-"),
            "leftover staging dir: {name}"
        );
    }

    // 2. Clone with group alias ("nvim:custom-nvim") and -y -> renames group directory and dotler.toml section
    let alias_out = sandbox
        .cmd()
        .current_dir(&sandbox.home_dir)
        .args(["git", "clone", &bare_url, "nvim:custom-nvim", "-y"])
        .output()
        .unwrap();
    assert_eq!(alias_out.status.code(), Some(0));
    let cloned_dir = sandbox.home_dir.join("remote_repo");
    assert!(cloned_dir.join("custom-nvim").join("init.lua").is_file());
    assert!(!cloned_dir.join("nvim").exists());
    let cloned_toml = fs::read_to_string(cloned_dir.join("dotler.toml")).unwrap();
    assert!(cloned_toml.contains("[custom-nvim]"), "toml:\n{cloned_toml}");
}

#[test]
fn test_unknown_group_returns_exit_code_2_for_status_import_and_export() {
    let sandbox = InteractiveSandbox::new();

    for args in [
        vec!["status", "--group", "nonexistent"],
        vec!["import", "nonexistent", "-y"],
        vec!["export", "nonexistent", "-y"],
    ] {
        let out = sandbox.cmd().args(&args).output().unwrap();
        assert_eq!(
            out.status.code(),
            Some(2),
            "expected exit code 2 for {args:?}, got {:?} (stderr: {})",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

