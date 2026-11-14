mod common;

use std::fs;
use std::io::Write;
use std::process::{Command, Stdio};

use common::E2eSandbox;
use serde_json::Value;

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
        update_stdout.trim().starts_with("Update check done. (v"),
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

#[test]
fn test_e2e_self_update_and_package_manager_delegation() {
    use sha2::{Digest, Sha256};

    let sandbox = E2eSandbox::new();
    let release_root = sandbox.home_dir.join("mock_releases");
    let v9_dir = release_root.join("v9.9.9");
    let staging_dir = sandbox.home_dir.join("staging_v9");
    fs::create_dir_all(&v9_dir).unwrap();
    fs::create_dir_all(&staging_dir).unwrap();

    fs::write(release_root.join("latest-version"), "v9.9.9\n").unwrap();

    let new_binary_payload = b"#!/bin/sh\necho dotler 9.9.9\n";
    fs::write(staging_dir.join("dotler"), new_binary_payload).unwrap();

    let target_info = dotler::cli::update::detect_release_target(
        std::env::consts::OS,
        std::env::consts::ARCH,
        Some("musl"),
    )
    .unwrap();

    let archive_path = v9_dir.join(&target_info.archive_name);
    let tar_status = Command::new("tar")
        .args([
            "-C",
            &staging_dir.to_string_lossy(),
            "-czf",
            &archive_path.to_string_lossy(),
            "dotler",
        ])
        .status()
        .unwrap();
    assert!(tar_status.success());

    let archive_bytes = fs::read(&archive_path).unwrap();
    let mut hasher = Sha256::new();
    hasher.update(&archive_bytes);
    let sha_hex: String = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let checksum_path = v9_dir.join(&target_info.checksum_name);
    fs::write(
        &checksum_path,
        format!("{sha_hex}  {}\n", target_info.archive_name),
    )
    .unwrap();

    let release_base_url = format!("file://{}", release_root.display());

    // 1. Package-manager path (Homebrew) delegates update without overwriting binary
    let brew_exe = sandbox
        .home_dir
        .join("opt/homebrew/Cellar/dotler/0.2.0/bin/dotler");
    fs::create_dir_all(brew_exe.parent().unwrap()).unwrap();
    fs::write(&brew_exe, b"original-homebrew-binary").unwrap();

    let brew_out = sandbox
        .cmd()
        .env("DOTLER_RELEASE_BASE_URL", &release_base_url)
        .env("DOTLER_UPDATE_EXE_PATH", &brew_exe)
        .args(["update", "--json"])
        .output()
        .unwrap();
    assert_eq!(brew_out.status.code(), Some(0));
    let brew_json: Value = serde_json::from_slice(&brew_out.stdout).unwrap();
    assert_eq!(
        brew_json["data"]["status"],
        Value::String("managed_by_package_manager".to_string())
    );
    assert_eq!(
        brew_json["data"]["install_method"],
        Value::String("homebrew-tap".to_string())
    );
    assert_eq!(
        brew_json["data"]["upgrade_command"],
        Value::String("brew upgrade msisdev/tap/dotler".to_string())
    );
    assert_eq!(fs::read(&brew_exe).unwrap(), b"original-homebrew-binary");

    // 1b. When release metadata includes the homebrew-core marker, homebrew-tap users are guided to migrate to official homebrew-core
    fs::write(
        release_root.join("latest.json"),
        r#"{"tag_name":"v9.9.9","body":"Release notes\n<!-- dotler:homebrew-core -->"}"#,
    )
    .unwrap();
    let brew_migrate_out = sandbox
        .cmd()
        .env("DOTLER_RELEASE_BASE_URL", &release_base_url)
        .env("DOTLER_UPDATE_EXE_PATH", &brew_exe)
        .args(["update"])
        .output()
        .unwrap();
    assert_eq!(brew_migrate_out.status.code(), Some(0));
    let brew_migrate_stdout = String::from_utf8_lossy(&brew_migrate_out.stdout);
    assert!(
        brew_migrate_stdout.contains(
            "brew uninstall msisdev/tap/dotler && brew untap msisdev/tap && brew install dotler"
        ),
        "stdout: {brew_migrate_stdout}"
    );
    assert!(
        brew_migrate_stdout.contains("official homebrew-core"),
        "stdout: {brew_migrate_stdout}"
    );
    let _ = fs::remove_file(release_root.join("latest.json"));

    // 2. Standalone binary path updates in-place after SHA-256 verification
    let standalone_exe = sandbox.home_dir.join(".local/bin/dotler");
    fs::create_dir_all(standalone_exe.parent().unwrap()).unwrap();
    fs::write(&standalone_exe, b"old-standalone-binary").unwrap();

    let check_out = sandbox
        .cmd()
        .env("DOTLER_RELEASE_BASE_URL", &release_base_url)
        .env("DOTLER_UPDATE_EXE_PATH", &standalone_exe)
        .args(["update", "--check"])
        .output()
        .unwrap();
    assert_eq!(check_out.status.code(), Some(0));
    let check_stdout = String::from_utf8_lossy(&check_out.stdout);
    assert!(
        check_stdout.contains("-> v9.9.9 available)"),
        "stdout: {check_stdout}"
    );
    assert_eq!(fs::read(&standalone_exe).unwrap(), b"old-standalone-binary");

    let update_out = sandbox
        .cmd()
        .env("DOTLER_RELEASE_BASE_URL", &release_base_url)
        .env("DOTLER_UPDATE_EXE_PATH", &standalone_exe)
        .env("DOTLER_LIBC", "musl")
        .args(["update", "-y"])
        .output()
        .unwrap();
    assert_eq!(
        update_out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&update_out.stderr)
    );
    let update_stdout = String::from_utf8_lossy(&update_out.stdout);
    assert!(
        update_stdout.contains("☀️ Update done. (v"),
        "stdout: {update_stdout}"
    );
    assert_eq!(fs::read(&standalone_exe).unwrap(), new_binary_payload);

    // 3. Tampered checksum is rejected and preserves existing binary
    fs::write(&standalone_exe, b"protected-binary").unwrap();
    fs::write(
        &checksum_path,
        format!(
            "0000000000000000000000000000000000000000000000000000000000000000  {}\n",
            target_info.archive_name
        ),
    )
    .unwrap();

    let tampered_out = sandbox
        .cmd()
        .env("DOTLER_RELEASE_BASE_URL", &release_base_url)
        .env("DOTLER_UPDATE_EXE_PATH", &standalone_exe)
        .env("DOTLER_LIBC", "musl")
        .args(["update", "-y"])
        .output()
        .unwrap();
    assert_eq!(tampered_out.status.code(), Some(2));
    assert_eq!(fs::read(&standalone_exe).unwrap(), b"protected-binary");
}
