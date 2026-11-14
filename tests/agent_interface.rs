mod common;

use std::fs;
use std::io::{BufRead, BufReader, Write};

use common::AgentTestSandbox;
use serde_json::{Value, json};

#[test]
fn test_dotler_init_ai_hint_and_no_skill_md() {
    let sandbox = AgentTestSandbox::new_agent();

    let output = sandbox
        .bin_cmd()
        .args(["init", "--label", "test-repo", "--device", "desktop"])
        .output()
        .expect("Execution of dotler init failed");

    assert_eq!(
        output.status.code(),
        Some(0),
        "dotler init must exit with code 0. Stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout_str = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout_str.contains("Hint:") && stdout_str.contains("dotler ai"),
        "dotler init stdout must include an onboarding hint pointing to 'dotler ai'. Got: {stdout_str}"
    );

    // Verify dotler.toml was created with top AI hint comment
    let dotler_toml = sandbox.repo_dir.join("dotler.toml");
    assert!(dotler_toml.is_file(), "dotler.toml must be created");
    let toml_text = fs::read_to_string(&dotler_toml).expect("Failed to read dotler.toml");
    assert!(
        toml_text.starts_with("# ")
            && toml_text.contains("AI Hint: Run 'dotler ai'")
            && toml_text.contains("https://msisdev.github.io/dotler/"),
        "dotler.toml must start with the ASCII header and AI Hint comment pointing to 'dotler ai'"
    );

    // Verify no standalone SKILL.md was generated
    let skill_md = sandbox.repo_dir.join("SKILL.md");
    assert!(
        !skill_md.exists(),
        "dotler init must not pollute the repository with a standalone SKILL.md file"
    );

    // Verify --json output also includes the hint field
    let json_output = sandbox
        .bin_cmd()
        .args([
            "init",
            "--label",
            "test-repo",
            "--device",
            "desktop",
            "--json",
        ])
        .output()
        .expect("Execution of dotler init --json failed");
    assert_eq!(json_output.status.code(), Some(0));
    let parsed: Value = serde_json::from_slice(&json_output.stdout).unwrap();
    assert_eq!(parsed["ok"], json!(true));
    assert!(
        parsed["data"]["hint"]
            .as_str()
            .unwrap_or_default()
            .contains("dotler ai"),
        "dotler init --json must include 'hint' pointing to 'dotler ai'"
    );
}

#[test]
fn test_dotler_ai_briefing_4_sections_and_zero_secret_leakage() {
    let sandbox = AgentTestSandbox::new_agent();

    // Initialize repo first
    let init_out = sandbox
        .bin_cmd()
        .args(["init", "--label", "work", "--device", "laptop"])
        .output()
        .unwrap();
    assert_eq!(init_out.status.code(), Some(0));

    // Secret password that must NEVER be leaked in briefing output
    let secret_pass = "ultra_confidential_master_passphrase_xyz789";

    // Run dotler ai with passphrase injected into environment
    let output = sandbox
        .bin_cmd_with_passphrase(secret_pass)
        .arg("ai")
        .output()
        .expect("Execution of dotler ai failed");

    assert_eq!(
        output.status.code(),
        Some(0),
        "dotler ai must exit with code 0. Stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Assert secret passphrase NEVER appears anywhere in output
    assert!(
        !stdout.contains(secret_pass),
        "SECURITY VIOLATION: Master passphrase leaked in dotler ai output!"
    );

    // Assert all 4 mandatory sections exist in sequential order
    let sec1 = stdout.find("## 1. System Overview & Active Device Profile");
    let sec2 = stdout.find("## 2. Group Layout & Selection Rules");
    let sec3 = stdout.find("## 3. Standard Operational Guidelines & Command Cheatsheet");
    let sec4 = stdout.find("## 4. Security Guardrails & Prohibitions");

    assert!(sec1.is_some(), "Section 1 heading missing in briefing");
    assert!(sec2.is_some(), "Section 2 heading missing in briefing");
    assert!(sec3.is_some(), "Section 3 heading missing in briefing");
    assert!(sec4.is_some(), "Section 4 heading missing in briefing");

    assert!(
        sec1.unwrap() < sec2.unwrap()
            && sec2.unwrap() < sec3.unwrap()
            && sec3.unwrap() < sec4.unwrap(),
        "Briefing sections must follow strict sequential order 1 -> 2 -> 3 -> 4"
    );

    // Check specific environment markers
    assert!(
        stdout.contains("keyring_ready:"),
        "keyring status must be reported"
    );
    assert!(
        stdout.contains("Default Devices Priority:"),
        "device priority must be listed"
    );
}

#[test]
fn test_mcp_handshake_and_tool_discovery() {
    let sandbox = AgentTestSandbox::new_agent();
    let mut child = sandbox.spawn_mcp();

    let mut stdin = child.stdin.take().expect("Child stdin unavailable");
    let mut reader = BufReader::new(child.stdout.take().expect("Child stdout unavailable"));

    // 1. Send initialize request
    let init_req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "clientInfo": { "name": "test-agent", "version": "1.0.0" }
        }
    });
    writeln!(stdin, "{}", serde_json::to_string(&init_req).unwrap()).unwrap();
    stdin.flush().unwrap();

    let mut line = String::new();
    reader
        .read_line(&mut line)
        .expect("Failed to read initialize response");
    let init_resp: Value = serde_json::from_str(&line).expect("Invalid JSON-RPC response");

    assert_eq!(init_resp["jsonrpc"], "2.0");
    assert_eq!(init_resp["id"], 1);
    assert_eq!(init_resp["result"]["serverInfo"]["name"], "dotler");
    assert_eq!(init_resp["result"]["protocolVersion"], "2024-11-05");

    // 2. Send notifications/initialized
    let init_notif = json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    });
    writeln!(stdin, "{}", serde_json::to_string(&init_notif).unwrap()).unwrap();
    stdin.flush().unwrap();

    // 3. Send tools/list request
    let list_req = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    });
    writeln!(stdin, "{}", serde_json::to_string(&list_req).unwrap()).unwrap();
    stdin.flush().unwrap();

    line.clear();
    reader
        .read_line(&mut line)
        .expect("Failed to read tools/list response");
    let list_resp: Value = serde_json::from_str(&line).expect("Invalid JSON-RPC response");

    assert_eq!(list_resp["jsonrpc"], "2.0");
    assert_eq!(list_resp["id"], 2);

    let tools = list_resp["result"]["tools"]
        .as_array()
        .expect("tools must be an array");

    // Must expose exactly 7 tools
    assert_eq!(tools.len(), 7, "MCP server must expose exactly 7 tools");

    let expected_tools = [
        "dotler_briefing",
        "dotler_check",
        "dotler_status",
        "dotler_import",
        "dotler_export",
        "dotler_tidy",
        "dotler_git_ls",
    ];

    let mut found_names: Vec<String> = tools
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect();
    found_names.sort();

    let mut expected_sorted: Vec<String> = expected_tools.iter().map(|s| s.to_string()).collect();
    expected_sorted.sort();

    assert_eq!(
        found_names, expected_sorted,
        "Exposed tools must match the exact 7 tool contracts"
    );

    // Invariant: Zero secret arguments in tool schemas (no passwords, passphrases, or mnemonics)
    for tool in tools {
        let tool_name = tool["name"].as_str().unwrap();
        let schema_str = serde_json::to_string(&tool["inputSchema"])
            .unwrap()
            .to_lowercase();

        assert!(
            !schema_str.contains("password"),
            "Tool '{}' schema must not contain password argument",
            tool_name
        );
        assert!(
            !schema_str.contains("passphrase"),
            "Tool '{}' schema must not contain passphrase argument",
            tool_name
        );
        assert!(
            !schema_str.contains("mnemonic"),
            "Tool '{}' schema must not contain mnemonic argument",
            tool_name
        );
    }

    // Clean shutdown: drop stdin and wait
    drop(stdin);
    let _ = child.wait();
}

#[test]
fn test_mcp_all_7_tools_execution() {
    let sandbox = AgentTestSandbox::new_agent();

    // Initialize local repo
    let init_out = sandbox
        .bin_cmd()
        .args(["init", "--label", "primary", "--device", "desktop"])
        .output()
        .unwrap();
    assert_eq!(init_out.status.code(), Some(0));

    // Configure a sample group in dotler.toml
    let toml_content = r#"[shell]
path = "~"
files = """
*
!*.log
"""
"#;
    fs::write(sandbox.repo_dir.join("dotler.toml"), toml_content).unwrap();

    // Create a dummy dotfile in home directory
    let bashrc = sandbox.home_dir.join(".bashrc");
    fs::write(&bashrc, "export TEST=1\n").unwrap();

    let mut child = sandbox.spawn_mcp_with_passphrase("correct_horse_battery_staple_123");
    let mut stdin = child.stdin.take().expect("Child stdin unavailable");
    let mut reader = BufReader::new(child.stdout.take().expect("Child stdout unavailable"));

    let call_tool = |stdin: &mut std::process::ChildStdin,
                     reader: &mut BufReader<std::process::ChildStdout>,
                     id_val: i64,
                     tool_name: &str,
                     args: Value|
     -> Value {
        let req = json!({
            "jsonrpc": "2.0",
            "id": id_val,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": args
            }
        });
        writeln!(stdin, "{}", serde_json::to_string(&req).unwrap()).unwrap();
        stdin.flush().unwrap();

        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        serde_json::from_str(&line).expect("Valid JSON-RPC response")
    };

    // Tool 1: dotler_briefing
    let resp1 = call_tool(&mut stdin, &mut reader, 1, "dotler_briefing", json!({}));
    assert_eq!(resp1["jsonrpc"], "2.0");
    assert_eq!(resp1["result"]["isError"], false);
    let text1 = resp1["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text1.contains("Dotler Agent Briefing"));

    // Tool 2: dotler_check
    let resp2 = call_tool(&mut stdin, &mut reader, 2, "dotler_check", json!({}));
    assert_eq!(resp2["jsonrpc"], "2.0");
    assert_eq!(resp2["result"]["isError"], false);

    // Tool 3: dotler_status
    let resp3 = call_tool(&mut stdin, &mut reader, 3, "dotler_status", json!({}));
    assert_eq!(resp3["jsonrpc"], "2.0");
    assert_eq!(resp3["result"]["isError"], false);

    // Tool 4: dotler_import (dry_run)
    let resp4 = call_tool(
        &mut stdin,
        &mut reader,
        4,
        "dotler_import",
        json!({ "dry_run": true }),
    );
    assert_eq!(resp4["jsonrpc"], "2.0");
    assert_eq!(resp4["result"]["isError"], false);

    // Tool 5: dotler_export (dry_run)
    let resp5 = call_tool(
        &mut stdin,
        &mut reader,
        5,
        "dotler_export",
        json!({ "dry_run": true }),
    );
    assert_eq!(resp5["jsonrpc"], "2.0");
    assert_eq!(resp5["result"]["isError"], false);

    // Tool 6: dotler_tidy (dry_run)
    let resp6 = call_tool(
        &mut stdin,
        &mut reader,
        6,
        "dotler_tidy",
        json!({ "dry_run": true }),
    );
    assert_eq!(resp6["jsonrpc"], "2.0");
    assert_eq!(resp6["result"]["isError"], false);

    // Tool 7: dotler_git_ls against local bare repo fixture
    let bare_url = format!("file://{}", sandbox.bare_git_dir.display());
    let resp7 = call_tool(
        &mut stdin,
        &mut reader,
        7,
        "dotler_git_ls",
        json!({ "url": bare_url }),
    );
    assert_eq!(resp7["jsonrpc"], "2.0");
    assert_eq!(resp7["result"]["isError"], false);
    let text7 = resp7["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        text7.contains("shell"),
        "Remote repo inspection must find shell group"
    );

    drop(stdin);
    let _ = child.wait();
}
