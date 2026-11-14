mod common;

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::time::Duration;

use common::AgentTestSandbox;
use serde_json::{Value, json};

#[test]
fn test_mcp_stateless_idle_and_lock_concurrency() {
    let sandbox = AgentTestSandbox::new_agent();

    // Initialize repo
    let init_out = sandbox
        .bin_cmd()
        .args(["init", "--label", "primary"])
        .output()
        .unwrap();
    assert_eq!(init_out.status.code(), Some(0));

    let lock_file_path = sandbox.dotler_dir.join("dotler.lock");

    // Spawn MCP server
    let mut child = sandbox.spawn_mcp();
    let mut stdin = child.stdin.take().expect("Child stdin unavailable");
    let mut reader = BufReader::new(child.stdout.take().expect("Child stdout unavailable"));

    // Handshake
    let init_req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    });
    writeln!(stdin, "{}", serde_json::to_string(&init_req).unwrap()).unwrap();
    stdin.flush().unwrap();
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();

    // STATELESS IDLE CHECK:
    // While MCP server is blocked waiting on stdin, an external process MUST be able to acquire lock immediately.
    let lock = dotler::config::state::DotlerLock::new(lock_file_path.clone());
    let lock_guard = lock
        .acquire(Duration::from_millis(100), Duration::from_millis(10))
        .expect("Stateless Idle Invariant: MCP server MUST NOT hold lock while idle on stdin");

    // While external lock is held, send tools/call request to MCP server.
    // The MCP server should wait, and if we release after a brief pause, complete successfully.
    let call_req = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "dotler_briefing",
            "arguments": {}
        }
    });
    writeln!(stdin, "{}", serde_json::to_string(&call_req).unwrap()).unwrap();
    stdin.flush().unwrap();

    // Release external lock after short pause
    std::thread::sleep(Duration::from_millis(50));
    drop(lock_guard);

    line.clear();
    reader.read_line(&mut line).unwrap();
    let resp: Value = serde_json::from_str(&line).expect("Valid JSON response");

    // The response must either succeed (if lock released before timeout) or return lock timeout error
    assert_eq!(resp["jsonrpc"], "2.0");

    // Now call again when lock is completely free
    let call_req2 = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "dotler_briefing",
            "arguments": {}
        }
    });
    writeln!(stdin, "{}", serde_json::to_string(&call_req2).unwrap()).unwrap();
    stdin.flush().unwrap();

    line.clear();
    reader.read_line(&mut line).unwrap();
    let resp2: Value = serde_json::from_str(&line).expect("Valid JSON response");
    assert_eq!(resp2["id"], 3);
    assert_eq!(resp2["result"]["isError"], false);

    // Verify No-Unlink: lock file is preserved on disk
    assert!(
        lock_file_path.exists(),
        "No-Unlink Invariant: dotler.lock must remain on disk after unlocking"
    );

    drop(stdin);
    let _ = child.wait();
}

#[test]
fn test_mcp_tidy_safe_keep_default() {
    let sandbox = AgentTestSandbox::new_agent();
    let init_out = sandbox
        .bin_cmd()
        .args(["init", "--label", "primary"])
        .output()
        .unwrap();
    assert_eq!(init_out.status.code(), Some(0));

    // Put a file in home
    let test_file = sandbox.home_dir.join(".sample_rc");
    fs::write(&test_file, "sample config\n").unwrap();

    let mut child = sandbox.spawn_mcp();
    let mut stdin = child.stdin.take().expect("Child stdin unavailable");
    let mut reader = BufReader::new(child.stdout.take().expect("Child stdout unavailable"));

    // Handshake
    let init_req = json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize" });
    writeln!(stdin, "{}", serde_json::to_string(&init_req).unwrap()).unwrap();
    stdin.flush().unwrap();
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();

    // Call dotler_tidy with NO purge flag (must default to purge=false)
    let tidy_req = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "dotler_tidy",
            "arguments": {}
        }
    });
    writeln!(stdin, "{}", serde_json::to_string(&tidy_req).unwrap()).unwrap();
    stdin.flush().unwrap();

    line.clear();
    reader.read_line(&mut line).unwrap();
    let resp: Value = serde_json::from_str(&line).expect("Valid JSON response");

    assert_eq!(resp["id"], 2);
    assert_eq!(resp["result"]["isError"], false);

    // Safe agent default: the file must NOT be deleted from the filesystem
    assert!(
        test_file.exists(),
        "Safe Default Invariant: dotler_tidy must default to purge=false and preserve OS files"
    );

    // Passing removed legacy argument (`rm`) must return a tool error
    let legacy_req = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "dotler_tidy",
            "arguments": { "rm": true }
        }
    });
    writeln!(stdin, "{}", serde_json::to_string(&legacy_req).unwrap()).unwrap();
    stdin.flush().unwrap();

    line.clear();
    reader.read_line(&mut line).unwrap();
    let legacy_resp: Value = serde_json::from_str(&line).expect("Valid JSON response");
    assert_eq!(legacy_resp["id"], 3);
    assert_eq!(legacy_resp["result"]["isError"], true);

    drop(stdin);
    let _ = child.wait();
}
