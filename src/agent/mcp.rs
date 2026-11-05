//! Model Context Protocol (MCP) JSON-RPC 2.0 stdio server implementation.
//!
//! Provides a stateless, idle-zero-lock stdio server exposing 7 dotfile management tools.

use std::fs;
use std::io::{BufRead, Write};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::agent::AgentError;
use crate::agent::briefing::render_briefing;
use crate::config::local::{LocalConfig, expand_tilde};
use crate::config::repo::{OsInfo, RepoConfig, parse_selection_rules, validate_path_security};
use crate::config::state::{
    DOTLER_LOCK_PATH, DOTLER_LOCK_POLL_INTERVAL_MS, DOTLER_LOCK_TIMEOUT_MS, DotlerLock,
    DotlerLockGuard, STATE_DB_PATH, StateDb,
};
use crate::crypto::keyring::OsKeyring;
use crate::crypto::vault::{VaultKey, VaultSlot};
use crate::engine::remote::{list_remote, parse_url};
use crate::engine::sync::{
    SyncEngine, TidyOrphanPolicy, export_files, import_files, plan, tidy_groups,
};

/// JSON-RPC 2.0 incoming request frame.
#[derive(Debug, Clone, Deserialize)]
pub struct McpRequest {
    pub jsonrpc: String,
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Option<Value>,
}

/// JSON-RPC 2.0 outgoing response frame.
#[derive(Debug, Clone, Serialize)]
pub struct McpResponse {
    pub jsonrpc: String,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<McpErrorObject>,
}

/// JSON-RPC 2.0 error object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpErrorObject {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// Model Context Protocol tool schema definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpToolDefinition {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
}

/// Content item inside an MCP tool call response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolContent {
    pub r#type: String,
    pub text: String,
}

/// Tool execution result envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolCallResult {
    pub content: Vec<ToolContent>,
    pub is_error: bool,
}

/// Returns the schema definitions for all 7 exposed MCP tools.
pub fn list_tools() -> Vec<McpToolDefinition> {
    vec![
        McpToolDefinition {
            name: "dotler_briefing".to_string(),
            description: "Retrieve comprehensive agent briefing including dotler.toml syntax, 3-state rules, device profile, and security guardrails.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }),
        },
        McpToolDefinition {
            name: "dotler_check".to_string(),
            description: "Statically validate dotler.toml and config.toml manifests, path security rules (~/ prefix, no ..), and cross-group collisions.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": { "type": "string", "description": "Repository label (defaults to configured default_repo)" },
                    "group": { "type": "string", "description": "Optional group name filter" }
                },
                "additionalProperties": false
            }),
        },
        McpToolDefinition {
            name: "dotler_status".to_string(),
            description: "Reconcile 3-way synchronization status between OS target paths, repository files, and SQLite state ledger.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": { "type": "string", "description": "Repository label (defaults to default_repo)" },
                    "group": { "type": "string", "description": "Optional group name filter" }
                },
                "additionalProperties": false
            }),
        },
        McpToolDefinition {
            name: "dotler_import".to_string(),
            description: "Ingest matching dotfiles from OS paths into repository, re-encrypting encrypted files using OS Keyring master key.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": { "type": "string", "description": "Repository label (defaults to default_repo)" },
                    "groups": { "type": "array", "items": { "type": "string" }, "description": "Optional group name filters" },
                    "dry_run": { "type": "boolean", "description": "Simulate collection without modifying repository or database" }
                },
                "additionalProperties": false
            }),
        },
        McpToolDefinition {
            name: "dotler_export".to_string(),
            description: "Deploy dotfiles from repository to OS paths with atomic temporary files and conflict detection.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": { "type": "string", "description": "Repository label (defaults to default_repo)" },
                    "groups": { "type": "array", "items": { "type": "string" }, "description": "Optional group name filters" },
                    "force": { "type": "boolean", "description": "Overwrite locally modified files" },
                    "dry_run": { "type": "boolean", "description": "Simulate deployment without modifying target files or database" }
                },
                "additionalProperties": false
            }),
        },
        McpToolDefinition {
            name: "dotler_tidy".to_string(),
            description: "Reconcile in-repo file formats (plain vs .enc) and clean up untracked orphans (safely keeps OS files by default).".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": { "type": "string", "description": "Repository label (defaults to default_repo)" },
                    "groups": { "type": "array", "items": { "type": "string" }, "description": "Optional group name filters" },
                    "purge": { "type": "boolean", "description": "Permanently delete orphaned files from OS filesystem (defaults to false, keeping OS files intact)" },
                    "dry_run": { "type": "boolean", "description": "Simulate tidy operations without modifying files" }
                },
                "additionalProperties": false
            }),
        },
        McpToolDefinition {
            name: "dotler_git_ls".to_string(),
            description: "Inspect remote Git dotfile repository without cloning to list available groups, target OS paths, and encryption status.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "url": { "type": "string", "description": "Remote Git repository URL or shorthand (gh:, gl:, cb:, srht:, bb:)" },
                    "branch": { "type": "string", "description": "Optional branch name" }
                },
                "required": ["url"],
                "additionalProperties": false
            }),
        },
    ]
}

/// Runs the MCP JSON-RPC 2.0 server over reader and writer streams.
pub fn run_mcp_server<R: BufRead, W: Write>(
    mut reader: R,
    mut writer: W,
) -> Result<(), AgentError> {
    let mut line = String::new();
    while reader.read_line(&mut line)? > 0 {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            line.clear();
            continue;
        }

        if let Some(resp) = handle_raw_line(trimmed) {
            let serialized = serde_json::to_string(&resp)?;
            writer.write_all(serialized.as_bytes())?;
            writer.write_all(b"\n")?;
            writer.flush()?;
        }
        line.clear();
    }
    Ok(())
}

fn handle_raw_line(line: &str) -> Option<McpResponse> {
    let req: McpRequest = match serde_json::from_str(line) {
        Ok(r) => r,
        Err(e) => {
            return Some(McpResponse {
                jsonrpc: "2.0".to_string(),
                id: Value::Null,
                result: None,
                error: Some(McpErrorObject {
                    code: -32700,
                    message: format!("Parse error: {}", e),
                    data: None,
                }),
            });
        }
    };

    let id = req.id.unwrap_or(Value::Null);

    // Notifications (no id)
    if id.is_null() && req.method.starts_with("notifications/") {
        return None;
    }

    match req.method.as_str() {
        "initialize" => Some(McpResponse {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "dotler",
                    "version": env!("CARGO_PKG_VERSION")
                }
            })),
            error: None,
        }),

        "tools/list" => Some(McpResponse {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(json!({
                "tools": list_tools()
            })),
            error: None,
        }),

        "tools/call" => {
            let params = req.params.unwrap_or(Value::Null);
            let tool_name = params.get("name").and_then(Value::as_str).unwrap_or("");
            let arguments = params.get("arguments").cloned().unwrap_or(json!({}));

            Some(execute_tool_with_lock(id, tool_name, arguments))
        }

        unknown => Some(McpResponse {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(McpErrorObject {
                code: -32601,
                message: format!("Method not found: {}", unknown),
                data: None,
            }),
        }),
    }
}

/// Executes a tool call under a single exclusive `DotlerLockGuard`.
fn execute_tool_with_lock(id: Value, name: &str, args: Value) -> McpResponse {
    let lock_path = expand_tilde(DOTLER_LOCK_PATH);
    if let Some(parent) = lock_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let lock = DotlerLock::new(lock_path);

    // Acquire lock with 5000ms timeout
    let guard = match lock.acquire(
        Duration::from_millis(DOTLER_LOCK_TIMEOUT_MS),
        Duration::from_millis(DOTLER_LOCK_POLL_INTERVAL_MS),
    ) {
        Ok(g) => g,
        Err(_) => {
            return McpResponse {
                jsonrpc: "2.0".to_string(),
                id,
                result: None,
                error: Some(McpErrorObject {
                    code: -32000,
                    message: "Failed to acquire dotler.lock: lock contention timeout".to_string(),
                    data: Some(json!({
                        "error_code": "LOCK_TIMEOUT",
                        "hint": "Another dotler process holds ~/.config/dotler/dotler.lock. Wait for it to complete or terminate stale processes."
                    })),
                }),
            };
        }
    };

    // Dispatch tool execution under DotlerLockGuard
    let tool_res = dispatch_tool(name, args, &guard);

    // Guard drops here upon function return: Lock released cleanly, No-Unlink preserved
    match tool_res {
        Ok(result) => McpResponse {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(serde_json::to_value(result).unwrap_or(json!({}))),
            error: None,
        },
        Err(err_msg) => McpResponse {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(json!({
                "content": [{
                    "type": "text",
                    "text": err_msg
                }],
                "isError": true
            })),
            error: None,
        },
    }
}

fn dispatch_tool(
    name: &str,
    args: Value,
    lock: &DotlerLockGuard,
) -> Result<ToolCallResult, String> {
    match name {
        "dotler_briefing" => {
            let local_cfg = load_or_default_local_config();
            let os_info = OsInfo::detect();
            let keyring_ready =
                local_cfg.use_keyring && OsKeyring::get().map(|opt| opt.is_some()).unwrap_or(false);
            let briefing_text = render_briefing(&local_cfg, &os_info, keyring_ready);
            Ok(ToolCallResult {
                content: vec![ToolContent {
                    r#type: "text".to_string(),
                    text: briefing_text,
                }],
                is_error: false,
            })
        }

        "dotler_check" => {
            let repo_arg = args.get("repo").and_then(Value::as_str);
            let group_arg = args.get("group").and_then(Value::as_str);

            let local_cfg = load_or_default_local_config();
            let (_label, repo_path) = resolve_mcp_repo(&local_cfg, repo_arg)
                .map_err(|e| format!("Configuration error: {e}"))?;

            let manifest_path = repo_path.join("dotler.toml");
            let repo_cfg = RepoConfig::load(&manifest_path)
                .map_err(|e| format!("Failed to load dotler.toml: {e}"))?;

            // Validate path safety and syntax
            for (g_name, g_cfg) in &repo_cfg.groups {
                if let Some(filter) = group_arg
                    && filter != g_name
                {
                    continue;
                }
                for target_path in g_cfg.paths.values() {
                    validate_path_security(target_path)
                        .map_err(|e| format!("Security check failed in group '{g_name}': {e}"))?;
                }
                parse_selection_rules(&g_cfg.files)
                    .map_err(|e| format!("Selection rule syntax error in group '{g_name}': {e}"))?;
                let group_repo_dir = repo_path.join(g_name);
                crate::config::repo::validate_dir_no_symlinks(&group_repo_dir)
                    .map_err(|e| format!("Security check failed in group '{g_name}': {e}"))?;
            }

            Ok(ToolCallResult {
                content: vec![ToolContent {
                    r#type: "text".to_string(),
                    text: json!({
                        "ok": true,
                        "message": "All manifest syntax, selection rules, and path security constraints validated successfully."
                    }).to_string(),
                }],
                is_error: false,
            })
        }

        "dotler_status" => {
            let repo_arg = args.get("repo").and_then(Value::as_str);
            let group_arg = args.get("group").and_then(Value::as_str);

            let local_cfg = load_or_default_local_config();
            let (label, repo_path) = resolve_mcp_repo(&local_cfg, repo_arg)
                .map_err(|e| format!("Configuration error: {e}"))?;

            let manifest_path = repo_path.join("dotler.toml");
            let repo_cfg = RepoConfig::load(&manifest_path)
                .map_err(|e| format!("Failed to load dotler.toml: {e}"))?;

            let state_db = StateDb::open(&expand_tilde(STATE_DB_PATH))
                .map_err(|e| format!("Failed to open state.db: {e}"))?;

            let vault_key = try_unlock_vault(&repo_cfg, local_cfg.use_keyring);
            let os_info = OsInfo::detect();

            let sync_engine = SyncEngine::new(
                &label,
                &repo_path,
                &repo_cfg,
                &state_db,
                local_cfg.default_devices.clone(),
                os_info,
                vault_key.as_ref(),
            );

            let plans = plan(&sync_engine, group_arg, lock)
                .map_err(|e| format!("Status planning failed: {e}"))?;

            Ok(ToolCallResult {
                content: vec![ToolContent {
                    r#type: "text".to_string(),
                    text: serde_json::to_string_pretty(&plans).unwrap_or_default(),
                }],
                is_error: false,
            })
        }

        "dotler_import" => {
            let repo_arg = args.get("repo").and_then(Value::as_str);
            let groups_arg: Option<Vec<String>> = args
                .get("groups")
                .and_then(|v| serde_json::from_value(v.clone()).ok());
            let dry_run = args
                .get("dry_run")
                .and_then(Value::as_bool)
                .unwrap_or(false);

            let local_cfg = load_or_default_local_config();
            let (label, repo_path) = resolve_mcp_repo(&local_cfg, repo_arg)
                .map_err(|e| format!("Configuration error: {e}"))?;

            let manifest_path = repo_path.join("dotler.toml");
            let repo_cfg = RepoConfig::load(&manifest_path)
                .map_err(|e| format!("Failed to load dotler.toml: {e}"))?;

            let state_db = StateDb::open(&expand_tilde(STATE_DB_PATH))
                .map_err(|e| format!("Failed to open state.db: {e}"))?;

            let vault_key = try_unlock_vault(&repo_cfg, local_cfg.use_keyring);
            let os_info = OsInfo::detect();

            let sync_engine = SyncEngine::new(
                &label,
                &repo_path,
                &repo_cfg,
                &state_db,
                local_cfg.default_devices.clone(),
                os_info,
                vault_key.as_ref(),
            );

            let mut all_plans = Vec::new();
            if let Some(groups) = groups_arg {
                for g in groups {
                    let mut p = plan(&sync_engine, Some(&g), lock)
                        .map_err(|e| format!("Planning failed for group '{g}': {e}"))?;
                    all_plans.append(&mut p);
                }
            } else {
                all_plans =
                    plan(&sync_engine, None, lock).map_err(|e| format!("Planning failed: {e}"))?;
            }

            let report = import_files(&sync_engine, &all_plans, lock, dry_run)
                .map_err(|e| format!("Import failed: {e}\nHint: {}", e.hint()))?;

            Ok(ToolCallResult {
                content: vec![ToolContent {
                    r#type: "text".to_string(),
                    text: serde_json::to_string_pretty(&report).unwrap_or_default(),
                }],
                is_error: false,
            })
        }

        "dotler_export" => {
            let repo_arg = args.get("repo").and_then(Value::as_str);
            let groups_arg: Option<Vec<String>> = args
                .get("groups")
                .and_then(|v| serde_json::from_value(v.clone()).ok());
            let force = args.get("force").and_then(Value::as_bool).unwrap_or(false);
            let dry_run = args
                .get("dry_run")
                .and_then(Value::as_bool)
                .unwrap_or(false);

            let local_cfg = load_or_default_local_config();
            let (label, repo_path) = resolve_mcp_repo(&local_cfg, repo_arg)
                .map_err(|e| format!("Configuration error: {e}"))?;

            let manifest_path = repo_path.join("dotler.toml");
            let repo_cfg = RepoConfig::load(&manifest_path)
                .map_err(|e| format!("Failed to load dotler.toml: {e}"))?;

            let state_db = StateDb::open(&expand_tilde(STATE_DB_PATH))
                .map_err(|e| format!("Failed to open state.db: {e}"))?;

            let vault_key = try_unlock_vault(&repo_cfg, local_cfg.use_keyring);
            let os_info = OsInfo::detect();

            let sync_engine = SyncEngine::new(
                &label,
                &repo_path,
                &repo_cfg,
                &state_db,
                local_cfg.default_devices.clone(),
                os_info,
                vault_key.as_ref(),
            );

            let mut all_plans = Vec::new();
            if let Some(groups) = groups_arg {
                for g in groups {
                    let mut p = plan(&sync_engine, Some(&g), lock)
                        .map_err(|e| format!("Planning failed for group '{g}': {e}"))?;
                    all_plans.append(&mut p);
                }
            } else {
                all_plans =
                    plan(&sync_engine, None, lock).map_err(|e| format!("Planning failed: {e}"))?;
            }

            let report = export_files(&sync_engine, &all_plans, lock, force, dry_run)
                .map_err(|e| format!("Export failed: {e}\nHint: {}", e.hint()))?;

            Ok(ToolCallResult {
                content: vec![ToolContent {
                    r#type: "text".to_string(),
                    text: serde_json::to_string_pretty(&report).unwrap_or_default(),
                }],
                is_error: false,
            })
        }

        "dotler_tidy" => {
            let repo_arg = args.get("repo").and_then(Value::as_str);
            let group_filters: Vec<String> = args
                .get("groups")
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();
            if let Some(obj) = args.as_object() {
                for key in obj.keys() {
                    if !matches!(key.as_str(), "repo" | "groups" | "purge" | "dry_run") {
                        return Err(format!(
                            "Unknown argument '{key}' for dotler_tidy. Allowed arguments: repo, groups, purge, dry_run."
                        ));
                    }
                }
            }

            let purge = args.get("purge").and_then(Value::as_bool).unwrap_or(false);
            let dry_run = args
                .get("dry_run")
                .and_then(Value::as_bool)
                .unwrap_or(false);

            // Safe agent default is KeepOnOs (purge = false)
            let policy = if purge {
                TidyOrphanPolicy::PurgeFromOs
            } else {
                TidyOrphanPolicy::KeepOnOs
            };

            let local_cfg = load_or_default_local_config();
            let (label, repo_path) = resolve_mcp_repo(&local_cfg, repo_arg)
                .map_err(|e| format!("Configuration error: {e}"))?;

            let manifest_path = repo_path.join("dotler.toml");
            let repo_cfg = RepoConfig::load(&manifest_path)
                .map_err(|e| format!("Failed to load dotler.toml: {e}"))?;

            let state_db = StateDb::open(&expand_tilde(STATE_DB_PATH))
                .map_err(|e| format!("Failed to open state.db: {e}"))?;

            let vault_key = try_unlock_vault(&repo_cfg, local_cfg.use_keyring);
            let os_info = OsInfo::detect();

            let sync_engine = SyncEngine::new(
                &label,
                &repo_path,
                &repo_cfg,
                &state_db,
                local_cfg.default_devices.clone(),
                os_info,
                vault_key.as_ref(),
            );

            let report = tidy_groups(&sync_engine, &group_filters, lock, policy, dry_run)
                .map_err(|e| format!("Tidy failed: {e}\nHint: {}", e.hint()))?;

            Ok(ToolCallResult {
                content: vec![ToolContent {
                    r#type: "text".to_string(),
                    text: serde_json::to_string_pretty(&report).unwrap_or_default(),
                }],
                is_error: false,
            })
        }

        "dotler_git_ls" => {
            let url_str = args
                .get("url")
                .and_then(Value::as_str)
                .ok_or_else(|| "Missing required parameter 'url'".to_string())?;
            let branch = args.get("branch").and_then(Value::as_str);

            let parsed_url =
                parse_url(url_str).map_err(|e| format!("Invalid URL '{url_str}': {e}"))?;

            let summary = list_remote(&parsed_url, branch, lock)
                .map_err(|e| format!("Failed to inspect remote Git repository: {e}"))?;

            Ok(ToolCallResult {
                content: vec![ToolContent {
                    r#type: "text".to_string(),
                    text: serde_json::to_string_pretty(&summary).unwrap_or_default(),
                }],
                is_error: false,
            })
        }

        unknown => Err(format!("Unknown tool: {unknown}")),
    }
}

fn load_or_default_local_config() -> LocalConfig {
    let config_path = expand_tilde("~/.config/dotler/config.toml");
    if config_path.is_file() {
        LocalConfig::load(&config_path).unwrap_or_default()
    } else {
        LocalConfig::default()
    }
}

fn resolve_mcp_repo(
    local_cfg: &LocalConfig,
    requested_label: Option<&str>,
) -> Result<(String, std::path::PathBuf), crate::config::ConfigError> {
    if requested_label.is_none()
        && let Ok(current_dir) = std::env::current_dir()
        && let Some(repo_dir) = crate::config::local::find_ancestor_repo_dir(&current_dir)
    {
        let canon_repo = fs::canonicalize(&repo_dir).unwrap_or_else(|_| repo_dir.clone());
        if let Some((reg_label, _)) = local_cfg.repos.iter().find(|(_, p)| {
            let exp = expand_tilde(p);
            fs::canonicalize(&exp).unwrap_or(exp) == canon_repo
        }) {
            return Ok((reg_label.clone(), repo_dir));
        }
        let label = repo_dir
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_else(|| "default".to_string());
        return Ok((label, repo_dir));
    }

    local_cfg.resolve_repo(requested_label)
}

fn try_unlock_vault(repo_cfg: &RepoConfig, use_keyring: bool) -> Option<VaultKey> {
    if !use_keyring {
        return None;
    }
    let vault_cfg = repo_cfg.vault.as_ref()?;
    let secret = OsKeyring::get().ok()??;
    let slot = VaultSlot::from_base64(&vault_cfg.password_slot).ok()?;
    slot.unwrap(&secret, Some(&vault_cfg.vault_id)).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_list_tools_schema_zero_secrets() {
        let tools = list_tools();
        assert_eq!(tools.len(), 7);

        for tool in tools {
            let schema = serde_json::to_string(&tool.input_schema)
                .unwrap()
                .to_lowercase();
            assert!(!schema.contains("password"));
            assert!(!schema.contains("passphrase"));
            assert!(!schema.contains("mnemonic"));
            assert_ne!(tool.name, "vault");
            assert_ne!(tool.name, "key");
        }
    }

    #[test]
    fn test_mcp_initialize_and_tools_list_handshake() {
        let input = "{\"jsonrpc\": \"2.0\", \"id\": 1, \"method\": \"initialize\"}\n{\"jsonrpc\": \"2.0\", \"id\": 2, \"method\": \"tools/list\"}\n";
        let reader = Cursor::new(input.as_bytes());
        let mut output = Vec::new();

        run_mcp_server(reader, &mut output).unwrap();

        let out_str = String::from_utf8(output).unwrap();
        let lines: Vec<&str> = out_str.lines().collect();
        assert_eq!(lines.len(), 2);

        let resp1: Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(resp1["jsonrpc"], "2.0");
        assert_eq!(resp1["id"], 1);
        assert_eq!(resp1["result"]["serverInfo"]["name"], "dotler");

        let resp2: Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(resp2["jsonrpc"], "2.0");
        assert_eq!(resp2["id"], 2);
        let tools = resp2["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 7);
    }
}
