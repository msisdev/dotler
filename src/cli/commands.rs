//! Command-line argument parsing and command dispatch.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use secrecy::SecretString;
use serde_json::json;

use crate::agent::briefing::{render_briefing, scaffold_skill_md};
use crate::cli::output::{EXIT_SUCCESS, render_success_to};
use crate::config::local::{LocalConfig, expand_tilde};
use crate::config::repo::{
    OsInfo, RepoConfig, SelectionMode, parse_selection_rules, validate_path_security,
};
use crate::config::state::{
    DOTLER_LOCK_PATH, DOTLER_LOCK_POLL_INTERVAL_MS, DOTLER_LOCK_TIMEOUT_MS, DotlerLock,
    DotlerLockGuard, STATE_DB_PATH, StateDb,
};
use crate::crypto::keyring::OsKeyring;
use crate::crypto::vault::{VaultKey, VaultSlot, change_password, init_vault, recover_vault};
use crate::engine::EngineError;
use crate::engine::remote::{
    GroupSelector, clone_repo, install_remote, list_remote, parse_url, uninstall_remote,
};
use crate::engine::sync::{
    FileSyncStatus, SyncEngine, TidyOrphanPolicy, atomic_write_file, export_files, import_files,
    plan, tidy_groups,
};

#[derive(Parser, Debug, Clone)]
#[command(
    name = "dotler",
    version,
    about = "Privacy-first, zero-trace dotfile management engine",
    long_about = None
)]
pub struct Cli {
    #[arg(
        short = 'j',
        long = "json",
        global = true,
        help = "Output structured JSON"
    )]
    pub json: bool,

    #[arg(
        short = 'd',
        long = "device",
        global = true,
        help = "Target device profile override"
    )]
    pub device: Option<String>,

    #[arg(
        short = 'r',
        long = "repo",
        global = true,
        help = "Repository label override"
    )]
    pub repo: Option<String>,

    #[arg(
        long = "dry-run",
        global = true,
        help = "Simulate operations without writing changes"
    )]
    pub dry_run: bool,

    #[arg(
        short = 'v',
        long = "verbose",
        global = true,
        help = "Enable verbose output"
    )]
    pub verbose: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Initialize a dotler repository and generate dotler.toml and SKILL.md
    Init(InitArgs),

    /// Remote Git repository operations (ls, clone, install, uninstall)
    Git {
        #[command(subcommand)]
        command: GitCommand,
    },

    /// Validate configuration syntax and path security
    Check(CheckArgs),

    /// Display 3-way synchronization status
    Status(StatusArgs),

    /// Import files from OS into dotfile repository
    Import(ImportArgs),

    /// Export files from dotfile repository to OS
    Export(ExportArgs),

    /// Format conversion (foo <-> foo.enc) and orphan cleanup
    Tidy(TidyArgs),

    /// Manage repository encryption vault slots
    Vault {
        #[command(subcommand)]
        command: VaultCommand,
    },

    /// Manage device OS keyring passphrase storage
    Key {
        #[command(subcommand)]
        command: KeyCommand,
    },

    /// Render one-shot AI briefing markdown
    Ai(AiArgs),

    /// Start stdio JSON-RPC 2.0 Model Context Protocol server
    Mcp(McpArgs),

    /// Check for updates or update repository
    Update(UpdateArgs),
}

#[derive(Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct InitArgs {
    #[arg(long, help = "Repository label for local registration")]
    pub label: Option<String>,

    #[arg(short, long, help = "Primary device name to register")]
    pub device: Option<String>,

    #[arg(
        long = "repo-path",
        help = "Target directory path for repository initialization"
    )]
    pub repo_path: Option<PathBuf>,
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum GitCommand {
    /// Inspect remote repository groups and configuration
    Ls(GitLsArgs),

    /// Clone remote repository into local management
    Clone(GitCloneArgs),

    /// Install remote dotfiles with write-ahead backups without cloning
    Install(GitInstallArgs),

    /// Restore backed-up original files and remove installed dotfiles
    Uninstall(GitUninstallArgs),
}

#[derive(Args, Debug, Clone, PartialEq, Eq)]
pub struct GitLsArgs {
    #[arg(help = "Remote repository URL or shorthand (gh:, gl:, cb:, srht:, bb:)")]
    pub url: String,

    #[arg(short, long, help = "Remote branch name")]
    pub branch: Option<String>,
}

#[derive(Args, Debug, Clone, PartialEq, Eq)]
pub struct GitCloneArgs {
    #[arg(help = "Remote repository URL or shorthand")]
    pub url: String,

    #[arg(help = "Groups to clone, with optional alias (e.g. nvim:my-nvim)")]
    pub groups: Vec<String>,

    #[arg(short, long, help = "Remote branch name")]
    pub branch: Option<String>,

    #[arg(short, long, help = "Target device profile for group resolution")]
    pub device: Option<String>,
}

#[derive(Args, Debug, Clone, PartialEq, Eq)]
pub struct GitInstallArgs {
    #[arg(help = "Remote repository URL or shorthand")]
    pub url: String,

    #[arg(required = true, help = "Groups to install")]
    pub groups: Vec<String>,

    #[arg(
        short,
        long,
        help = "Custom target path override (e.g. group=~/custom/path)"
    )]
    pub path: Vec<String>,

    #[arg(short, long, help = "Remote branch name")]
    pub branch: Option<String>,

    #[arg(short, long, help = "Target device profile for group resolution")]
    pub device: Option<String>,
}

#[derive(Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct GitUninstallArgs {
    #[arg(help = "Groups to uninstall (all if empty)")]
    pub groups: Vec<String>,

    #[arg(long, help = "Simulate rollback without restoring files")]
    pub dry_run: bool,
}

#[derive(Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct CheckArgs {
    #[arg(short, long, help = "Specific group to validate")]
    pub group: Option<String>,
}

#[derive(Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct StatusArgs {
    #[arg(short, long, help = "Specific group to inspect")]
    pub group: Option<String>,
}

#[derive(Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct ImportArgs {
    #[arg(help = "Positional group names to import")]
    pub groups: Vec<String>,

    #[arg(short, long, help = "Group name flag to import")]
    pub group: Option<String>,

    #[arg(short, long, help = "Force overwrite repository files")]
    pub force: bool,

    #[arg(long, help = "Simulate import without modifying repository")]
    pub dry_run: bool,
}

impl ImportArgs {
    pub fn resolved_groups(&self) -> Vec<String> {
        let mut list = self.groups.clone();
        if let Some(ref g) = self.group
            && !list.contains(g)
        {
            list.push(g.clone());
        }
        list
    }
}

#[derive(Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct ExportArgs {
    #[arg(help = "Positional group names to export")]
    pub groups: Vec<String>,

    #[arg(short, long, help = "Group name flag to export")]
    pub group: Option<String>,

    #[arg(short, long, help = "Force overwrite conflicting OS files")]
    pub force: bool,

    #[arg(long, help = "Simulate export without modifying OS files")]
    pub dry_run: bool,
}

impl ExportArgs {
    pub fn resolved_groups(&self) -> Vec<String> {
        let mut list = self.groups.clone();
        if let Some(ref g) = self.group
            && !list.contains(g)
        {
            list.push(g.clone());
        }
        list
    }
}

#[derive(Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct TidyArgs {
    #[arg(help = "Positional group names to tidy")]
    pub groups: Vec<String>,

    #[arg(short, long, help = "Group name flag to tidy")]
    pub group: Option<String>,

    #[arg(long, help = "Permanently delete orphaned files from OS filesystem")]
    pub purge: bool,

    #[arg(long, help = "Simulate tidy operations without modifying files")]
    pub dry_run: bool,
}

impl TidyArgs {
    pub fn resolved_groups(&self) -> Vec<String> {
        let mut list = self.groups.clone();
        if let Some(ref g) = self.group
            && !list.contains(g)
        {
            list.push(g.clone());
        }
        list
    }
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum VaultCommand {
    /// Initialize vault slots and generate 12-word recovery mnemonic
    Init(VaultInitArgs),

    /// Rotate vault password slot using current credentials
    Passwd(VaultPasswdArgs),

    /// Recover vault using 12-word mnemonic and issue new recovery mnemonic
    Recover(VaultRecoverArgs),
}

#[derive(Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct VaultInitArgs {
    #[arg(long = "password-stdin", help = "Read passphrase from standard input")]
    pub password_stdin: bool,
}

#[derive(Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct VaultPasswdArgs {
    #[arg(
        long = "password-stdin",
        help = "Read new passphrase from standard input"
    )]
    pub password_stdin: bool,
}

#[derive(Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct VaultRecoverArgs {
    #[arg(long, help = "12-word recovery mnemonic phrase")]
    pub mnemonic: Option<String>,

    #[arg(
        long = "password-stdin",
        help = "Read new passphrase from standard input"
    )]
    pub password_stdin: bool,
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum KeyCommand {
    /// Store default passphrase in OS keyring
    Set(KeySetArgs),

    /// Delete default passphrase from OS keyring
    Del(KeyDelArgs),
}

#[derive(Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct KeySetArgs {
    #[arg(long = "password-stdin", help = "Read passphrase from standard input")]
    pub password_stdin: bool,
}

#[derive(Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct KeyDelArgs {}

#[derive(Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct AiArgs {}

#[derive(Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct McpArgs {}

#[derive(Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct UpdateArgs {
    #[arg(long, help = "Check for updates without modifying repository")]
    pub check: bool,
}

/// Dispatches parsed CLI commands to domain workflows under lock protection.
pub fn dispatch<W1: Write, W2: Write>(
    cli: &Cli,
    is_interactive: bool,
    stdout: &mut W1,
    _stderr: &mut W2,
) -> Result<i32, EngineError> {
    // MCP runs in stateless idle mode and manages dotler.lock internally per tool execution
    if let Command::Mcp(_) = &cli.command {
        return match crate::agent::mcp::run_mcp_server(std::io::stdin().lock(), stdout) {
            Ok(()) => Ok(EXIT_SUCCESS),
            Err(e) => Err(EngineError::Io(std::io::Error::other(e.to_string()))),
        };
    }

    // Acquire single exclusive dotler.lock for all standard CLI commands
    let lock_path = expand_tilde(DOTLER_LOCK_PATH);
    if let Some(parent) = lock_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let lock = DotlerLock::new(lock_path);
    let lock_guard = lock.acquire(
        Duration::from_millis(DOTLER_LOCK_TIMEOUT_MS),
        Duration::from_millis(DOTLER_LOCK_POLL_INTERVAL_MS),
    )?;

    match &cli.command {
        Command::Init(args) => handle_init(args, cli, stdout, &lock_guard),
        Command::Git { command } => handle_git(command, cli, stdout, &lock_guard),
        Command::Check(args) => handle_check(args, cli, stdout, &lock_guard),
        Command::Status(args) => handle_status(args, cli, is_interactive, stdout, &lock_guard),
        Command::Import(args) => handle_import(args, cli, is_interactive, stdout, &lock_guard),
        Command::Export(args) => handle_export(args, cli, is_interactive, stdout, &lock_guard),
        Command::Tidy(args) => handle_tidy(args, cli, is_interactive, stdout, &lock_guard),
        Command::Vault { command } => {
            handle_vault(command, cli, is_interactive, stdout, &lock_guard)
        }
        Command::Key { command } => handle_key(command, cli, is_interactive, stdout, &lock_guard),
        Command::Ai(_) => handle_ai(cli, stdout, &lock_guard),
        Command::Update(args) => handle_update(args, cli, stdout, &lock_guard),
        Command::Mcp(_) => unreachable!(),
    }
}

fn handle_init<W: Write>(
    args: &InitArgs,
    cli: &Cli,
    stdout: &mut W,
    _lock: &DotlerLockGuard,
) -> Result<i32, EngineError> {
    let repo_dir = match &args.repo_path {
        Some(p) => p.clone(),
        None => std::env::current_dir()?,
    };

    fs::create_dir_all(&repo_dir)?;

    let dotler_toml_path = repo_dir.join("dotler.toml");
    if !dotler_toml_path.exists() {
        let initial_toml = r#"[shell]
path = "~"
files = """
*
"""
"#;
        atomic_write_file(&dotler_toml_path, initial_toml.as_bytes())?;
    }

    let skill_path = scaffold_skill_md(&repo_dir)
        .map_err(|e| EngineError::Io(std::io::Error::other(e.to_string())))?;

    // Register in ~/.config/dotler/config.toml
    let local_cfg_path = expand_tilde("~/.config/dotler/config.toml");
    let mut local_cfg = if local_cfg_path.is_file() {
        LocalConfig::load(&local_cfg_path).unwrap_or_default()
    } else {
        LocalConfig::default()
    };

    let label = args
        .label
        .clone()
        .or_else(|| cli.repo.clone())
        .unwrap_or_else(|| {
            repo_dir
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "default".to_string())
        });

    let device = args
        .device
        .clone()
        .or_else(|| cli.device.clone())
        .unwrap_or_else(|| "default".to_string());

    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("~"));
    let repo_path_entry = if let Ok(rel) = repo_dir.strip_prefix(&home) {
        if rel.as_os_str().is_empty() {
            "~".to_string()
        } else {
            format!("~/{}", rel.display())
        }
    } else {
        format!(
            "~/{}",
            repo_dir
                .file_name()
                .map(|f| f.to_string_lossy())
                .unwrap_or_default()
        )
    };

    if local_cfg.default_repo.is_none() {
        local_cfg.default_repo = Some(label.clone());
    }
    local_cfg.repos.insert(label.clone(), repo_path_entry);

    if !local_cfg.default_devices.contains(&device) {
        local_cfg.default_devices.push(device.clone());
    }

    local_cfg.save_atomic(&local_cfg_path)?;

    let data = json!({
        "label": label,
        "device": device,
        "repo_path": repo_dir.display().to_string(),
        "skill_path": skill_path.display().to_string(),
    });

    Ok(render_success_to(stdout, "init", &data, cli.json))
}

fn handle_git<W: Write>(
    cmd: &GitCommand,
    cli: &Cli,
    stdout: &mut W,
    lock: &DotlerLockGuard,
) -> Result<i32, EngineError> {
    match cmd {
        GitCommand::Ls(args) => {
            let parsed_url = parse_url(&args.url)?;
            let summary = list_remote(&parsed_url, args.branch.as_deref(), lock)?;
            Ok(render_success_to(stdout, "git ls", &summary, cli.json))
        }
        GitCommand::Clone(args) => {
            let parsed_url = parse_url(&args.url)?;
            let selectors: Vec<GroupSelector> = args
                .groups
                .iter()
                .map(|s| GroupSelector::parse(s))
                .collect();

            let repo_name = parsed_url
                .clone_url
                .trim_end_matches('/')
                .trim_end_matches(".git")
                .rsplit('/')
                .next()
                .unwrap_or("dotfiles");
            let dest = std::env::current_dir()?.join(repo_name);
            let cfg_path = expand_tilde("~/.config/dotler/config.toml");

            let report = clone_repo(
                &parsed_url,
                &selectors,
                args.branch.as_deref(),
                &dest,
                Some(&cfg_path),
                None,
                None,
                lock,
            )?;
            Ok(render_success_to(stdout, "git clone", &report, cli.json))
        }
        GitCommand::Install(args) => {
            let parsed_url = parse_url(&args.url)?;
            let state_db_path = expand_tilde(STATE_DB_PATH);
            if let Some(parent) = state_db_path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let state = StateDb::open(&state_db_path)?;
            let override_path = args.path.first().map(Path::new);

            let local_cfg_path = expand_tilde("~/.config/dotler/config.toml");
            let local_cfg = if local_cfg_path.is_file() {
                LocalConfig::load(&local_cfg_path)?
            } else {
                LocalConfig::default()
            };
            let mut devices = local_cfg.default_devices;
            if let Some(ref d) = args.device.as_deref().or(cli.device.as_deref()) {
                devices.insert(0, d.to_string());
            }

            let report = install_remote(
                &parsed_url,
                &args.groups,
                override_path,
                args.branch.as_deref(),
                &devices,
                &state,
                lock,
            )?;
            Ok(render_success_to(stdout, "git install", &report, cli.json))
        }
        GitCommand::Uninstall(args) => {
            let state_db_path = expand_tilde(STATE_DB_PATH);
            if let Some(parent) = state_db_path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let state = StateDb::open(&state_db_path)?;
            let report = uninstall_remote(&args.groups, &state, lock, args.dry_run || cli.dry_run)?;
            Ok(render_success_to(
                stdout,
                "git uninstall",
                &report,
                cli.json,
            ))
        }
    }
}

fn handle_check<W: Write>(
    args: &CheckArgs,
    cli: &Cli,
    stdout: &mut W,
    _lock: &DotlerLockGuard,
) -> Result<i32, EngineError> {
    let local_cfg_path = expand_tilde("~/.config/dotler/config.toml");
    let local_cfg = if local_cfg_path.is_file() {
        LocalConfig::load(&local_cfg_path)?
    } else {
        LocalConfig::default()
    };

    let (_label, repo_path) = resolve_repo_path(&local_cfg, cli.repo.as_deref())?;
    let manifest_path = repo_path.join("dotler.toml");
    let repo_cfg = RepoConfig::load(&manifest_path)?;

    if let Some(ref filter_grp) = args.group
        && !repo_cfg.groups.contains_key(filter_grp)
    {
        let available = repo_cfg.groups.keys().cloned().collect();
        return Err(EngineError::GroupNotFound {
            group: filter_grp.clone(),
            available,
        });
    }

    // Path security check
    for (g_name, g_cfg) in &repo_cfg.groups {
        if let Some(ref filter) = args.group
            && filter != g_name
        {
            continue;
        }
        for p in g_cfg.paths.values() {
            validate_path_security(p)?;
        }
        parse_selection_rules(&g_cfg.files)?;
    }

    // Cross-group collision detection
    let os_info = OsInfo::detect();
    let devices = if let Some(ref d) = cli.device {
        vec![d.clone()]
    } else {
        local_cfg.default_devices.clone()
    };
    repo_cfg.detect_cross_group_collisions(&devices, &os_info)?;

    // Check repository files for encryption mismatch
    for (g_name, g_cfg) in &repo_cfg.groups {
        if let Some(ref filter) = args.group
            && filter != g_name
        {
            continue;
        }
        let group_repo_dir = repo_path.join(g_name);
        if !group_repo_dir.is_dir() {
            continue;
        }
        let rules = parse_selection_rules(&g_cfg.files)?;
        for entry in walkdir::WalkDir::new(&group_repo_dir)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file() {
                let file_name = entry.file_name().to_string_lossy();
                if file_name.starts_with(crate::engine::sync::TMP_FILE_PREFIX)
                    || file_name == ".git"
                {
                    continue;
                }
                if let Ok(rel) = entry.path().strip_prefix(&group_repo_dir) {
                    let rel_str = rel.to_string_lossy();
                    if rel_str.split('/').any(|s| s == ".git") {
                        continue;
                    }
                    let (clean_rel, is_enc_file) =
                        if let Some(stripped) = rel_str.strip_suffix(".enc") {
                            (stripped.to_string(), true)
                        } else {
                            (rel_str.to_string(), false)
                        };
                    if let Some(mode) = crate::config::repo::evaluate_selection(&rules, &clean_rel)
                    {
                        match mode {
                            SelectionMode::EncryptedInclude if !is_enc_file => {
                                return Err(EngineError::EncryptionMismatch {
                                    path: entry.path().to_path_buf(),
                                    reason: format!(
                                        "Repository file '{}' format conflicts with encryption rule in dotler.toml. Run 'dotler tidy' to reconcile format.",
                                        clean_rel
                                    ),
                                });
                            }
                            SelectionMode::PlaintextInclude if is_enc_file => {
                                return Err(EngineError::EncryptionMismatch {
                                    path: entry.path().to_path_buf(),
                                    reason: format!(
                                        "Repository file '{}' format conflicts with encryption rule in dotler.toml. Run 'dotler tidy' to reconcile format.",
                                        clean_rel
                                    ),
                                });
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    let data = json!({
        "status": "valid",
        "groups_checked": repo_cfg.groups.len(),
    });
    Ok(render_success_to(stdout, "check", &data, cli.json))
}

fn handle_status<W: Write>(
    args: &StatusArgs,
    cli: &Cli,
    is_interactive: bool,
    stdout: &mut W,
    lock: &DotlerLockGuard,
) -> Result<i32, EngineError> {
    let local_cfg_path = expand_tilde("~/.config/dotler/config.toml");
    let local_cfg = if local_cfg_path.is_file() {
        LocalConfig::load(&local_cfg_path)?
    } else {
        LocalConfig::default()
    };

    let (label, repo_path) = resolve_repo_path(&local_cfg, cli.repo.as_deref())?;
    let manifest_path = repo_path.join("dotler.toml");
    let repo_cfg = RepoConfig::load(&manifest_path)?;

    let state_db_path = expand_tilde(STATE_DB_PATH);
    if let Some(parent) = state_db_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let state_db = StateDb::open(&state_db_path)?;

    let has_enc = has_encrypted_rules(&repo_cfg) || has_encrypted_repo_files(&repo_path, &repo_cfg);
    let vault_key = unlock_vault_if_needed(&repo_cfg, is_interactive, has_enc && is_interactive)?;
    let os_info = OsInfo::detect();

    let mut devices = local_cfg.default_devices.clone();
    if let Some(ref d) = cli.device {
        devices.insert(0, d.clone());
    }

    let sync_engine = SyncEngine::new(
        &label,
        &repo_path,
        &repo_cfg,
        &state_db,
        devices,
        os_info,
        vault_key.as_ref(),
    );

    let plans = plan(&sync_engine, args.group.as_deref(), lock)?;

    Ok(render_success_to(stdout, "status", &plans, cli.json))
}

fn handle_import<W: Write>(
    args: &ImportArgs,
    cli: &Cli,
    is_interactive: bool,
    stdout: &mut W,
    lock: &DotlerLockGuard,
) -> Result<i32, EngineError> {
    let local_cfg_path = expand_tilde("~/.config/dotler/config.toml");
    let local_cfg = if local_cfg_path.is_file() {
        LocalConfig::load(&local_cfg_path)?
    } else {
        LocalConfig::default()
    };

    let (label, repo_path) = resolve_repo_path(&local_cfg, cli.repo.as_deref())?;
    let manifest_path = repo_path.join("dotler.toml");
    let repo_cfg = RepoConfig::load(&manifest_path)?;

    let state_db_path = expand_tilde(STATE_DB_PATH);
    if let Some(parent) = state_db_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let state_db = StateDb::open(&state_db_path)?;

    let needs_vault = has_encrypted_rules(&repo_cfg);
    let vault_key = unlock_vault_if_needed(&repo_cfg, is_interactive, needs_vault)?;
    let os_info = OsInfo::detect();

    let mut devices = local_cfg.default_devices.clone();
    if let Some(ref d) = cli.device {
        devices.insert(0, d.clone());
    }

    let sync_engine = SyncEngine::new(
        &label,
        &repo_path,
        &repo_cfg,
        &state_db,
        devices,
        os_info,
        vault_key.as_ref(),
    );

    let groups = args.resolved_groups();

    let mut plans = Vec::new();
    if groups.is_empty() {
        plans = plan(&sync_engine, None, lock)?;
    } else {
        for g in &groups {
            let mut p = plan(&sync_engine, Some(g), lock)?;
            plans.append(&mut p);
        }
    }

    let dry_run = args.dry_run || cli.dry_run;
    let report = import_files(&sync_engine, &plans, lock, dry_run)?;
    Ok(render_success_to(stdout, "import", &report, cli.json))
}

fn handle_export<W: Write>(
    args: &ExportArgs,
    cli: &Cli,
    is_interactive: bool,
    stdout: &mut W,
    lock: &DotlerLockGuard,
) -> Result<i32, EngineError> {
    let local_cfg_path = expand_tilde("~/.config/dotler/config.toml");
    let local_cfg = if local_cfg_path.is_file() {
        LocalConfig::load(&local_cfg_path)?
    } else {
        LocalConfig::default()
    };

    let (label, repo_path) = resolve_repo_path(&local_cfg, cli.repo.as_deref())?;
    let manifest_path = repo_path.join("dotler.toml");
    let repo_cfg = RepoConfig::load(&manifest_path)?;

    let state_db_path = expand_tilde(STATE_DB_PATH);
    if let Some(parent) = state_db_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let state_db = StateDb::open(&state_db_path)?;

    let needs_vault = has_encrypted_rules(&repo_cfg);
    let vault_key = unlock_vault_if_needed(&repo_cfg, is_interactive, needs_vault)?;
    let os_info = OsInfo::detect();

    let mut devices = local_cfg.default_devices.clone();
    if let Some(ref d) = cli.device {
        devices.insert(0, d.clone());
    }

    let sync_engine = SyncEngine::new(
        &label,
        &repo_path,
        &repo_cfg,
        &state_db,
        devices,
        os_info,
        vault_key.as_ref(),
    );

    let groups = args.resolved_groups();

    let mut plans = Vec::new();
    if groups.is_empty() {
        plans = plan(&sync_engine, None, lock)?;
    } else {
        for g in &groups {
            let mut p = plan(&sync_engine, Some(g), lock)?;
            plans.append(&mut p);
        }
    }

    for p in &plans {
        if p.status == FileSyncStatus::EncryptionMismatch {
            return Err(EngineError::EncryptionMismatch {
                path: p.repo_file_path.clone(),
                reason: format!(
                    "Repository file '{}' format conflicts with encryption rule in dotler.toml. Run 'dotler tidy' to reconcile format.",
                    p.relative_path
                ),
            });
        }
    }

    let dry_run = args.dry_run || cli.dry_run;
    let report = export_files(&sync_engine, &plans, lock, args.force, dry_run)?;
    Ok(render_success_to(stdout, "export", &report, cli.json))
}

fn handle_tidy<W: Write>(
    args: &TidyArgs,
    cli: &Cli,
    is_interactive: bool,
    stdout: &mut W,
    lock: &DotlerLockGuard,
) -> Result<i32, EngineError> {
    let local_cfg_path = expand_tilde("~/.config/dotler/config.toml");
    let local_cfg = if local_cfg_path.is_file() {
        LocalConfig::load(&local_cfg_path)?
    } else {
        LocalConfig::default()
    };

    let (label, repo_path) = resolve_repo_path(&local_cfg, cli.repo.as_deref())?;
    let manifest_path = repo_path.join("dotler.toml");
    let repo_cfg = RepoConfig::load(&manifest_path)?;

    let state_db_path = expand_tilde(STATE_DB_PATH);
    if let Some(parent) = state_db_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let state_db = StateDb::open(&state_db_path)?;

    let needs_vault =
        has_encrypted_rules(&repo_cfg) || has_encrypted_repo_files(&repo_path, &repo_cfg);
    let vault_key = unlock_vault_if_needed(&repo_cfg, is_interactive, needs_vault)?;
    let os_info = OsInfo::detect();

    let mut devices = local_cfg.default_devices.clone();
    if let Some(ref d) = cli.device {
        devices.insert(0, d.clone());
    }

    let sync_engine = SyncEngine::new(
        &label,
        &repo_path,
        &repo_cfg,
        &state_db,
        devices,
        os_info,
        vault_key.as_ref(),
    );

    let groups = args.resolved_groups();

    let policy = if args.purge {
        TidyOrphanPolicy::PurgeFromOs
    } else {
        TidyOrphanPolicy::KeepOnOs
    };

    let dry_run = args.dry_run || cli.dry_run;
    let report = tidy_groups(&sync_engine, &groups, lock, policy, dry_run)?;
    Ok(render_success_to(stdout, "tidy", &report, cli.json))
}

fn handle_vault<W: Write>(
    cmd: &VaultCommand,
    cli: &Cli,
    is_interactive: bool,
    stdout: &mut W,
    _lock: &DotlerLockGuard,
) -> Result<i32, EngineError> {
    let local_cfg_path = expand_tilde("~/.config/dotler/config.toml");
    let local_cfg = if local_cfg_path.is_file() {
        LocalConfig::load(&local_cfg_path)?
    } else {
        LocalConfig::default()
    };

    match cmd {
        VaultCommand::Init(args) => {
            let (_label, repo_path) = resolve_repo_path(&local_cfg, cli.repo.as_deref())?;
            let manifest_path = repo_path.join("dotler.toml");
            let repo_cfg = RepoConfig::load(&manifest_path)?;

            if repo_cfg.vault.is_some() {
                return Err(EngineError::Config(crate::config::ConfigError::UnknownField {
                    field: "vault".to_string(),
                    hint: "Vault is already initialized in dotler.toml. Use 'dotler vault passwd' to change password.".to_string(),
                }));
            }
            let pass = read_new_passphrase(
                args.password_stdin,
                true,
                is_interactive,
                "Enter new vault passphrase: ",
            )?;
            let (vault_cfg, _vault_key, mnemonic) = init_vault(&pass)?;

            // Update dotler.toml atomically
            let mut manifest_str = fs::read_to_string(&manifest_path)?;
            manifest_str.push_str(&format!(
                "\n[vault]\nvault_id = \"{}\"\npassword_slot = \"{}\"\nrecovery_slot = \"{}\"\n",
                vault_cfg.vault_id, vault_cfg.password_slot, vault_cfg.recovery_slot
            ));
            atomic_write_file(&manifest_path, manifest_str.as_bytes())?;

            // Attempt to store in keyring
            let _ = OsKeyring::set(&pass);

            let data = json!({
                "vault_id": vault_cfg.vault_id,
                "mnemonic": mnemonic.phrase(),
            });
            Ok(render_success_to(stdout, "vault init", &data, cli.json))
        }

        VaultCommand::Passwd(args) => {
            let data = rotate_vault_passphrases(
                &local_cfg,
                cli.repo.as_deref(),
                args.password_stdin,
                is_interactive,
            )?;
            Ok(render_success_to(stdout, "vault passwd", &data, cli.json))
        }

        VaultCommand::Recover(args) => {
            let (_label, repo_path) = resolve_repo_path(&local_cfg, cli.repo.as_deref())?;
            let manifest_path = repo_path.join("dotler.toml");
            let repo_cfg = RepoConfig::load(&manifest_path)?;

            let vault_cfg = repo_cfg
                .vault
                .as_ref()
                .ok_or_else(|| EngineError::VaultLocked {
                    reason: "Vault is not configured".to_string(),
                })?;
            let mnemonic_phrase = if let Some(ref m) = args.mnemonic {
                SecretString::new(m.clone())
            } else {
                read_new_passphrase(
                    false,
                    false,
                    is_interactive,
                    "Enter 12-word recovery mnemonic: ",
                )?
            };
            let new_pass = read_new_passphrase(
                args.password_stdin,
                true,
                is_interactive,
                "Enter new vault passphrase: ",
            )?;

            let (new_cfg, new_mnemonic) = recover_vault(vault_cfg, &mnemonic_phrase, &new_pass)?;

            let manifest_str = fs::read_to_string(&manifest_path)?;
            let mut updated = manifest_str.replace(
                &format!("password_slot = \"{}\"", vault_cfg.password_slot),
                &format!("password_slot = \"{}\"", new_cfg.password_slot),
            );
            updated = updated.replace(
                &format!("recovery_slot = \"{}\"", vault_cfg.recovery_slot),
                &format!("recovery_slot = \"{}\"", new_cfg.recovery_slot),
            );
            atomic_write_file(&manifest_path, updated.as_bytes())?;
            let _ = OsKeyring::set(&new_pass);

            let data = json!({
                "vault_id": new_cfg.vault_id,
                "status": "recovered",
                "new_mnemonic": new_mnemonic.phrase(),
            });
            Ok(render_success_to(stdout, "vault recover", &data, cli.json))
        }
    }
}

fn handle_key<W: Write>(
    cmd: &KeyCommand,
    cli: &Cli,
    is_interactive: bool,
    stdout: &mut W,
    _lock: &DotlerLockGuard,
) -> Result<i32, EngineError> {
    match cmd {
        KeyCommand::Set(args) => {
            let pass = read_new_passphrase(
                args.password_stdin,
                true,
                is_interactive,
                "Enter vault passphrase to store in keyring: ",
            )?;
            OsKeyring::set(&pass)
                .map_err(|e| EngineError::Crypto(crate::crypto::CryptoError::Keyring(e)))?;
            let data = json!({ "status": "keyring_updated" });
            Ok(render_success_to(stdout, "key set", &data, cli.json))
        }
        KeyCommand::Del(_) => {
            OsKeyring::delete()
                .map_err(|e| EngineError::Crypto(crate::crypto::CryptoError::Keyring(e)))?;
            let data = json!({ "status": "keyring_deleted" });
            Ok(render_success_to(stdout, "key del", &data, cli.json))
        }
    }
}

fn handle_ai<W: Write>(
    cli: &Cli,
    stdout: &mut W,
    _lock: &DotlerLockGuard,
) -> Result<i32, EngineError> {
    let local_cfg_path = expand_tilde("~/.config/dotler/config.toml");
    let local_cfg = if local_cfg_path.is_file() {
        LocalConfig::load(&local_cfg_path).unwrap_or_default()
    } else {
        LocalConfig::default()
    };
    let os_info = OsInfo::detect();
    let keyring_ready = OsKeyring::get().map(|opt| opt.is_some()).unwrap_or(false);

    let briefing_markdown = render_briefing(&local_cfg, &os_info, keyring_ready);
    Ok(render_success_to(
        stdout,
        "ai",
        &briefing_markdown,
        cli.json,
    ))
}

fn handle_update<W: Write>(
    args: &UpdateArgs,
    cli: &Cli,
    stdout: &mut W,
    _lock: &DotlerLockGuard,
) -> Result<i32, EngineError> {
    let data = json!({
        "status": "up_to_date",
        "check_only": args.check,
        "version": env!("CARGO_PKG_VERSION"),
    });
    Ok(render_success_to(stdout, "update", &data, cli.json))
}

fn resolve_repo_path(
    local_cfg: &LocalConfig,
    requested_label: Option<&str>,
) -> Result<(String, PathBuf), EngineError> {
    if requested_label.is_none() {
        let current_dir = std::env::current_dir()?;
        if current_dir.join("dotler.toml").is_file() {
            let label = current_dir
                .file_name()
                .map(|f| f.to_string_lossy().to_string())
                .unwrap_or_else(|| "default".to_string());
            return Ok((label, current_dir));
        }
    }

    local_cfg
        .resolve_repo(requested_label)
        .map_err(EngineError::Config)
}

fn rotate_vault_passphrases(
    local_cfg: &LocalConfig,
    requested_label: Option<&str>,
    password_stdin: bool,
    is_interactive: bool,
) -> Result<serde_json::Value, EngineError> {
    let mut candidates: Vec<(String, PathBuf)> = Vec::new();
    let explicit_repo = requested_label.is_some();

    if let Some(label) = requested_label {
        let (resolved_label, path) = local_cfg
            .resolve_repo(Some(label))
            .map_err(EngineError::Config)?;
        candidates.push((resolved_label, path));
    } else {
        for (label, raw_path) in &local_cfg.repos {
            candidates.push((label.clone(), expand_tilde(raw_path)));
        }

        if let Ok(current_dir) = std::env::current_dir()
            && current_dir.join("dotler.toml").is_file()
        {
            let canon_cwd = fs::canonicalize(&current_dir).unwrap_or_else(|_| current_dir.clone());
            let already_listed = candidates
                .iter()
                .any(|(_, p)| fs::canonicalize(p).unwrap_or_else(|_| p.clone()) == canon_cwd);
            if !already_listed {
                let cwd_label = current_dir
                    .file_name()
                    .map(|f| f.to_string_lossy().to_string())
                    .unwrap_or_else(|| "current".to_string());
                candidates.push((cwd_label, current_dir));
            }
        }
    }

    if candidates.is_empty() {
        return Err(EngineError::Config(
            crate::config::ConfigError::NoReposConfigured,
        ));
    }

    let mut vault_targets: Vec<(String, PathBuf, crate::config::repo::VaultConfig)> = Vec::new();
    let mut skipped_repos: Vec<String> = Vec::new();

    for (label, repo_path) in candidates {
        let manifest_path = repo_path.join("dotler.toml");
        if !manifest_path.is_file() {
            if explicit_repo {
                return Err(EngineError::Config(
                    crate::config::ConfigError::RepoPathNotFound(repo_path.display().to_string()),
                ));
            }
            skipped_repos.push(label);
            continue;
        }

        let repo_cfg = match RepoConfig::load(&manifest_path) {
            Ok(cfg) => cfg,
            Err(e) if explicit_repo => return Err(EngineError::Config(e)),
            Err(_) => {
                skipped_repos.push(label);
                continue;
            }
        };

        match repo_cfg.vault {
            Some(vault_cfg) => vault_targets.push((label, manifest_path, vault_cfg)),
            None if explicit_repo => {
                return Err(EngineError::VaultLocked {
                    reason: "Vault is not configured".to_string(),
                });
            }
            None => skipped_repos.push(label),
        }
    }

    if vault_targets.is_empty() {
        return Err(EngineError::VaultLocked {
            reason: "Vault is not configured in any registered repository".to_string(),
        });
    }

    let old_pass = resolve_old_passphrase_for_vaults(&vault_targets, is_interactive)?;
    let new_pass = read_new_passphrase(
        password_stdin,
        false,
        is_interactive,
        "Enter new vault passphrase: ",
    )?;

    let mut pending_writes: Vec<(String, PathBuf, String, String)> = Vec::new();
    let mut already_synced_repos: Vec<String> = Vec::new();

    for (label, manifest_path, vault_cfg) in vault_targets {
        match change_password(&vault_cfg, &old_pass, &new_pass) {
            Ok(new_cfg) => {
                let manifest_str = fs::read_to_string(&manifest_path)?;
                let updated_manifest = manifest_str.replace(
                    &format!("password_slot = \"{}\"", vault_cfg.password_slot),
                    &format!("password_slot = \"{}\"", new_cfg.password_slot),
                );
                pending_writes.push((label, manifest_path, updated_manifest, new_cfg.vault_id));
            }
            Err(crate::crypto::vault::VaultError::WeakPassphrase(msg)) => {
                return Err(EngineError::Vault(
                    crate::crypto::vault::VaultError::WeakPassphrase(msg),
                ));
            }
            Err(crate::crypto::vault::VaultError::InvalidSecret) => {
                if let Ok(slot) = VaultSlot::from_base64(&vault_cfg.password_slot)
                    && slot.unwrap(&new_pass, Some(&vault_cfg.vault_id)).is_ok()
                {
                    already_synced_repos.push(label);
                    continue;
                }
                if explicit_repo {
                    return Err(EngineError::Vault(
                        crate::crypto::vault::VaultError::InvalidSecret,
                    ));
                }
                skipped_repos.push(label);
            }
            Err(other) => {
                if explicit_repo {
                    return Err(EngineError::Vault(other));
                }
                skipped_repos.push(label);
            }
        }
    }

    if pending_writes.is_empty() && already_synced_repos.is_empty() {
        return Err(EngineError::Vault(
            crate::crypto::vault::VaultError::InvalidSecret,
        ));
    }

    let mut rotated_repos = Vec::new();
    let mut primary_vault_id: Option<String> = None;

    for (label, manifest_path, updated_manifest, vault_id) in pending_writes {
        atomic_write_file(&manifest_path, updated_manifest.as_bytes())?;
        if primary_vault_id.is_none() {
            primary_vault_id = Some(vault_id);
        }
        rotated_repos.push(label);
    }

    let keyring_updated = OsKeyring::set(&new_pass).is_ok();
    skipped_repos.sort();

    let mut data = json!({
        "status": "password_rotated",
        "rotated_repos": rotated_repos,
        "skipped_repos": skipped_repos,
        "keyring_updated": keyring_updated,
    });
    if !already_synced_repos.is_empty() {
        data["already_synced_repos"] = json!(already_synced_repos);
    }
    if let Some(vid) = primary_vault_id {
        data["vault_id"] = json!(vid);
    }
    Ok(data)
}

fn resolve_old_passphrase_for_vaults(
    vault_targets: &[(String, PathBuf, crate::config::repo::VaultConfig)],
    is_interactive: bool,
) -> Result<SecretString, EngineError> {
    let matches_any = |candidate: &SecretString| -> bool {
        vault_targets.iter().any(|(_, _, vcfg)| {
            VaultSlot::from_base64(&vcfg.password_slot)
                .ok()
                .and_then(|slot| slot.unwrap(candidate, Some(&vcfg.vault_id)).ok())
                .is_some()
        })
    };

    if let Ok(env_pass) = std::env::var(crate::crypto::keyring::PASSPHRASE_ENV_VAR) {
        let trimmed = env_pass.trim_end_matches(['\r', '\n']);
        if !trimmed.is_empty() {
            let secret = SecretString::new(trimmed.to_string());
            if matches_any(&secret) || !is_interactive {
                return Ok(secret);
            }
        }
    }

    if let Ok(Some(sec)) = OsKeyring::get()
        && matches_any(&sec)
    {
        return Ok(sec);
    }

    if !is_interactive {
        return Err(EngineError::Crypto(crate::crypto::CryptoError::Keyring(
            crate::crypto::keyring::KeyringError::PassphraseRequiredInNonInteractiveMode,
        )));
    }

    let resolved = OsKeyring::prompt_passphrase_with_message("Enter current vault passphrase: ")
        .map_err(|e| EngineError::Crypto(crate::crypto::CryptoError::Keyring(e)))?;
    Ok(resolved.secret)
}

fn unlock_vault_if_needed(
    repo_cfg: &RepoConfig,
    is_interactive: bool,
    required: bool,
) -> Result<Option<VaultKey>, EngineError> {
    let Some(vault_cfg) = repo_cfg.vault.as_ref() else {
        if required {
            return Err(EngineError::VaultLocked {
                reason:
                    "Encrypted group cannot be synced without an initialized [vault] in dotler.toml"
                        .to_string(),
            });
        }
        return Ok(None);
    };

    let slot = VaultSlot::from_base64(&vault_cfg.password_slot)?;

    if let Ok(env_pass) = std::env::var(crate::crypto::keyring::PASSPHRASE_ENV_VAR) {
        let trimmed = env_pass.trim_end_matches(['\r', '\n']);
        if !trimmed.is_empty() {
            let secret = SecretString::new(trimmed.to_string());
            match slot.unwrap(&secret, Some(&vault_cfg.vault_id)) {
                Ok(key) => return Ok(Some(key)),
                Err(e) if !is_interactive && required => return Err(EngineError::Vault(e)),
                Err(_) => {}
            }
        }
    }

    let keyring_secret = OsKeyring::get().ok().flatten();
    if let Some(ref sec) = keyring_secret
        && let Ok(key) = slot.unwrap(sec, Some(&vault_cfg.vault_id))
    {
        return Ok(Some(key));
    }

    if !required {
        return Ok(None);
    }

    if !is_interactive {
        return Err(EngineError::Crypto(crate::crypto::CryptoError::Keyring(
            crate::crypto::keyring::KeyringError::PassphraseRequiredInNonInteractiveMode,
        )));
    }

    let resolved = OsKeyring::prompt_passphrase_with_message("Enter dotler vault passphrase: ")
        .map_err(|e| EngineError::Crypto(crate::crypto::CryptoError::Keyring(e)))?;
    let key = slot.unwrap(&resolved.secret, Some(&vault_cfg.vault_id))?;

    if keyring_secret.is_none() {
        let _ = OsKeyring::set(&resolved.secret);
    }

    Ok(Some(key))
}

fn has_encrypted_rules(repo_cfg: &RepoConfig) -> bool {
    for g in repo_cfg.groups.values() {
        if let Ok(rules) = parse_selection_rules(&g.files) {
            for r in rules {
                if r.mode == SelectionMode::EncryptedInclude {
                    return true;
                }
            }
        }
    }
    false
}

fn has_encrypted_repo_files(repo_path: &Path, repo_cfg: &RepoConfig) -> bool {
    for g_name in repo_cfg.groups.keys() {
        let group_dir = repo_path.join(g_name);
        if !group_dir.is_dir() {
            continue;
        }
        for entry in walkdir::WalkDir::new(&group_dir)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file()
                && entry.path().extension().and_then(|s| s.to_str()) == Some("enc")
            {
                return true;
            }
        }
    }
    false
}

fn read_new_passphrase(
    password_stdin: bool,
    allow_env_var: bool,
    is_interactive: bool,
    prompt_msg: &str,
) -> Result<SecretString, EngineError> {
    if password_stdin {
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            return Err(EngineError::Crypto(crate::crypto::CryptoError::Vault(
                crate::crypto::vault::VaultError::WeakPassphrase(
                    "Passphrase cannot be empty".to_string(),
                ),
            )));
        }
        return Ok(SecretString::new(trimmed.to_string()));
    }

    if allow_env_var && let Ok(env_pass) = std::env::var(crate::crypto::keyring::PASSPHRASE_ENV_VAR)
    {
        let trimmed = env_pass.trim_end_matches(['\r', '\n']);
        if !trimmed.is_empty() {
            return Ok(SecretString::new(trimmed.to_string()));
        }
    }

    if !is_interactive {
        return Err(EngineError::Crypto(crate::crypto::CryptoError::Keyring(
            crate::crypto::keyring::KeyringError::PassphraseRequiredInNonInteractiveMode,
        )));
    }

    let resolved = OsKeyring::prompt_passphrase_with_message(prompt_msg)
        .map_err(|e| EngineError::Crypto(crate::crypto::CryptoError::Keyring(e)))?;
    Ok(resolved.secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tidy_purge_and_reject_removed_flags() {
        let default_cli = Cli::try_parse_from(["dotler", "tidy"]).expect("bare tidy must parse");
        match default_cli.command {
            Command::Tidy(args) => assert!(!args.purge),
            other => panic!("Unexpected command: {other:?}"),
        }

        let purge_cli =
            Cli::try_parse_from(["dotler", "tidy", "--purge"]).expect("tidy --purge must parse");
        match purge_cli.command {
            Command::Tidy(args) => assert!(args.purge),
            other => panic!("Unexpected command: {other:?}"),
        }

        assert!(
            Cli::try_parse_from(["dotler", "tidy", "--rm"]).is_err(),
            "Clap must reject removed --rm flag"
        );
        assert!(
            Cli::try_parse_from(["dotler", "tidy", "--keep"]).is_err(),
            "Clap must reject removed --keep flag"
        );
    }

    #[test]
    fn test_parse_12_subcommands_syntax() {
        assert!(Cli::try_parse_from(["dotler", "init"]).is_ok());
        assert!(Cli::try_parse_from(["dotler", "git", "ls", "gh:user/dot"]).is_ok());
        assert!(Cli::try_parse_from(["dotler", "check"]).is_ok());
        assert!(Cli::try_parse_from(["dotler", "status"]).is_ok());
        assert!(Cli::try_parse_from(["dotler", "import"]).is_ok());
        assert!(Cli::try_parse_from(["dotler", "export"]).is_ok());
        assert!(Cli::try_parse_from(["dotler", "tidy"]).is_ok());
        assert!(Cli::try_parse_from(["dotler", "vault", "init"]).is_ok());
        assert!(Cli::try_parse_from(["dotler", "key", "set"]).is_ok());
        assert!(Cli::try_parse_from(["dotler", "ai"]).is_ok());
        assert!(Cli::try_parse_from(["dotler", "mcp"]).is_ok());
        assert!(Cli::try_parse_from(["dotler", "update"]).is_ok());
    }

    #[test]
    fn test_interactive_prompt_unlocks_vault_and_autosaves_to_keyring() {
        use secrecy::ExposeSecret;

        let _guard = crate::crypto::keyring::MOCK_KEYRING_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        OsKeyring::enable_mock();
        OsKeyring::clear_mock();
        unsafe {
            std::env::remove_var(crate::crypto::keyring::PASSPHRASE_ENV_VAR);
        }

        let pass = SecretString::new("interactive-day0-secret".to_string());
        let (vault_cfg, expected_key, _mnemonic) = init_vault(&pass).unwrap();
        let repo_cfg = RepoConfig {
            vault: Some(vault_cfg.clone()),
            ..Default::default()
        };

        // Keyring starts empty; queue interactive prompt reply
        assert!(OsKeyring::get().unwrap().is_none());
        OsKeyring::push_mock_prompt_reply("interactive-day0-secret");

        let unlocked = unlock_vault_if_needed(&repo_cfg, true, true)
            .expect("interactive unlock must succeed")
            .expect("vault key must be returned");
        assert_eq!(unlocked.vault_id(), expected_key.vault_id());

        // Verified passphrase must be auto-saved to OsKeyring on Day 0
        let saved = OsKeyring::get()
            .unwrap()
            .expect("keyring must hold auto-saved secret");
        assert_eq!(saved.expose_secret(), "interactive-day0-secret");

        // Rotating password interactively must prompt for the NEW passphrase rather than reusing keyring
        OsKeyring::push_mock_prompt_reply("rotated-new-secret-999");
        let targets = vec![(
            "primary".to_string(),
            PathBuf::from("/tmp/dummy"),
            vault_cfg.clone(),
        )];
        let resolved_old = resolve_old_passphrase_for_vaults(&targets, true).unwrap();
        assert_eq!(resolved_old.expose_secret(), "interactive-day0-secret");

        let resolved_new =
            read_new_passphrase(false, false, true, "Enter new vault passphrase: ").unwrap();
        assert_eq!(resolved_new.expose_secret(), "rotated-new-secret-999");

        let rotated_cfg = change_password(&vault_cfg, &resolved_old, &resolved_new).unwrap();
        let rotated_slot = VaultSlot::from_base64(&rotated_cfg.password_slot).unwrap();
        assert!(
            rotated_slot
                .unwrap(&resolved_new, Some(&rotated_cfg.vault_id))
                .is_ok()
        );

        OsKeyring::clear_mock();
        OsKeyring::disable_mock();
    }

    #[test]
    fn test_rotate_vault_passphrases_updates_all_matching_repos_and_keyring() {
        use secrecy::ExposeSecret;

        let _guard = crate::crypto::keyring::MOCK_KEYRING_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        OsKeyring::enable_mock();
        OsKeyring::clear_mock();
        unsafe {
            std::env::remove_var(crate::crypto::keyring::PASSPHRASE_ENV_VAR);
        }

        let tmp = tempfile::tempdir().unwrap();
        let repo_a = tmp.path().join("repo_a");
        let repo_b = tmp.path().join("repo_b");
        let repo_other = tmp.path().join("repo_other");
        let repo_plain = tmp.path().join("repo_plain");
        let repo_missing = tmp.path().join("repo_missing");

        for dir in [&repo_a, &repo_b, &repo_other, &repo_plain] {
            fs::create_dir_all(dir.join("shell")).unwrap();
        }

        let old_pass = SecretString::new("shared-old-pass-111".to_string());
        let other_pass = SecretString::new("third-party-pass-222".to_string());

        let (vcfg_a, vkey_a, _) = init_vault(&old_pass).unwrap();
        let (vcfg_b, vkey_b, _) = init_vault(&old_pass).unwrap();
        let (vcfg_other, _, _) = init_vault(&other_pass).unwrap();

        let enc_a = vkey_a.encrypt_file(b"secret-a-payload").unwrap().to_bytes();
        let enc_b = vkey_b.encrypt_file(b"secret-b-payload").unwrap().to_bytes();
        atomic_write_file(&repo_a.join("shell/token.enc"), &enc_a).unwrap();
        atomic_write_file(&repo_b.join("shell/token.enc"), &enc_b).unwrap();

        let write_vault_manifest = |dir: &Path, vcfg: &crate::config::repo::VaultConfig| {
            let content = format!(
                "[shell]\nos-linux = \"~\"\nos-macos = \"~\"\nos-windows = \"~\"\nfiles = \"* encrypt\"\n\n[vault]\nvault_id = \"{}\"\npassword_slot = \"{}\"\nrecovery_slot = \"{}\"\n",
                vcfg.vault_id, vcfg.password_slot, vcfg.recovery_slot
            );
            atomic_write_file(&dir.join("dotler.toml"), content.as_bytes()).unwrap();
        };

        write_vault_manifest(&repo_a, &vcfg_a);
        write_vault_manifest(&repo_b, &vcfg_b);
        write_vault_manifest(&repo_other, &vcfg_other);
        atomic_write_file(
            &repo_plain.join("dotler.toml"),
            b"[shell]\nos-linux = \"~\"\nos-macos = \"~\"\nos-windows = \"~\"\nfiles = \"*\"\n",
        )
        .unwrap();

        let mut local_cfg = LocalConfig::default();
        local_cfg
            .repos
            .insert("repo_a".to_string(), repo_a.to_string_lossy().to_string());
        local_cfg
            .repos
            .insert("repo_b".to_string(), repo_b.to_string_lossy().to_string());
        local_cfg.repos.insert(
            "repo_other".to_string(),
            repo_other.to_string_lossy().to_string(),
        );
        local_cfg.repos.insert(
            "repo_plain".to_string(),
            repo_plain.to_string_lossy().to_string(),
        );
        local_cfg.repos.insert(
            "repo_missing".to_string(),
            repo_missing.to_string_lossy().to_string(),
        );

        // Wrong old password matching zero vaults must fail without modifying keyring or manifests
        OsKeyring::push_mock_prompt_reply("wrong-old-pass-000");
        OsKeyring::push_mock_prompt_reply("shared-new-pass-999");
        let wrong_res = rotate_vault_passphrases(&local_cfg, None, false, true);
        assert!(wrong_res.is_err());
        assert!(OsKeyring::get().unwrap().is_none());

        // Seed OsKeyring with old_pass, then rotate interactively to shared-new-pass-999
        OsKeyring::set(&old_pass).unwrap();
        OsKeyring::push_mock_prompt_reply("shared-new-pass-999");

        let report = rotate_vault_passphrases(&local_cfg, None, false, true)
            .expect("multi-repo rotation must succeed");

        assert_eq!(report["status"], "password_rotated");
        assert_eq!(report["rotated_repos"], json!(["repo_a", "repo_b"]));
        assert_eq!(
            report["skipped_repos"],
            json!(["repo_missing", "repo_other", "repo_plain"])
        );
        assert_eq!(report["keyring_updated"], true);

        // OsKeyring must now hold the new passphrase
        let keyring_secret = OsKeyring::get().unwrap().unwrap();
        assert_eq!(keyring_secret.expose_secret(), "shared-new-pass-999");

        // Both repo_a and repo_b must unlock with the new passphrase while .enc bytes stay untouched
        for (repo_dir, orig_enc, expected_plain) in [
            (&repo_a, &enc_a, b"secret-a-payload".as_slice()),
            (&repo_b, &enc_b, b"secret-b-payload".as_slice()),
        ] {
            let disk_enc = fs::read(repo_dir.join("shell/token.enc")).unwrap();
            assert_eq!(&disk_enc, orig_enc, ".enc bytes must remain 100% untouched");

            let reloaded = RepoConfig::load(&repo_dir.join("dotler.toml")).unwrap();
            let vcfg = reloaded.vault.unwrap();
            let slot = VaultSlot::from_base64(&vcfg.password_slot).unwrap();
            assert!(slot.unwrap(&old_pass, Some(&vcfg.vault_id)).is_err());
            let unlocked_key = slot.unwrap(&keyring_secret, Some(&vcfg.vault_id)).unwrap();
            let dec = unlocked_key
                .decrypt_file(&crate::crypto::vault::EncryptedFile::from_bytes(&disk_enc).unwrap())
                .unwrap();
            assert_eq!(dec.expose_secret().as_slice(), expected_plain);
        }

        // Third-party repo with different passphrase must remain untouched
        let reloaded_other = RepoConfig::load(&repo_other.join("dotler.toml")).unwrap();
        let other_vcfg = reloaded_other.vault.unwrap();
        assert_eq!(other_vcfg.password_slot, vcfg_other.password_slot);

        OsKeyring::clear_mock();
        OsKeyring::disable_mock();
    }
}
