//! Command-line argument parsing and command dispatch.

use std::io::Write;
use std::path::{Path, PathBuf};

use clap::{Args, Parser, Subcommand};

use crate::agent::briefing::render_briefing;
use crate::cli::output::{
    EXIT_SUCCESS, ExportReport, KeyReport, UpdateReport, VaultInitReport, VaultRecoverReport,
    render_success_to,
};
use crate::config::local::{
    LOCAL_CONFIG_FILE, LocalConfig, expand_tilde, get_local_config, resolve_repo_path_with_cwd,
};
use crate::config::repo::{OsInfo, RepoConfig, get_repo_config};
use crate::config::state::{DOTLER_LOCK_PATH, DotlerLockGuard, get_lock};
use crate::core::context::CoreContext;
use crate::core::vault_loader::{read_new_passphrase, rotate_vault_passphrases};
use crate::crypto::SecretString;
use crate::crypto::keyring::{OsKeyring, get_password};
use crate::crypto::vault::{init_vault, recover_vault};
use crate::engine::EngineError;
use crate::engine::check::{run_check, run_init, run_status};
use crate::engine::observer::{
    CommandObserver, NoopObserver, PlanActionKind, PlanDirection, PlanPreviewEntry,
};
use crate::engine::remote::{
    GroupSelector, run_git_clone, run_git_install, run_git_ls, run_git_uninstall,
};
use crate::engine::sync::{run_export, run_import};
use crate::engine::tidy::{TidyOrphanPolicy, run_tidy};
use crate::tui::confirm::{
    ConfirmError, ConfirmPrompt, DEFAULT_CONFIRM_TITLE, confirm_proceed_to,
};
use crate::tui::preview::{BadgeOp, PreviewArrow, PreviewItem, render_preview_to};
use crate::tui::progress::ProgressReporter;

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
    /// Initialize a dotler repository and register device/repo in config.toml (run 'dotler ai' for AI agent briefing)
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

#[derive(Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct GitCloneArgs {
    #[arg(help = "Remote repository URL or shorthand")]
    pub url: String,

    #[arg(help = "Groups to clone, with optional alias (e.g. nvim:my-nvim)")]
    pub groups: Vec<String>,

    #[arg(short, long, help = "Remote branch name")]
    pub branch: Option<String>,

    #[arg(short, long, help = "Target device profile for group resolution")]
    pub device: Option<String>,

    #[arg(short = 'y', long = "yes", help = "Skip confirmation prompt")]
    pub yes: bool,

    #[arg(short = 'a', long = "all", help = "Show all files in preview")]
    pub all: bool,

    #[arg(long = "dry-run", help = "Simulate clone without writing changes")]
    pub dry_run: bool,
}

#[derive(Args, Debug, Clone, PartialEq, Eq, Default)]
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

    #[arg(short = 'y', long = "yes", help = "Skip confirmation prompt")]
    pub yes: bool,

    #[arg(short = 'a', long = "all", help = "Show all files in preview")]
    pub all: bool,

    #[arg(long = "dry-run", help = "Simulate installation without writing changes")]
    pub dry_run: bool,
}

#[derive(Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct GitUninstallArgs {
    #[arg(help = "Groups to uninstall (all if empty)")]
    pub groups: Vec<String>,

    #[arg(short = 'y', long = "yes", help = "Skip confirmation prompt")]
    pub yes: bool,

    #[arg(short = 'a', long = "all", help = "Show all files in preview")]
    pub all: bool,

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

    #[arg(short = 'y', long = "yes", help = "Skip confirmation prompt")]
    pub yes: bool,

    #[arg(short = 'a', long = "all", help = "Show all files in preview")]
    pub all: bool,

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

    #[arg(short = 'y', long = "yes", help = "Skip confirmation prompt")]
    pub yes: bool,

    #[arg(short = 'a', long = "all", help = "Show all files in preview")]
    pub all: bool,

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

    #[arg(short = 'y', long = "yes", help = "Skip confirmation prompt")]
    pub yes: bool,

    #[arg(short = 'a', long = "all", help = "Show all files in preview")]
    pub all: bool,

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

    #[arg(long, help = "Optional plaintext password hint stored in dotler.toml")]
    pub hint: Option<String>,
}

#[derive(Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct VaultPasswdArgs {
    #[arg(
        long = "password-stdin",
        help = "Read new passphrase from standard input"
    )]
    pub password_stdin: bool,

    #[arg(long, help = "Optional plaintext password hint stored in dotler.toml")]
    pub hint: Option<String>,
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

    #[arg(long, help = "Optional plaintext password hint stored in dotler.toml")]
    pub hint: Option<String>,
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

/// Interactive terminal observer bridging `engine::observer::CommandObserver` with `tui::*`.
struct TuiObserver<'a, W: Write> {
    writer: &'a mut W,
    command_name: &'static str,
    view_all: bool,
    yes: bool,
    is_interactive: bool,
    approved: bool,
    progress: Option<ProgressReporter>,
}

impl<'a, W: Write> TuiObserver<'a, W> {
    fn new(
        writer: &'a mut W,
        command_name: &'static str,
        view_all: bool,
        yes: bool,
        is_interactive: bool,
    ) -> Self {
        Self {
            writer,
            command_name,
            view_all,
            yes,
            is_interactive,
            approved: false,
            progress: None,
        }
    }
}

fn map_badge(kind: PlanActionKind) -> BadgeOp {
    match kind {
        PlanActionKind::Okay => BadgeOp::Okay,
        PlanActionKind::Skip => BadgeOp::Skip,
        PlanActionKind::Create => BadgeOp::Create,
        PlanActionKind::Overwrite => BadgeOp::Overwrite,
        PlanActionKind::Delete => BadgeOp::Delete,
        PlanActionKind::Untrack => BadgeOp::Untrack,
    }
}

fn map_arrow(dir: PlanDirection) -> PreviewArrow {
    match dir {
        PlanDirection::PlainToRepo => PreviewArrow::PlainToRepo,
        PlanDirection::EncryptToRepo => PreviewArrow::EncryptToRepo,
        PlanDirection::PlainToOs => PreviewArrow::PlainToOs,
        PlanDirection::DecryptToOs => PreviewArrow::DecryptToOs,
        PlanDirection::DecryptInRepo => PreviewArrow::DecryptInRepo,
    }
}

impl<W: Write> CommandObserver for TuiObserver<'_, W> {
    fn confirm_plan(
        &mut self,
        entries: &[PlanPreviewEntry],
        dry_run: bool,
    ) -> Result<bool, EngineError> {
        let items: Vec<PreviewItem> = entries
            .iter()
            .map(|e| PreviewItem {
                group_name: e.group_name.clone(),
                os_path: e.os_path.clone(),
                os_op: map_badge(e.os_action),
                repo_path: e.repo_path.clone(),
                repo_op: map_badge(e.repo_action),
                arrow: map_arrow(e.direction),
            })
            .collect();

        let counts = render_preview_to(self.writer, &items, self.view_all)?;
        let total_updates = counts.total_updates();
        if total_updates == 0 || dry_run {
            return Ok(false);
        }

        if self.yes {
            self.approved = true;
            self.progress = Some(ProgressReporter::new(total_updates, true));
            return Ok(true);
        }

        if !self.is_interactive && !ConfirmPrompt::has_mock_or_env_input() {
            return Err(EngineError::NonInteractiveConfirmationRequired {
                command: self.command_name.to_string(),
            });
        }

        let approved = match confirm_proceed_to(self.writer, DEFAULT_CONFIRM_TITLE) {
            Ok(val) => val,
            Err(ConfirmError::NonTtyError) => {
                return Err(EngineError::NonInteractiveConfirmationRequired {
                    command: self.command_name.to_string(),
                });
            }
            Err(ConfirmError::TerminalIoError(e)) => return Err(EngineError::Io(e)),
        };

        if approved {
            self.approved = true;
            self.progress = Some(ProgressReporter::new(total_updates, true));
        }

        Ok(approved)
    }

    fn on_file_progress(
        &mut self,
        group_name: &str,
        group_base_path: &Path,
        relative_path: &str,
        file_size: Option<u64>,
    ) {
        if let Some(ref mut prog) = self.progress {
            let _ = prog.inc_to(
                self.writer,
                group_name,
                group_base_path,
                relative_path,
                file_size,
            );
        }
    }

    fn finish_progress(&mut self) {
        if let Some(ref mut prog) = self.progress {
            let _ = prog.finish_to(self.writer);
        }
    }
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

    // Acquire single exclusive dotler.lock for all standard CLI commands via lazy resource
    let lock_res = get_lock(expand_tilde(DOTLER_LOCK_PATH));
    let lock_guard = lock_res.get()?;

    match &cli.command {
        Command::Init(args) => handle_init(args, cli, is_interactive, stdout, lock_guard),
        Command::Git { command } => handle_git(command, cli, is_interactive, stdout, lock_guard),
        Command::Check(args) => handle_check(args, cli, is_interactive, stdout, lock_guard),
        Command::Status(args) => handle_status(args, cli, is_interactive, stdout, lock_guard),
        Command::Import(args) => handle_import(args, cli, is_interactive, stdout, lock_guard),
        Command::Export(args) => handle_export(args, cli, is_interactive, stdout, lock_guard),
        Command::Tidy(args) => handle_tidy(args, cli, is_interactive, stdout, lock_guard),
        Command::Vault { command } => {
            handle_vault(command, cli, is_interactive, stdout, lock_guard)
        }
        Command::Key { command } => handle_key(command, cli, is_interactive, stdout, lock_guard),
        Command::Ai(_) => handle_ai(cli, stdout, lock_guard),
        Command::Update(args) => handle_update(args, cli, stdout, lock_guard),
        Command::Mcp(_) => unreachable!(),
    }
}

fn handle_init<W: Write>(
    args: &InitArgs,
    cli: &Cli,
    is_interactive: bool,
    stdout: &mut W,
    lock: &DotlerLockGuard,
) -> Result<i32, EngineError> {
    let mut ctx = CoreContext::new(cli.repo.clone(), cli.device.clone(), is_interactive);
    let report = run_init(
        &mut ctx,
        crate::engine::check::InitParams {
            label: args.label.clone(),
            device: args.device.clone(),
            repo_path: args.repo_path.clone(),
        },
        lock,
    )?;
    Ok(render_success_to(stdout, "init", &report, cli.json))
}

fn handle_git<W: Write>(
    cmd: &GitCommand,
    cli: &Cli,
    is_interactive: bool,
    stdout: &mut W,
    lock: &DotlerLockGuard,
) -> Result<i32, EngineError> {
    match cmd {
        GitCommand::Ls(args) => {
            let summary = run_git_ls(&args.url, args.branch.as_deref(), lock)?;
            Ok(render_success_to(stdout, "git ls", &summary, cli.json))
        }
        GitCommand::Clone(args) => {
            let parsed_url = crate::engine::remote::parse_url(&args.url)?;
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
            let cfg_path = expand_tilde(LOCAL_CONFIG_FILE);
            let dry_run = args.dry_run || cli.dry_run;

            if cli.json {
                let mut obs = NoopObserver;
                let report = run_git_clone(
                    &args.url,
                    &selectors,
                    args.branch.as_deref(),
                    &dest,
                    Some(&cfg_path),
                    None,
                    None,
                    lock,
                    dry_run,
                    &mut obs,
                )?;
                Ok(render_success_to(stdout, "git clone", &report, true))
            } else {
                let mut obs =
                    TuiObserver::new(stdout, "git clone", args.all, args.yes, is_interactive);
                let report = run_git_clone(
                    &args.url,
                    &selectors,
                    args.branch.as_deref(),
                    &dest,
                    Some(&cfg_path),
                    None,
                    None,
                    lock,
                    dry_run,
                    &mut obs,
                )?;
                let approved = obs.approved;
                if approved {
                    render_success_to(stdout, "git clone", &report, false);
                }
                Ok(EXIT_SUCCESS)
            }
        }
        GitCommand::Install(args) => {
            let dev_override = args.device.clone().or_else(|| cli.device.clone());
            let ctx = CoreContext::new(cli.repo.clone(), dev_override, is_interactive);
            let override_path = args.path.first().map(Path::new);
            let dry_run = args.dry_run || cli.dry_run;

            if cli.json {
                let mut obs = NoopObserver;
                let report = run_git_install(
                    &ctx,
                    &args.url,
                    &args.groups,
                    override_path,
                    args.branch.as_deref(),
                    lock,
                    dry_run,
                    &mut obs,
                )?;
                Ok(render_success_to(stdout, "git install", &report, true))
            } else {
                let mut obs =
                    TuiObserver::new(stdout, "git install", args.all, args.yes, is_interactive);
                let report = run_git_install(
                    &ctx,
                    &args.url,
                    &args.groups,
                    override_path,
                    args.branch.as_deref(),
                    lock,
                    dry_run,
                    &mut obs,
                )?;
                let approved = obs.approved;
                if approved {
                    render_success_to(stdout, "git install", &report, false);
                }
                Ok(EXIT_SUCCESS)
            }
        }
        GitCommand::Uninstall(args) => {
            let ctx = CoreContext::new(cli.repo.clone(), cli.device.clone(), is_interactive);
            let dry_run = args.dry_run || cli.dry_run;

            if cli.json {
                let mut obs = NoopObserver;
                let report = run_git_uninstall(&ctx, &args.groups, lock, dry_run, &mut obs)?;
                Ok(render_success_to(stdout, "git uninstall", &report, true))
            } else {
                let mut obs =
                    TuiObserver::new(stdout, "git uninstall", args.all, args.yes, is_interactive);
                let report = run_git_uninstall(&ctx, &args.groups, lock, dry_run, &mut obs)?;
                let approved = obs.approved;
                if approved {
                    render_success_to(stdout, "git uninstall", &report, false);
                }
                Ok(EXIT_SUCCESS)
            }
        }
    }
}

fn handle_check<W: Write>(
    args: &CheckArgs,
    cli: &Cli,
    is_interactive: bool,
    stdout: &mut W,
    lock: &DotlerLockGuard,
) -> Result<i32, EngineError> {
    let ctx = CoreContext::new(cli.repo.clone(), cli.device.clone(), is_interactive);
    let report = run_check(&ctx, args.group.as_deref(), lock)?;
    Ok(render_success_to(stdout, "check", &report, cli.json))
}

fn handle_status<W: Write>(
    args: &StatusArgs,
    cli: &Cli,
    is_interactive: bool,
    stdout: &mut W,
    lock: &DotlerLockGuard,
) -> Result<i32, EngineError> {
    let ctx = CoreContext::new(cli.repo.clone(), cli.device.clone(), is_interactive);
    let plans = run_status(&ctx, args.group.as_deref(), lock)?;
    Ok(render_success_to(stdout, "status", &plans, cli.json))
}

fn handle_import<W: Write>(
    args: &ImportArgs,
    cli: &Cli,
    is_interactive: bool,
    stdout: &mut W,
    lock: &DotlerLockGuard,
) -> Result<i32, EngineError> {
    let ctx = CoreContext::new(cli.repo.clone(), cli.device.clone(), is_interactive);
    let groups = args.resolved_groups();
    let dry_run = args.dry_run || cli.dry_run;

    if cli.json {
        let mut obs = NoopObserver;
        let report = run_import(&ctx, &groups, args.force, dry_run, lock, &mut obs)?;
        Ok(render_success_to(stdout, "import", &report, true))
    } else {
        let mut obs = TuiObserver::new(stdout, "import", args.all, args.yes, is_interactive);
        let report = run_import(&ctx, &groups, args.force, dry_run, lock, &mut obs)?;
        let approved = obs.approved;
        if approved {
            render_success_to(stdout, "import", &report, false);
        }
        Ok(EXIT_SUCCESS)
    }
}

fn handle_export<W: Write>(
    args: &ExportArgs,
    cli: &Cli,
    is_interactive: bool,
    stdout: &mut W,
    lock: &DotlerLockGuard,
) -> Result<i32, EngineError> {
    let ctx = CoreContext::new(cli.repo.clone(), cli.device.clone(), is_interactive);
    let groups = args.resolved_groups();
    let dry_run = args.dry_run || cli.dry_run;

    if cli.json {
        let mut obs = NoopObserver;
        let report = run_export(&ctx, &groups, args.force, dry_run, lock, &mut obs)?;
        Ok(render_success_to(stdout, "export", &report, true))
    } else {
        let mut obs = TuiObserver::new(stdout, "export", args.all, args.yes, is_interactive);
        let report = run_export(&ctx, &groups, args.force, dry_run, lock, &mut obs)?;
        let approved = obs.approved;
        if approved {
            let exp_report = ExportReport(report);
            render_success_to(stdout, "export", &exp_report, false);
        }
        Ok(EXIT_SUCCESS)
    }
}

fn handle_tidy<W: Write>(
    args: &TidyArgs,
    cli: &Cli,
    is_interactive: bool,
    stdout: &mut W,
    lock: &DotlerLockGuard,
) -> Result<i32, EngineError> {
    let ctx = CoreContext::new(cli.repo.clone(), cli.device.clone(), is_interactive);
    let groups = args.resolved_groups();
    let policy = if args.purge {
        TidyOrphanPolicy::PurgeFromOs
    } else {
        TidyOrphanPolicy::KeepOnOs
    };
    let dry_run = args.dry_run || cli.dry_run;

    if cli.json {
        let mut obs = NoopObserver;
        let report = run_tidy(&ctx, &groups, policy, dry_run, lock, &mut obs)?;
        Ok(render_success_to(stdout, "tidy", &report, true))
    } else {
        let mut obs = TuiObserver::new(stdout, "tidy", args.all, args.yes, is_interactive);
        let report = run_tidy(&ctx, &groups, policy, dry_run, lock, &mut obs)?;
        let approved = obs.approved;
        if approved {
            render_success_to(stdout, "tidy", &report, false);
        }
        Ok(EXIT_SUCCESS)
    }
}

fn handle_vault<W: Write>(
    cmd: &VaultCommand,
    cli: &Cli,
    is_interactive: bool,
    stdout: &mut W,
    _lock: &DotlerLockGuard,
) -> Result<i32, EngineError> {
    let local_cfg_res = get_local_config(expand_tilde(LOCAL_CONFIG_FILE));
    let local_cfg = local_cfg_res.get()?;

    match cmd {
        VaultCommand::Init(args) => {
            let (_label, repo_path) = resolve_repo_path_with_cwd(local_cfg, cli.repo.as_deref())?;
            let manifest_path = repo_path.join("dotler.toml");
            let mut repo_cfg = RepoConfig::load_without_vault_check(&manifest_path)?;

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
            let (mut vault_cfg, _vault_key, mnemonic) = init_vault(&pass)?;
            vault_cfg.hint = args
                .hint
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string);

            let vault_id = vault_cfg.vault_id.clone();
            let vault_hint = vault_cfg.hint.clone();
            repo_cfg.vault = Some(vault_cfg);

            let mut repo_cfg_res = get_repo_config(manifest_path);
            repo_cfg_res.set(repo_cfg)?;

            let mut password_res = get_password(local_cfg.use_keyring, None, is_interactive, None);
            let _ = password_res.set(pass);

            let data = VaultInitReport {
                vault_id,
                mnemonic: mnemonic.phrase().to_string(),
                hint: vault_hint,
            };
            Ok(render_success_to(stdout, "vault init", &data, cli.json))
        }

        VaultCommand::Passwd(args) => {
            let data = rotate_vault_passphrases(
                local_cfg,
                cli.repo.as_deref(),
                args.password_stdin,
                args.hint.as_deref(),
                is_interactive,
            )?;
            Ok(render_success_to(stdout, "vault passwd", &data, cli.json))
        }

        VaultCommand::Recover(args) => {
            let (_label, repo_path) = resolve_repo_path_with_cwd(local_cfg, cli.repo.as_deref())?;
            let manifest_path = repo_path.join("dotler.toml");
            let mut repo_cfg_res = get_repo_config(manifest_path);
            let mut repo_cfg = repo_cfg_res.get()?.clone();

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

            let (mut new_cfg, new_mnemonic) =
                recover_vault(vault_cfg, &mnemonic_phrase, &new_pass)?;
            if let Some(ref h) = args.hint {
                let trimmed = h.trim();
                new_cfg.hint = if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_string())
                };
            }

            let vault_id = new_cfg.vault_id.clone();
            let vault_hint = new_cfg.hint.clone();
            repo_cfg.vault = Some(new_cfg);
            repo_cfg_res.set(repo_cfg)?;

            let mut password_res = get_password(local_cfg.use_keyring, None, is_interactive, None);
            let _ = password_res.set(new_pass);

            let data = VaultRecoverReport {
                vault_id,
                status: "recovered".to_string(),
                new_mnemonic: new_mnemonic.phrase().to_string(),
                hint: vault_hint,
            };
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
            let mut password_res = get_password(true, None, is_interactive, None);
            password_res
                .set(pass)
                .map_err(|e| EngineError::Crypto(crate::crypto::CryptoError::Keyring(e)))?;
            let data = KeyReport {
                status: "keyring_updated".to_string(),
            };
            Ok(render_success_to(stdout, "key set", &data, cli.json))
        }
        KeyCommand::Del(_) => {
            OsKeyring::delete()
                .map_err(|e| EngineError::Crypto(crate::crypto::CryptoError::Keyring(e)))?;
            let data = KeyReport {
                status: "keyring_deleted".to_string(),
            };
            Ok(render_success_to(stdout, "key del", &data, cli.json))
        }
    }
}

fn handle_ai<W: Write>(
    cli: &Cli,
    stdout: &mut W,
    _lock: &DotlerLockGuard,
) -> Result<i32, EngineError> {
    let local_cfg_res = get_local_config(expand_tilde(LOCAL_CONFIG_FILE));
    let default_cfg = LocalConfig::default();
    let local_cfg = local_cfg_res.get().unwrap_or(&default_cfg);
    let os_info = OsInfo::detect();
    let keyring_ready =
        local_cfg.use_keyring && OsKeyring::get().map(|opt| opt.is_some()).unwrap_or(false);

    let briefing_markdown = render_briefing(local_cfg, &os_info, keyring_ready);
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
    let data = UpdateReport {
        status: "up_to_date".to_string(),
        check_only: args.check,
        version: env!("CARGO_PKG_VERSION").to_string(),
    };
    Ok(render_success_to(stdout, "update", &data, cli.json))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use crate::config::state::write_file_safe;
    use crate::core::vault_loader::{
        resolve_old_passphrase_for_vaults, unlock_vault_if_needed,
    };
    use crate::crypto::vault::{VaultSlot, change_password};

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
    fn test_parse_6_mutating_commands_yes_all_dry_run_flags() {
        let imp = Cli::try_parse_from(["dotler", "import", "-y", "-a", "--dry-run"]).unwrap();
        match imp.command {
            Command::Import(a) => assert!(a.yes && a.all && a.dry_run),
            other => panic!("Unexpected: {other:?}"),
        }

        let exp = Cli::try_parse_from(["dotler", "export", "-y", "-a", "--dry-run", "-f"]).unwrap();
        match exp.command {
            Command::Export(a) => assert!(a.yes && a.all && a.dry_run && a.force),
            other => panic!("Unexpected: {other:?}"),
        }

        let tidy = Cli::try_parse_from(["dotler", "tidy", "-y", "-a", "--dry-run", "--purge"]).unwrap();
        match tidy.command {
            Command::Tidy(a) => assert!(a.yes && a.all && a.dry_run && a.purge),
            other => panic!("Unexpected: {other:?}"),
        }

        let clone = Cli::try_parse_from(["dotler", "git", "clone", "gh:u/r", "-y", "-a", "--dry-run"]).unwrap();
        match clone.command {
            Command::Git { command: GitCommand::Clone(a) } => assert!(a.yes && a.all && a.dry_run),
            other => panic!("Unexpected: {other:?}"),
        }

        let install = Cli::try_parse_from(["dotler", "git", "install", "gh:u/r", "nvim", "-y", "-a", "--dry-run"]).unwrap();
        match install.command {
            Command::Git { command: GitCommand::Install(a) } => assert!(a.yes && a.all && a.dry_run),
            other => panic!("Unexpected: {other:?}"),
        }

        let uninstall = Cli::try_parse_from(["dotler", "git", "uninstall", "-y", "-a", "--dry-run"]).unwrap();
        match uninstall.command {
            Command::Git { command: GitCommand::Uninstall(a) } => assert!(a.yes && a.all && a.dry_run),
            other => panic!("Unexpected: {other:?}"),
        }
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
        use crate::crypto::ExposeSecret;

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

        assert!(OsKeyring::get().unwrap().is_none());
        OsKeyring::push_mock_prompt_reply("interactive-day0-secret");

        let unlocked = unlock_vault_if_needed(&repo_cfg, true, true, true)
            .expect("interactive unlock must succeed")
            .expect("vault key must be returned");
        assert_eq!(unlocked.vault_id(), expected_key.vault_id());

        let saved = OsKeyring::get()
            .unwrap()
            .expect("keyring must hold auto-saved secret");
        assert_eq!(saved.expose_secret(), "interactive-day0-secret");

        OsKeyring::push_mock_prompt_reply("rotated-new-secret-999");
        let targets = vec![(
            "primary".to_string(),
            PathBuf::from("/tmp/dummy"),
            vault_cfg.clone(),
        )];
        let resolved_old = resolve_old_passphrase_for_vaults(&targets, true, true).unwrap();
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
        use crate::crypto::ExposeSecret;

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
        write_file_safe(&repo_a.join("shell/token.enc"), &enc_a).unwrap();
        write_file_safe(&repo_b.join("shell/token.enc"), &enc_b).unwrap();

        let write_vault_manifest = |dir: &Path, vcfg: &crate::config::repo::VaultConfig| {
            let content = format!(
                "[shell]\nos-nux = \"~\"\nos-mac = \"~\"\nos-win = \"~\"\nfiles = \"* encrypt\"\n\n[vault]\nvault_id = \"{}\"\npassword_slot = \"{}\"\nrecovery_slot = \"{}\"\n",
                vcfg.vault_id, vcfg.password_slot, vcfg.recovery_slot
            );
            write_file_safe(&dir.join("dotler.toml"), content.as_bytes()).unwrap();
        };

        write_vault_manifest(&repo_a, &vcfg_a);
        write_vault_manifest(&repo_b, &vcfg_b);
        write_vault_manifest(&repo_other, &vcfg_other);
        write_file_safe(
            &repo_plain.join("dotler.toml"),
            b"[shell]\nos-nux = \"~\"\nos-mac = \"~\"\nos-win = \"~\"\nfiles = \"*\"\n",
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

        OsKeyring::push_mock_prompt_reply("wrong-old-pass-000");
        OsKeyring::push_mock_prompt_reply("shared-new-pass-999");
        let wrong_res = rotate_vault_passphrases(&local_cfg, None, false, None, true);
        assert!(wrong_res.is_err());
        assert!(OsKeyring::get().unwrap().is_none());

        OsKeyring::set(&old_pass).unwrap();
        OsKeyring::push_mock_prompt_reply("shared-new-pass-999");

        let report = rotate_vault_passphrases(&local_cfg, None, false, Some("updated-hint"), true)
            .expect("multi-repo rotation must succeed");

        assert_eq!(report.status, "password_rotated");
        assert_eq!(
            report.rotated_repos,
            vec!["repo_a".to_string(), "repo_b".to_string()]
        );
        assert_eq!(
            report.skipped_repos,
            vec![
                "repo_missing".to_string(),
                "repo_other".to_string(),
                "repo_plain".to_string()
            ]
        );
        assert!(report.keyring_updated);

        let keyring_secret = OsKeyring::get().unwrap().unwrap();
        assert_eq!(keyring_secret.expose_secret(), "shared-new-pass-999");

        for (repo_dir, orig_enc, expected_plain) in [
            (&repo_a, &enc_a, b"secret-a-payload".as_slice()),
            (&repo_b, &enc_b, b"secret-b-payload".as_slice()),
        ] {
            let disk_enc = fs::read(repo_dir.join("shell/token.enc")).unwrap();
            assert_eq!(&disk_enc, orig_enc, ".enc bytes must remain 100% untouched");

            let reloaded = RepoConfig::load(&repo_dir.join("dotler.toml")).unwrap();
            let vcfg = reloaded.vault.unwrap();
            assert_eq!(vcfg.hint.as_deref(), Some("updated-hint"));
            let slot = VaultSlot::from_base64(&vcfg.password_slot).unwrap();
            assert!(slot.unwrap(&old_pass, Some(&vcfg.vault_id)).is_err());
            let unlocked_key = slot.unwrap(&keyring_secret, Some(&vcfg.vault_id)).unwrap();
            let dec = unlocked_key
                .decrypt_file(&crate::crypto::vault::EncryptedFile::from_bytes(&disk_enc).unwrap())
                .unwrap();
            assert_eq!(dec.expose_secret().as_slice(), expected_plain);
        }

        let reloaded_other = RepoConfig::load(&repo_other.join("dotler.toml")).unwrap();
        let other_vcfg = reloaded_other.vault.unwrap();
        assert_eq!(other_vcfg.password_slot, vcfg_other.password_slot);

        OsKeyring::clear_mock();
        OsKeyring::disable_mock();
    }

    #[test]
    fn test_unlock_vault_if_needed_respects_use_keyring_false() {
        let _guard = crate::crypto::keyring::MOCK_KEYRING_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        OsKeyring::enable_mock();
        OsKeyring::clear_mock();
        unsafe {
            std::env::remove_var(crate::crypto::keyring::PASSPHRASE_ENV_VAR);
        }

        let pass = SecretString::new("keyring-disabled-secret-123".to_string());
        let (mut vault_cfg, expected_key, _mnemonic) = init_vault(&pass).unwrap();
        vault_cfg.hint = Some("my hint".to_string());
        let repo_cfg = RepoConfig {
            vault: Some(vault_cfg),
            ..Default::default()
        };

        OsKeyring::set(&pass).unwrap();
        let non_interactive_res = unlock_vault_if_needed(&repo_cfg, false, false, true);
        assert!(non_interactive_res.is_err());

        OsKeyring::clear_mock();
        OsKeyring::push_mock_prompt_reply("keyring-disabled-secret-123");
        let unlocked = unlock_vault_if_needed(&repo_cfg, false, true, true)
            .expect("interactive unlock must succeed")
            .expect("vault key must be returned");
        assert_eq!(unlocked.vault_id(), expected_key.vault_id());
        assert!(
            OsKeyring::get().unwrap().is_none(),
            "OsKeyring must remain empty when use_keyring = false"
        );

        OsKeyring::clear_mock();
        OsKeyring::disable_mock();
    }
}
