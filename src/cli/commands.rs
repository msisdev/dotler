//! Command-line dispatch routing parsed commands to domain workflows under lock protection.

use std::io::Write;
use std::path::Path;

use crate::agent::briefing::render_briefing;
use crate::cli::observer::execute_with_observer;
use crate::cli::output::{EXIT_SUCCESS, ExportReport, render_success_to};
use crate::cli::vault::{handle_key, handle_vault};
use crate::config::local::{LOCAL_CONFIG_FILE, LocalConfig, expand_tilde, get_local_config};
use crate::config::repo::OsInfo;
use crate::config::state::{DOTLER_LOCK_PATH, DotlerLockGuard, get_lock};
use crate::core::context::CoreContext;
use crate::crypto::keyring::OsKeyring;
use crate::engine::EngineError;
use crate::engine::check::{run_check, run_init, run_status};
use crate::engine::remote::{
    GroupSelector, run_git_clone, run_git_install, run_git_ls, run_git_uninstall,
};
use crate::engine::sync::{run_export, run_import};
use crate::engine::tidy::{TidyOrphanPolicy, run_tidy};

pub use crate::cli::args::{
    AiArgs, CheckArgs, Cli, Command, ExportArgs, GitCloneArgs, GitCommand, GitInstallArgs,
    GitLsArgs, GitUninstallArgs, ImportArgs, InitArgs, KeyCommand, KeyDelArgs, KeySetArgs, McpArgs,
    StatusArgs, TidyArgs, UpdateArgs, VaultCommand, VaultInitArgs, VaultPasswdArgs,
    VaultRecoverArgs,
};

/// Dispatches parsed CLI commands to domain workflows under lock protection.
pub fn dispatch<W1: Write, W2: Write>(
    cli: &Cli,
    is_interactive: bool,
    stdout: &mut W1,
    _stderr: &mut W2,
) -> Result<i32, EngineError> {
    if let Command::Mcp(_) = &cli.command {
        return match crate::agent::mcp::run_mcp_server(std::io::stdin().lock(), stdout) {
            Ok(()) => Ok(EXIT_SUCCESS),
            Err(e) => Err(EngineError::Io(std::io::Error::other(e.to_string()))),
        };
    }

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
        Command::Vault { command } => handle_vault(command, cli, is_interactive, stdout, lock_guard),
        Command::Key { command } => handle_key(command, cli, is_interactive, stdout, lock_guard),
        Command::Ai(_) => handle_ai(cli, stdout, lock_guard),
        Command::Update(args) => handle_update(args, cli, is_interactive, stdout, lock_guard),
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
            let selectors: Vec<GroupSelector> =
                args.groups.iter().map(|s| GroupSelector::parse(s)).collect();
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
            execute_with_observer(
                stdout,
                "git clone",
                cli.json,
                args.all,
                args.yes,
                is_interactive,
                |obs| {
                    run_git_clone(
                        &args.url,
                        &selectors,
                        args.branch.as_deref(),
                        &dest,
                        Some(&cfg_path),
                        None,
                        None,
                        lock,
                        dry_run,
                        obs,
                    )
                },
                |r| r,
            )
        }
        GitCommand::Install(args) => {
            let dev_override = args.device.clone().or_else(|| cli.device.clone());
            let ctx = CoreContext::new(cli.repo.clone(), dev_override, is_interactive);
            let override_path = args.path.first().map(Path::new);
            let dry_run = args.dry_run || cli.dry_run;
            execute_with_observer(
                stdout,
                "git install",
                cli.json,
                args.all,
                args.yes,
                is_interactive,
                |obs| {
                    run_git_install(
                        &ctx,
                        &args.url,
                        &args.groups,
                        override_path,
                        args.branch.as_deref(),
                        lock,
                        dry_run,
                        obs,
                    )
                },
                |r| r,
            )
        }
        GitCommand::Uninstall(args) => {
            let ctx = CoreContext::new(cli.repo.clone(), cli.device.clone(), is_interactive);
            let dry_run = args.dry_run || cli.dry_run;
            execute_with_observer(
                stdout,
                "git uninstall",
                cli.json,
                args.all,
                args.yes,
                is_interactive,
                |obs| run_git_uninstall(&ctx, &args.groups, lock, dry_run, obs),
                |r| r,
            )
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
    execute_with_observer(
        stdout,
        "import",
        cli.json,
        args.all,
        args.yes,
        is_interactive,
        |obs| run_import(&ctx, &groups, args.force, dry_run, lock, obs),
        |r| r,
    )
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
    execute_with_observer(
        stdout,
        "export",
        cli.json,
        args.all,
        args.yes,
        is_interactive,
        |obs| run_export(&ctx, &groups, args.force, dry_run, lock, obs),
        ExportReport,
    )
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
    execute_with_observer(
        stdout,
        "tidy",
        cli.json,
        args.all,
        args.yes,
        is_interactive,
        |obs| run_tidy(&ctx, &groups, policy, dry_run, lock, obs),
        |r| r,
    )
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
    Ok(render_success_to(stdout, "ai", &briefing_markdown, cli.json))
}

fn handle_update<W: Write>(
    args: &UpdateArgs,
    cli: &Cli,
    is_interactive: bool,
    stdout: &mut W,
    _lock: &DotlerLockGuard,
) -> Result<i32, EngineError> {
    let data = crate::cli::update::run_update(args, is_interactive, cli.json)?;
    Ok(render_success_to(stdout, "update", &data, cli.json))
}
