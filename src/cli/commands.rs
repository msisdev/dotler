//! Command-line dispatch routing parsed commands to domain workflows under lock protection.

use std::io::Write;

use crate::agent::briefing::render_briefing;
use crate::cli::observer::{execute_with_observer, handle_git};
use crate::cli::output::{EXIT_SUCCESS, ExportReport, render_success_to};
use crate::cli::vault::{ensure_repo_vault_in_keyring, handle_vault};
use crate::config::local::{
    LOCAL_CONFIG_FILE, LocalConfig, expand_tilde, format_home_repo_path, get_local_config,
    resolve_home_for_config_path,
};
use crate::config::repo::{OsInfo, RepoConfig};
use crate::config::state::{DOTLER_LOCK_PATH, DotlerLockGuard, get_lock};
use crate::core::context::CoreContext;
use crate::crypto::keyring::OsKeyring;
use crate::engine::EngineError;
use crate::engine::check::{CheckReport, run_check, run_init, run_status};
use crate::engine::sync::{run_export, run_import};
use crate::engine::tidy::{TidyOrphanPolicy, run_tidy};

pub use crate::cli::args::{
    AiArgs, CheckArgs, Cli, Command, ExportArgs, GitCloneArgs, GitCommand, GitInstallArgs,
    GitLsArgs, GitUninstallArgs, ImportArgs, InitArgs, McpArgs, StatusArgs, TidyArgs, UpdateArgs,
    VaultCommand, VaultFromCommand, VaultFromSourceArgs, VaultInitArgs, VaultLsArgs,
    VaultRecoverArgs, VaultRotateArgs,
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
        Command::Vault { command } => {
            handle_vault(command, cli, is_interactive, stdout, lock_guard)
        }
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
    let repo_dir = match &args.repo_path {
        Some(p) => p.clone(),
        None => std::env::current_dir()?,
    };
    let home = resolve_home_for_config_path(&expand_tilde(LOCAL_CONFIG_FILE));
    let _ = format_home_repo_path(&repo_dir, &home)?;
    let manifest_path = repo_dir.join("dotler.toml");
    if manifest_path.is_file() {
        let existing_cfg = RepoConfig::load_without_vault_check(&manifest_path)?;
        if let Some(ref vault_cfg) = existing_cfg.vault {
            let use_keyring = ctx
                .local_config
                .get()
                .map(|c| c.use_keyring)
                .unwrap_or(true);
            ensure_repo_vault_in_keyring(
                vault_cfg,
                use_keyring,
                args.password_stdin,
                is_interactive,
            )?;
        }
    }
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

fn handle_check<W: Write>(
    args: &CheckArgs,
    cli: &Cli,
    is_interactive: bool,
    stdout: &mut W,
    lock: &DotlerLockGuard,
) -> Result<i32, EngineError> {
    let ctx = CoreContext::new(cli.repo.clone(), cli.device.clone(), is_interactive);
    let report = if args.groups.is_empty() {
        run_check(&ctx, None, lock)?
    } else {
        let mut warnings = Vec::new();
        for g in &args.groups {
            let sub = run_check(&ctx, Some(g), lock)?;
            for w in sub.warnings {
                if !warnings.contains(&w) {
                    warnings.push(w);
                }
            }
        }
        CheckReport {
            status: "valid".to_string(),
            groups_checked: args.groups.len(),
            warnings,
        }
    };
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
    let plans = if args.groups.is_empty() {
        run_status(&ctx, None, lock)?
    } else {
        let mut all_plans = Vec::new();
        for g in &args.groups {
            all_plans.extend(run_status(&ctx, Some(g), lock)?);
        }
        all_plans.sort_by(|a, b| a.target_os_path.cmp(&b.target_os_path));
        all_plans
    };
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
    let dry_run = cli.dry_run;
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
    let dry_run = cli.dry_run;
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
    let dry_run = cli.dry_run;
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
    let active_vault_id = CoreContext::new(cli.repo.clone(), cli.device.clone(), false)
        .resolve_repo()
        .ok()
        .and_then(|ctx| ctx.repo_config.vault.map(|v| v.vault_id));
    let keyring_ready =
        local_cfg.use_keyring && OsKeyring::is_ready_for_vault(active_vault_id.as_deref());

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
    is_interactive: bool,
    stdout: &mut W,
    _lock: &DotlerLockGuard,
) -> Result<i32, EngineError> {
    let data = crate::cli::update::run_update(args, is_interactive, cli.json)?;
    Ok(render_success_to(stdout, "update", &data, cli.json))
}
