//! Command-line interface orchestration, argument parsing, and output formatting.

pub mod args;
pub mod channel;
pub mod commands;
pub mod observer;
pub mod output;
pub mod render;
pub mod update;
pub mod vault;

use clap::Parser;
use std::io::{IsTerminal, Write};

use crate::config::ConfigError;
use crate::engine::EngineError;

pub use commands::{Cli, Command, GitCommand, KeyCommand, VaultCommand, dispatch};
pub use output::{
    CliError, EXIT_AUTH_OR_LOCK_ERROR, EXIT_CONFIG_OR_ARGS_ERROR, EXIT_SECURITY_BLOCKED,
    EXIT_SUCCESS, EXIT_SYNC_CONFLICT, ExportReport, InlineRender, JsonEnvelope, JsonErrorPayload,
    KeyReport, UpdateReport, VaultInitReport, VaultPasswdReport, VaultRecoverReport,
    render_engine_error, render_error, render_error_to, render_success, render_success_to,
};

/// Public entry point for executing the CLI application.
pub fn run(args: Option<Vec<String>>) -> Result<i32, EngineError> {
    let mut stdout = std::io::stdout();
    let mut stderr = std::io::stderr();
    run_with_io(args, &mut stdout, &mut stderr)
}

/// Internal entry point enabling customized stdout and stderr streams.
pub fn run_with_io<W1: Write, W2: Write>(
    args: Option<Vec<String>>,
    stdout: &mut W1,
    stderr: &mut W2,
) -> Result<i32, EngineError> {
    let args_vec = args.unwrap_or_else(|| std::env::args().collect());

    let cli = match Cli::try_parse_from(&args_vec) {
        Ok(parsed) => parsed,
        Err(err) => {
            if err.kind() == clap::error::ErrorKind::DisplayHelp
                || err.kind() == clap::error::ErrorKind::DisplayVersion
            {
                let _ = write!(stdout, "{err}");
                return Ok(EXIT_SUCCESS);
            }
            let is_json = args_vec.iter().any(|a| a == "--json" || a == "-j");
            if is_json {
                let payload = JsonErrorPayload::new(
                    "CLI_ARGS_ERROR",
                    err.to_string(),
                    None,
                    "Run 'dotler --help' to see valid command syntax.",
                );
                let _ = serde_json::to_writer(&mut *stdout, &payload);
                let _ = writeln!(stdout);
            } else {
                let _ = write!(stderr, "{err}");
            }
            return Err(EngineError::Config(ConfigError::UnknownField {
                field: err.to_string(),
                hint: "Run 'dotler --help' for usage instructions.".to_string(),
            }));
        }
    };

    let is_interactive = std::io::stdin().is_terminal() && !cli.json;

    match commands::dispatch(&cli, is_interactive, stdout, stderr) {
        Ok(code) => Ok(code),
        Err(err) => {
            let _ = output::render_engine_error(stdout, stderr, &err, cli.json);
            Err(err)
        }
    }
}
