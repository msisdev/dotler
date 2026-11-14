//! Command-line argument structures and subcommand definitions powered by `clap`.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

#[derive(Parser, Debug, Clone)]
#[command(
    name = "dotler",
    version,
    about = "Privacy-first, zero-trace dotfile management engine",
    long_about = None
)]
pub struct Cli {
    #[arg(short = 'j', long = "json", global = true, help = "Output structured JSON")]
    pub json: bool,

    #[arg(short = 'd', long = "device", global = true, help = "Target device profile override")]
    pub device: Option<String>,

    #[arg(short = 'r', long = "repo", global = true, help = "Repository label override")]
    pub repo: Option<String>,

    #[arg(long = "dry-run", global = true, help = "Simulate operations without writing changes")]
    pub dry_run: bool,

    #[arg(short = 'v', long = "verbose", global = true, help = "Enable verbose output")]
    pub verbose: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Initialize a dotler repository and register device/repo in config.toml (run 'dotler ai' for AI context)
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

    #[arg(long = "repo-path", help = "Target directory path for repository initialization")]
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

    #[arg(short, long, help = "Custom target path override (e.g. group=~/custom/path)")]
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

fn merge_group_args(groups: &[String], group: Option<&String>) -> Vec<String> {
    let mut list = groups.to_vec();
    if let Some(g) = group
        && !list.contains(g)
    {
        list.push(g.clone());
    }
    list
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
        merge_group_args(&self.groups, self.group.as_ref())
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
        merge_group_args(&self.groups, self.group.as_ref())
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
        merge_group_args(&self.groups, self.group.as_ref())
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
    #[arg(
        long,
        conflicts_with_all = ["url", "from"],
        help = "Import existing vault metadata from a remote Git repository"
    )]
    pub git: Option<String>,

    #[arg(
        long,
        conflicts_with_all = ["git", "from"],
        help = "Import existing vault metadata via HTTP GET (TOML or JSON)"
    )]
    pub url: Option<String>,

    #[arg(
        long,
        conflicts_with_all = ["git", "url"],
        help = "Import existing vault metadata from a registered repository label or local path (TOML or JSON)"
    )]
    pub from: Option<String>,

    #[arg(long = "password-stdin", help = "Read passphrase from standard input")]
    pub password_stdin: bool,

    #[arg(long, help = "Optional plaintext password hint stored in dotler.toml")]
    pub hint: Option<String>,
}

#[derive(Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct VaultPasswdArgs {
    #[arg(long = "password-stdin", help = "Read new passphrase from standard input")]
    pub password_stdin: bool,

    #[arg(long, help = "Optional plaintext password hint stored in dotler.toml")]
    pub hint: Option<String>,
}

#[derive(Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct VaultRecoverArgs {
    #[arg(long, help = "12-word recovery mnemonic phrase")]
    pub mnemonic: Option<String>,

    #[arg(long = "password-stdin", help = "Read new passphrase from standard input")]
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
    #[arg(long, help = "Check for updates without replacing the executable")]
    pub check: bool,

    #[arg(long, help = "Target release version or tag (e.g. v0.2.0)")]
    pub version: Option<String>,

    #[arg(
        short = 'f',
        long = "force",
        help = "Force binary replacement even if up-to-date or managed by a package manager"
    )]
    pub force: bool,

    #[arg(short = 'y', long = "yes", help = "Skip confirmation prompt")]
    pub yes: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tidy_purge_and_reject_removed_flags() {
        let default_cli = Cli::try_parse_from(["dotler", "tidy"]).expect("bare tidy must parse");
        assert!(matches!(default_cli.command, Command::Tidy(a) if !a.purge));

        let purge_cli = Cli::try_parse_from(["dotler", "tidy", "--purge"]).unwrap();
        assert!(matches!(purge_cli.command, Command::Tidy(a) if a.purge));

        assert!(Cli::try_parse_from(["dotler", "tidy", "--rm"]).is_err());
        assert!(Cli::try_parse_from(["dotler", "tidy", "--keep"]).is_err());
    }

    #[test]
    fn test_parse_6_mutating_commands_yes_all_dry_run_flags() {
        let imp = Cli::try_parse_from(["dotler", "import", "-y", "-a", "--dry-run"]).unwrap();
        assert!(matches!(imp.command, Command::Import(a) if a.yes && a.all && a.dry_run));

        let exp = Cli::try_parse_from(["dotler", "export", "-y", "-a", "--dry-run", "-f"]).unwrap();
        assert!(matches!(exp.command, Command::Export(a) if a.yes && a.all && a.dry_run && a.force));

        let tidy = Cli::try_parse_from(["dotler", "tidy", "-y", "-a", "--dry-run", "--purge"]).unwrap();
        assert!(matches!(tidy.command, Command::Tidy(a) if a.yes && a.all && a.dry_run && a.purge));

        let clone = Cli::try_parse_from(["dotler", "git", "clone", "gh:u/r", "-y", "-a", "--dry-run"]).unwrap();
        assert!(matches!(clone.command, Command::Git { command: GitCommand::Clone(a) } if a.yes && a.all && a.dry_run));

        let install = Cli::try_parse_from(["dotler", "git", "install", "gh:u/r", "nvim", "-y", "-a", "--dry-run"]).unwrap();
        assert!(matches!(install.command, Command::Git { command: GitCommand::Install(a) } if a.yes && a.all && a.dry_run));

        let uninstall = Cli::try_parse_from(["dotler", "git", "uninstall", "-y", "-a", "--dry-run"]).unwrap();
        assert!(matches!(uninstall.command, Command::Git { command: GitCommand::Uninstall(a) } if a.yes && a.all && a.dry_run));
    }

    #[test]
    fn test_parse_12_subcommands_syntax() {
        for argv in [
            vec!["dotler", "init"],
            vec!["dotler", "git", "ls", "gh:user/dot"],
            vec!["dotler", "check"],
            vec!["dotler", "status"],
            vec!["dotler", "import"],
            vec!["dotler", "export"],
            vec!["dotler", "tidy"],
            vec!["dotler", "vault", "init"],
            vec!["dotler", "key", "set"],
            vec!["dotler", "ai"],
            vec!["dotler", "mcp"],
            vec!["dotler", "update"],
        ] {
            assert!(Cli::try_parse_from(&argv).is_ok(), "failed: {argv:?}");
        }

        let parsed = Cli::try_parse_from(["dotler", "update", "--check", "--version", "v0.3.0", "--force", "-y"])
            .expect("dotler update flags must parse");
        match parsed.command {
            Command::Update(u) => {
                assert!(u.check && u.force && u.yes);
                assert_eq!(u.version.as_deref(), Some("v0.3.0"));
            }
            other => panic!("Unexpected command: {other:?}"),
        }
    }

    #[test]
    fn test_vault_init_external_flags_mutual_exclusion() {
        let g = Cli::try_parse_from(["dotler", "vault", "init", "--git", "github:user/dots"]).unwrap();
        assert!(matches!(g.command, Command::Vault { command: VaultCommand::Init(a) } if a.git.as_deref() == Some("github:user/dots")));

        let u = Cli::try_parse_from(["dotler", "vault", "init", "--url", "https://example.com/vault.json"]).unwrap();
        assert!(matches!(u.command, Command::Vault { command: VaultCommand::Init(a) } if a.url.as_deref() == Some("https://example.com/vault.json")));

        let f = Cli::try_parse_from(["dotler", "vault", "init", "--from", "main"]).unwrap();
        assert!(matches!(f.command, Command::Vault { command: VaultCommand::Init(a) } if a.from.as_deref() == Some("main")));

        assert!(Cli::try_parse_from(["dotler", "vault", "init", "--git", "gh:u/r", "--url", "https://example.com/v.toml"]).is_err());
        assert!(Cli::try_parse_from(["dotler", "vault", "init", "--git", "gh:u/r", "--from", "main"]).is_err());
        assert!(Cli::try_parse_from(["dotler", "vault", "init", "--url", "https://example.com/v.toml", "--from", "main"]).is_err());
    }
}
