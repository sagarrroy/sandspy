use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

mod alerts;
mod config;
mod daemon;
mod demo;
mod events;
mod history;
mod interactive;

mod analysis;
mod monitor;
mod platform;
mod report;
mod ui;

/// sandspy — Real-time security monitor for AI coding agents
#[derive(Parser, Debug)]
#[command(name = "sandspy", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Use TUI dashboard instead of live stream
    #[arg(short, long, global = true)]
    dashboard: bool,

    /// Verbosity level
    #[arg(short, long, value_enum, default_value_t = Verbosity::Low, global = true)]
    verbosity: Verbosity,

    /// Write session log to file
    #[arg(short, long, global = true)]
    output: Option<PathBuf>,

    /// Force a specific agent profile
    #[arg(long, global = true)]
    profile: Option<String>,

    /// Disable color output
    #[arg(long, global = true)]
    no_color: bool,

    /// Output events as JSON lines
    #[arg(long, global = true)]
    json: bool,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Launch a command and monitor it
    Watch {
        /// Command to launch and monitor
        command: String,
    },
    /// Attach to a running process
    Attach {
        /// PID to attach to
        #[arg(long, required_unless_present = "name", conflicts_with = "name")]
        pid: Option<u32>,
        /// Process name to find and attach to
        #[arg(long, required_unless_present = "pid", conflicts_with = "pid")]
        name: Option<String>,
    },
    /// Run a simulated demo session
    Demo {
        /// Show scan summary instead of live stream
        #[arg(long)]
        scan: bool,
        /// RNG seed for reproducible demos
        #[arg(long)]
        seed: Option<u64>,
    },
    /// View session reports
    Report {
        /// Session ID to view
        #[arg(long)]
        session: Option<String>,
        /// Output format
        #[arg(long, value_enum, default_value_t = ReportFormat::Text)]
        format: ReportFormat,
    },
    /// Browse session history
    History {
        /// Session ID for details
        #[arg(long)]
        session: Option<String>,
    },
    /// Manage background daemon
    Daemon {
        #[command(subcommand)]
        action: DaemonAction,
    },
    /// Manage agent profiles
    Profiles {
        #[command(subcommand)]
        action: ProfileAction,
    },
}

#[derive(Subcommand, Debug)]
enum DaemonAction {
    Start,
    Stop,
    Status,
    Watch,
}

#[derive(Subcommand, Debug)]
enum ProfileAction {
    List,
    Show { name: String },
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum Verbosity {
    Low,
    Medium,
    High,
    All,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum ReportFormat {
    Text,
    Json,
}

#[derive(Debug, Clone)]
struct GlobalOptions {
    dashboard: bool,
    verbosity: Verbosity,
    output: Option<PathBuf>,
    profile: Option<String>,
    no_color: bool,
    json: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    let cli = Cli::parse();
    let global = GlobalOptions {
        dashboard: cli.dashboard,
        verbosity: cli.verbosity,
        output: cli.output,
        profile: cli.profile,
        no_color: cli.no_color,
        json: cli.json,
    };

    // Respect NO_COLOR env var and --no-color flag
    if global.no_color || std::env::var("NO_COLOR").is_ok() {
        colored::control::set_override(false);
    }

    match cli.command {
        None => handle_interactive().await?,
        Some(command) => handle_command(command, global).await?,
    }

    Ok(())
}

async fn handle_interactive() -> Result<()> {
    interactive::run().await
}

async fn handle_command(command: Commands, global: GlobalOptions) -> Result<()> {
    match command {
        Commands::Watch { command } => handle_watch(command, global).await,
        Commands::Attach { pid, name } => handle_attach(pid, name, global).await,
        Commands::Demo { scan, seed } => handle_demo(scan, seed, global).await,
        Commands::Report { session, format } => handle_report(session, format, global).await,
        Commands::History { session } => handle_history(session, global).await,
        Commands::Daemon { action } => handle_daemon(action, global).await,
        Commands::Profiles { action } => handle_profiles(action, global).await,
    }
}

async fn handle_watch(command: String, global: GlobalOptions) -> Result<()> {
    tracing::info!(
        command = %command,
        dashboard = global.dashboard,
        verbosity = ?global.verbosity,
        output = ?global.output,
        profile = ?global.profile,
        json = global.json,
        "watch mode"
    );
    println!("watch mode not yet implemented (Sprint 1+)");
    Ok(())
}

async fn handle_attach(pid: Option<u32>, name: Option<String>, global: GlobalOptions) -> Result<()> {
    tracing::info!(
        pid = ?pid,
        name = ?name,
        dashboard = global.dashboard,
        verbosity = ?global.verbosity,
        output = ?global.output,
        profile = ?global.profile,
        json = global.json,
        "attach mode"
    );
    println!("attach mode not yet implemented (Sprint 1+)");
    Ok(())
}

async fn handle_demo(scan: bool, seed: Option<u64>, global: GlobalOptions) -> Result<()> {
    tracing::info!(
        scan = scan,
        seed = ?seed,
        dashboard = global.dashboard,
        verbosity = ?global.verbosity,
        json = global.json,
        "demo mode"
    );
    demo::run(scan, seed, global.dashboard).await
}

async fn handle_report(
    session: Option<String>,
    format: ReportFormat,
    global: GlobalOptions,
) -> Result<()> {
    tracing::info!(
        session = ?session,
        format = ?format,
        dashboard = global.dashboard,
        verbosity = ?global.verbosity,
        output = ?global.output,
        profile = ?global.profile,
        json = global.json,
        "report mode"
    );

    println!("report mode not yet implemented (Sprint 2+)");
    Ok(())
}

async fn handle_history(session: Option<String>, _global: GlobalOptions) -> Result<()> {
    match session {
        Some(session_id) => history::show(&session_id).await,
        None => history::list().await,
    }
}

async fn handle_daemon(action: DaemonAction, _global: GlobalOptions) -> Result<()> {
    match action {
        DaemonAction::Start => daemon::start().await,
        DaemonAction::Stop => daemon::stop().await,
        DaemonAction::Status => daemon::status().await,
        DaemonAction::Watch => daemon::watch().await,
    }
}

async fn handle_profiles(action: ProfileAction, _global: GlobalOptions) -> Result<()> {
    match action {
        ProfileAction::List => {
            tracing::info!("profiles list");
            println!("profiles list not yet implemented (Sprint 1+)");
        }
        ProfileAction::Show { name } => {
            tracing::info!(profile = %name, "profiles show");
            println!("profiles show not yet implemented (Sprint 1+)");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_has_required_subcommands() {
        let command = Cli::command();

        let subcommands: Vec<String> = command
            .get_subcommands()
            .map(|sub| sub.get_name().to_string())
            .collect();

        assert!(subcommands.contains(&"watch".to_string()));
        assert!(subcommands.contains(&"attach".to_string()));
        assert!(subcommands.contains(&"demo".to_string()));
        assert!(subcommands.contains(&"report".to_string()));
        assert!(subcommands.contains(&"history".to_string()));
        assert!(subcommands.contains(&"daemon".to_string()));
        assert!(subcommands.contains(&"profiles".to_string()));
    }

    #[test]
    fn attach_requires_exactly_one_target() {
        let missing = Cli::try_parse_from(["sandspy", "attach"]);
        assert!(missing.is_err());

        let both = Cli::try_parse_from(["sandspy", "attach", "--pid", "42", "--name", "cursor"]);
        assert!(both.is_err());

        let by_pid = Cli::try_parse_from(["sandspy", "attach", "--pid", "42"]);
        assert!(by_pid.is_ok());

        let by_name = Cli::try_parse_from(["sandspy", "attach", "--name", "cursor"]);
        assert!(by_name.is_ok());
    }

    #[test]
    fn verbosity_restricts_allowed_values() {
        let valid = Cli::try_parse_from(["sandspy", "watch", "codex", "-v", "medium"]);
        assert!(valid.is_ok());

        let invalid = Cli::try_parse_from(["sandspy", "watch", "codex", "-v", "verbose"]);
        assert!(invalid.is_err());
    }

    #[test]
    fn report_format_restricts_allowed_values() {
        let valid = Cli::try_parse_from(["sandspy", "report", "--format", "json"]);
        assert!(valid.is_ok());

        let invalid = Cli::try_parse_from(["sandspy", "report", "--format", "yaml"]);
        assert!(invalid.is_err());
    }
}
