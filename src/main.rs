use anyhow::Result;
use clap::Parser;

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
    #[arg(short, long, default_value = "low", global = true)]
    verbosity: String,

    /// Write session log to file
    #[arg(short, long, global = true)]
    output: Option<String>,

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

#[derive(clap::Subcommand, Debug)]
enum Commands {
    /// Launch a command and monitor it
    Watch {
        /// Command to launch and monitor
        command: String,
    },
    /// Attach to a running process
    Attach {
        /// PID to attach to
        #[arg(long)]
        pid: Option<u32>,
        /// Process name to find and attach to
        #[arg(long)]
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
        #[arg(long, default_value = "text")]
        format: String,
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

#[derive(clap::Subcommand, Debug)]
enum DaemonAction {
    Start,
    Stop,
    Status,
    Watch,
}

#[derive(clap::Subcommand, Debug)]
enum ProfileAction {
    List,
    Show { name: String },
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

    // Respect NO_COLOR env var and --no-color flag
    if cli.no_color || std::env::var("NO_COLOR").is_ok() {
        colored::control::set_override(false);
    }

    match cli.command {
        None => {
            // Interactive mode: detect running agents
            interactive::run().await?;
        }
        Some(Commands::Watch { command }) => {
            tracing::info!("watch mode: {}", command);
            // TODO: Sprint 1 — wire up monitors
        }
        Some(Commands::Attach { pid, name }) => {
            tracing::info!("attach mode: pid={:?} name={:?}", pid, name);
            // TODO: Sprint 1 — wire up monitors
        }
        Some(Commands::Demo { scan, seed }) => {
            tracing::info!("demo mode: scan={} seed={:?}", scan, seed);
            // TODO: Sprint 2 — demo mode
        }
        Some(Commands::Report { session, format }) => {
            tracing::info!("report: session={:?} format={}", session, format);
            // TODO: Sprint 2 — session reports
        }
        Some(Commands::History { session }) => {
            tracing::info!("history: session={:?}", session);
            // TODO: Sprint 2 — session history
        }
        Some(Commands::Daemon { action }) => {
            match action {
                DaemonAction::Start => tracing::info!("daemon start"),
                DaemonAction::Stop => tracing::info!("daemon stop"),
                DaemonAction::Status => tracing::info!("daemon status"),
                DaemonAction::Watch => tracing::info!("daemon watch"),
            }
            // TODO: Sprint 4 — daemon mode
        }
        Some(Commands::Profiles { action }) => {
            match action {
                ProfileAction::List => tracing::info!("profiles list"),
                ProfileAction::Show { name } => tracing::info!("profiles show: {}", name),
            }
            // TODO: Sprint 1 — profile loading
        }
    }

    Ok(())
}
