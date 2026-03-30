use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::{mpsc, RwLock};
use tokio::time;

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
        #[arg(long, value_enum, default_value_t = ReportFormat::Markdown)]
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
    Markdown,
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
    let session_start = SystemTime::now();
    let loaded_profiles = analysis::profiler::load_profiles()?;
    let command_token = command.split_whitespace().next();
    let matched_profile = analysis::profiler::match_profile(
        &loaded_profiles,
        global.profile.as_deref(),
        command_token,
    );

    tracing::info!(
        command = %command,
        profile = ?matched_profile.map(|profile| profile.id.clone()),
        dashboard = global.dashboard,
        verbosity = ?global.verbosity,
        output = ?global.output,
        json = global.json,
        "watch mode"
    );

    let (tx, mut rx) = events::create_event_bus();
    let pids = monitor::process::create_pid_set();
    let process_state = Arc::new(RwLock::new(WatchProcessState::default()));
    let watch_command = command.clone();
    let tx_for_process = tx.clone();
    let tx_for_filesystem = tx.clone();
    let tx_for_network = tx.clone();
    let tx_for_command = tx.clone();
    let tx_for_environment = tx.clone();
    let tx_for_clipboard = tx.clone();
    let pids_for_process = pids.clone();
    let pids_for_filesystem = pids.clone();
    let pids_for_network = pids.clone();
    let pids_for_command = pids.clone();
    let pids_for_environment = pids.clone();

    let process_handle = tokio::spawn(async move {
        monitor::process::spawn_and_monitor(&watch_command, tx_for_process, pids_for_process).await
    });
    let filesystem_handle = tokio::spawn(async move {
        monitor::filesystem::run(tx_for_filesystem, pids_for_filesystem).await
    });
    let network_handle = tokio::spawn(async move {
        monitor::network::run(tx_for_network, pids_for_network).await
    });
    let command_handle = tokio::spawn(async move {
        monitor::command::run(tx_for_command, pids_for_command).await
    });
    let environment_handle = tokio::spawn(async move {
        monitor::environment::run(tx_for_environment, pids_for_environment).await
    });
    let clipboard_handle = tokio::spawn(async move { monitor::clipboard::run(tx_for_clipboard).await });

    // Agent label for the header
    let agent_label = command.clone();
    let verbosity_level: u8 = match global.verbosity {
        Verbosity::Low => 0,
        Verbosity::Medium => 1,
        Verbosity::High => 2,
        Verbosity::All => 3,
    };
    let session_start_utc = chrono::Utc::now();
    let agent_pid_hint = {
        let guard = process_state.read().await;
        guard.seen.iter().min().copied()
    };

    // Branch: TUI dashboard vs plain live stream
    let live_stats = if global.dashboard {
        // Dashboard mode: rx moves into the TUI runner
        let stats = ui::run_dashboard(
            rx,
            agent_label.clone(),
            agent_pid_hint,
            global.no_color || std::env::var("NO_COLOR").is_ok(),
        )
        .await?;
        // Abort all monitors since user quit
        process_handle.abort();
        filesystem_handle.abort();
        network_handle.abort();
        command_handle.abort();
        environment_handle.abort();
        clipboard_handle.abort();
        drop(tx);
        stats
    } else {
        // Live stream mode: spawn printer, wait for process to finish naturally
        let printer_handle = tokio::spawn(async move {
            ui::live::run(&mut rx, &agent_label, verbosity_level).await
        });

        process_handle.await??;
        filesystem_handle.abort();
        let _ = filesystem_handle.await;
        network_handle.abort();
        let _ = network_handle.await;
        command_handle.abort();
        let _ = command_handle.await;
        environment_handle.abort();
        let _ = environment_handle.await;
        clipboard_handle.abort();
        let _ = clipboard_handle.await;

        let seen_pids = {
            let guard = process_state.read().await;
            guard.seen.clone()
        };
        monitor::memory::run(tx.clone(), session_start, &seen_pids).await?;
        time::sleep(Duration::from_millis(250)).await;
        drop(tx);
        printer_handle.await?
    };

    let duration_secs = (chrono::Utc::now() - session_start_utc)
        .num_seconds()
        .max(0) as u64;
    let agent_pid = agent_pid_hint;
    let metadata = history::SessionMetadata {
        agent_name: command.clone(),
        pid: agent_pid,
        duration: duration_secs,
        risk_score: live_stats.risk_score,
        event_count: live_stats.event_count,
        timestamp: session_start_utc,
    };
    let session_id = history::persist_session(&metadata, &live_stats.events)?;

    // Print post-session summary
    let summary_data = ui::summary::SessionData {
        agent_name: command.clone(),
        agent_pid,
        start: session_start_utc,
        end: chrono::Utc::now(),
        events: live_stats.events.clone(),
        risk_score: live_stats.risk_score,
    };
    ui::summary::print_summary(&summary_data);
    println!("  session saved: {}", session_id);
    let _ = alerts::notify(
        "sandspy",
        &format!("session complete — risk {}", live_stats.risk_score),
    );

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
    let target_pid = match (pid, name.as_deref()) {
        (Some(id), None) => id,
        (None, Some(agent_name)) => {
            let normalized = normalize_process_name(agent_name);
            let found = monitor::process::scan_for_agents()
                .into_iter()
                .find(|agent| normalize_process_name(&agent.name) == normalized);

            match found {
                Some(agent) => agent.pid,
                None => {
                    anyhow::bail!("no running agent found with name: {agent_name}");
                }
            }
        }
        _ => unreachable!("clap enforces exactly one attach target"),
    };

    let (tx, mut rx) = events::create_event_bus();
    let pids = monitor::process::create_pid_set();
    let monitor_handle = tokio::spawn(monitor::process::attach_and_monitor(target_pid, tx.clone(), pids));
    let process_state = Arc::new(RwLock::new(WatchProcessState::default()));
    drop(tx);

    print_watch_events(&mut rx, None, process_state).await;
    monitor_handle.await??;

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

    let session_id = session.ok_or_else(|| anyhow::anyhow!("--session is required for report"))?;
    let (metadata, events) = report::load_session(&session_id)?;

    match format {
        ReportFormat::Json => {
            let output = report::build_json_report(metadata, events);
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
        ReportFormat::Markdown => {
            report::print_markdown_summary(metadata, events);
        }
    }

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
    let profiles = analysis::profiler::load_profiles()?;

    match action {
        ProfileAction::List => {
            for profile in &profiles {
                println!("{} ({})", profile.id, profile.agent.name);
            }
        }
        ProfileAction::Show { name } => {
            let profile = analysis::profiler::match_profile(&profiles, Some(&name), None)
                .ok_or_else(|| anyhow::anyhow!("profile not found: {}", name))?;

            println!("id: {}", profile.id);
            println!("name: {}", profile.agent.name);
            println!("description: {}", profile.agent.description);
            println!("process_names: {}", profile.agent.process_names.join(", "));
            println!(
                "allowed_domains: {}",
                profile.expected.network.allowed_domains.join(", ")
            );
        }
    }
    Ok(())
}

#[derive(Debug, Default)]
struct WatchProcessState {
    seen: HashSet<u32>,
    active: HashSet<u32>,
}

async fn print_watch_events(
    rx: &mut mpsc::Receiver<events::Event>,
    tx: Option<&mpsc::Sender<events::Event>>,
    process_state: Arc<RwLock<WatchProcessState>>,
) {
    let mut risk_scorer = analysis::risk::RiskScorer::new();

    while let Some(event) = rx.recv().await {
        {
            let mut state = process_state.write().await;
            match &event.kind {
                events::EventKind::ProcessSpawn { pid, .. } => {
                    state.seen.insert(*pid);
                    state.active.insert(*pid);
                }
                events::EventKind::ProcessExit { pid, .. } => {
                    state.active.remove(pid);
                }
                _ => {}
            }
        }

        let (score, alerts) = risk_scorer.process_with_alerts(&event);

        match &event.kind {
            events::EventKind::ProcessSpawn {
                pid,
                name,
                cmdline,
                parent_pid,
            } => {
                println!(
                    "{:?} ProcessSpawn pid={} parent={} name={} cmdline={} score={}",
                    event.timestamp, pid, parent_pid, name, cmdline, score
                );
            }
            events::EventKind::ProcessExit { pid, exit_code } => {
                println!(
                    "{:?} ProcessExit pid={} exit_code={:?} score={}",
                    event.timestamp, pid, exit_code, score
                );
            }
            events::EventKind::FileRead {
                path,
                sensitive,
                category,
            } => {
                println!(
                    "{:?} FileRead path={} sensitive={} category={:?} score={}",
                    event.timestamp,
                    path.display(),
                    sensitive,
                    category,
                    score
                );
            }
            events::EventKind::FileWrite { path, diff_summary } => {
                println!(
                    "{:?} FileWrite path={} diff_summary={:?} score={}",
                    event.timestamp,
                    path.display(),
                    diff_summary,
                    score
                );
            }
            events::EventKind::FileDelete { path } => {
                println!(
                    "{:?} FileDelete path={} score={}",
                    event.timestamp,
                    path.display(),
                    score
                );
            }
            events::EventKind::NetworkConnection {
                remote_addr,
                remote_port,
                domain,
                category,
                bytes_sent,
                bytes_recv,
            } => {
                println!(
                    "{:?} NetworkConnection remote={}:{} domain={:?} category={:?} sent={} recv={} score={}",
                    event.timestamp,
                    remote_addr,
                    remote_port,
                    domain,
                    category,
                    bytes_sent,
                    bytes_recv,
                    score
                );
            }
            events::EventKind::ShellCommand {
                command,
                working_dir,
                risk,
            } => {
                println!(
                    "{:?} ShellCommand command={} cwd={} risk={:?} score={}",
                    event.timestamp,
                    command,
                    working_dir.display(),
                    risk,
                    score
                );
            }
            events::EventKind::EnvVarRead { name, sensitive } => {
                println!(
                    "{:?} EnvVarRead name={} sensitive={} score={}",
                    event.timestamp,
                    name,
                    sensitive,
                    score
                );
            }
            events::EventKind::ClipboardRead {
                content_type,
                contains_secret,
            } => {
                println!(
                    "{:?} ClipboardRead type={} contains_secret={} score={}",
                    event.timestamp,
                    content_type,
                    contains_secret,
                    score
                );
            }
            events::EventKind::Alert { message, severity } => {
                println!(
                    "{:?} ALERT severity={:?} message={} score={}",
                    event.timestamp,
                    severity,
                    message,
                    score
                );
            }
            _ => {}
        }

        if let Some(sender) = tx {
            for alert_event in alerts {
                let _ = sender.send(alert_event).await;
            }
        }
    }
}

fn normalize_process_name(name: &str) -> String {
    let lower = name.to_lowercase();
    if let Some(stripped) = lower.strip_suffix(".exe") {
        stripped.to_string()
    } else {
        lower
    }
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
