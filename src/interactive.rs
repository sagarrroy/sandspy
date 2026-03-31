// sandspy::interactive — Interactive first-run agent detection (Step 2.3)
//
// When sandspy is invoked with no subcommand, this runs:
// - Scans for running AI agents
// - Shows a numbered selection list if agents found
// - Falls back to usage hints if none detected

use crate::monitor::process::scan_for_agents;
use anyhow::Result;
use colored::*;
use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers},
    terminal,
};

/// Run interactive mode. Called when sandspy has no subcommand.
pub async fn run() -> Result<()> {
    print_banner();

    println!("  {}  scanning for running AI agents...", "→".dimmed());
    println!();

    let agents = scan_for_agents();

    if agents.is_empty() {
        print_no_agents();
    } else {
        print_agent_list(&agents);
        if let Some(selected) = pick_agent(&agents)? {
            println!();
            println!(
                "  {} {}",
                "attaching to".dimmed(),
                format!("{} (pid {})", selected.name, selected.pid)
                    .bold()
                    .white()
            );
            println!();
            // Delegate to watch via exec-style relaunch
            let args: Vec<String> = std::env::args().collect();
            let bin = &args[0];
            let status = std::process::Command::new(bin)
                .args(["attach", "--pid", &selected.pid.to_string()])
                .status()?;
            std::process::exit(status.code().unwrap_or(0));
        }
    }

    Ok(())
}

// ─── UI helpers ─────────────────────────────────────────────────────────────

fn print_banner() {
    let version = env!("CARGO_PKG_VERSION");
    println!();
    println!(
        "  {}  {}",
        "sandspy".bold().white(),
        format!("v{version}").dimmed()
    );
    println!("  {}", "AI agent security monitor".dimmed());
    println!();
    println!("  {}", "─".repeat(62).dimmed());
    println!();
}

fn print_agent_list(agents: &[crate::events::AgentInfo]) {
    println!(
        "  {}  {} running agent{} detected\n",
        "✓".green().bold(),
        agents.len().to_string().bold().white(),
        if agents.len() == 1 { "" } else { "s" }
    );

    for (i, agent) in agents.iter().enumerate() {
        let uptime = format_uptime(agent.uptime_secs);
        println!(
            "  {}  {}   {}   {}",
            format!("[{}]", i + 1).bold().cyan(),
            agent.name.bold().white(),
            format!("pid {}", agent.pid).dimmed(),
            uptime.dimmed()
        );
    }

    println!();
    println!(
        "  {}",
        "select an agent to monitor  [1-9] / ctrl+c to exit".dimmed()
    );
    println!();
}

fn print_no_agents() {
    println!("  {}  no running AI agents detected\n", "○".yellow());
    println!("  {}", "usage".bold().white());
    println!();

    let cmds = [
        (
            "sandspy watch \"claude-code\"",
            "monitor a launched command",
        ),
        ("sandspy attach --name cursor", "attach to a running agent"),
        ("sandspy demo", "run a simulated 25-second session"),
        ("sandspy daemon start", "background monitoring mode"),
    ];

    for (cmd, desc) in &cmds {
        println!("    {}   {}", cmd.bold().white(), desc.dimmed());
    }

    println!();
    println!("  {}", "supported agents".bold().white());
    println!();

    let agents = [
        "Claude Code",
        "Cursor",
        "Codex CLI",
        "Gemini CLI",
        "Windsurf",
        "Cline",
        "Aider",
        "Continue",
        "Antigravity",
        "OpenClaw",
    ];

    let joined = agents.join("  ·  ");
    println!("    {}", joined.dimmed());
    println!();
}

fn pick_agent(agents: &[crate::events::AgentInfo]) -> Result<Option<&crate::events::AgentInfo>> {
    // Enable raw mode to capture single keypress
    terminal::enable_raw_mode()?;

    let result = loop {
        if let Ok(Event::Key(key)) = event::read() {
            // Ctrl+c or q → cancel
            if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
                break None;
            }
            if key.code == KeyCode::Char('q') || key.code == KeyCode::Esc {
                break None;
            }
            // Digit key
            if let KeyCode::Char(c) = key.code {
                if let Some(digit) = c.to_digit(10) {
                    let idx = digit as usize;
                    if idx >= 1 && idx <= agents.len() {
                        break Some(&agents[idx - 1]);
                    }
                }
            }
        }
    };

    terminal::disable_raw_mode()?;
    Ok(result)
}

fn format_uptime(secs: u64) -> String {
    if secs < 60 {
        format!("up {}s", secs)
    } else if secs < 3600 {
        format!("up {}m", secs / 60)
    } else {
        format!("up {}h {}m", secs / 3600, (secs % 3600) / 60)
    }
}
