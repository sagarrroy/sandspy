// sandspy::interactive — Interactive first-run agent detection

use anyhow::Result;

/// Run interactive mode: scan for agents, prompt user to select.
pub async fn run() -> Result<()> {
    println!();
    println!("  sandspy v{}", env!("CARGO_PKG_VERSION"));
    println!("  AI agent security monitor");
    println!();
    println!("  scanning for running AI agents...");
    println!();

    // TODO: Sprint 1 — call monitor::process::scan_for_agents()
    // For now, show usage hints
    println!("  no agents detected");
    println!();
    println!("  usage:");
    println!("    sandspy watch \"claude-code\"       monitor a command");
    println!("    sandspy attach --name cursor      attach to running agent");
    println!("    sandspy demo                      run a simulated session");
    println!("    sandspy daemon start              background monitoring");
    println!();
    println!("  supported agents:");
    println!("    Claude Code, Cursor, Codex CLI, Gemini CLI, Windsurf,");
    println!("    Cline, Aider, Continue, Antigravity, OpenClaw");
    println!();

    Ok(())
}
