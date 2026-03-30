<div align="center">
  <h1>S A N D S P Y</h1>
  <p><strong>Zero-Friction Security Telemetry for Autonomous AI Agents</strong></p>
  
  <a href="https://crates.io/crates/sandspy"><img src="https://img.shields.io/crates/v/sandspy.svg?style=for-the-badge&color=black&logoColor=white" alt="Crates.io"></a>
  <a href="https://github.com/user/sandspy/actions"><img src="https://img.shields.io/github/actions/workflow/status/user/sandspy/ci.yml?branch=main&style=for-the-badge&color=black" alt="CI Status"></a>
</div>

---

### The Problem
You are running Cursor, Windsurf, Claude Code, or Aider on your local machine. You have given an autonomous, continuous-execution AI system root-level shell access and filesystem read/write privileges. 

**You have a junior developer running blind on your system at 1,000 WPM. You have absolutely no idea what it is actually doing.**
- What `.env` files did it silently read?
- Did it accidentally copy your AWS credentials to clipboard?
- What external telemetry tracking servers did its shell commands connect to?

**Sandspy visualizes the invisible.** It is a native, frictionless Crowdstrike-style sensor built specifically to audit AI coding agents in real-time.

<br>

<div align="center">
  <!-- TODO: Replace with actual asset path before launch -->
  <img src="https://raw.githubusercontent.com/user/sandspy/main/assets/dashboard.gif" alt="Sandspy TUI Dashboard in Action" width="800" style="border: 1px solid #333; border-radius: 4px;">
</div>

<br>

## Features

- 🎯 **Auto-Attach**: Instantly discovers and hooks into active Agent PIDs (Cursor, Windsurf, Aider, etc.) with zero configuration required.
- 📡 **Deep Network Forensics**: Intercepts and categorizes every background `TCP/UDP` connection the agent attempts.
- 🔐 **Regex Secret Sniffing**: Memory-safe memory scanning. Instantly triggers **CRITICAL** risk alerts if the agent touches an AWS key, Stripe live token, or OpenAI secret.
- 📝 **Clipboard Monitoring**: Detects when malicious shell commands or agent responses poison your systemic clipboard.
- 🛡️ **Self-Healing Daemon**: If the AI process exits, the Sandspy daemon silently resets and waits in an infinite loop to seamlessly re-attach to the next spawned process.
- 📊 **Brutalist HTML Audits**: Generates breathtakingly minimal, Vercel-inspired HTML executive summaries for post-session telemetry review.

## Installation

Sandspy is a lightweight Rust binary. Install it globally via Cargo:

```bash
cargo install sandspy
```
*(Require Rust 1.88+)*

Or build from source:
```bash
git clone https://github.com/user/sandspy.git
cd sandspy
cargo install --path . --force
```

## Quick Start

### 1. The Real-Time Dashboard
To open the 60fps telemetry terminal UI and automatically hook into the nearest AI agent process:

```bash
sandspy watch --dashboard
```

### 2. The Headless Daemon
To run Sandspy silently in the background (perfect for CI/CD or continuous monitoring):

```bash
sandspy watch
```

### 3. Generate HTML Audit Reports
After an agent session cleanly exits, generate a VC-grade brutalist HTML report to review exactly what files and networks it touched.

```bash
sandspy history                  # See recent sessions
sandspy report --session <ID> --format Html
```

## Under The Hood

Sandspy is not a sloppy python wrapper. It is enterprise-grade Rust infrastructure:
- **Lock-Free Event Bus**: Powered by `tokio` multi-threaded MPSC channels handling >10,000 events/sec.
- **Cross-Platform**: Operates flawlessly across Windows (`Win32`), Linux (`procfs`), and macOS.
- **Zero-Friction Engine**: Does not require root elevation or messy kernel drivers to observe process network tables.

---
<div align="center">
  <i>"Trust your agents. Verify their execution."</i>
</div>
