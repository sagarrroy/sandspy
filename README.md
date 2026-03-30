<div align="center">
  <h1>S A N D S P Y</h1>
  <p><strong>Zero-Friction Security Telemetry for Autonomous AI Agents</strong></p>
  
  <a href="https://github.com/user/sandspy/actions"><img src="https://img.shields.io/github/actions/workflow/status/user/sandspy/ci.yml?branch=main&style=for-the-badge&color=2BB4AB" alt="CI Status"></a>
  <a href="https://github.com/user/sandspy/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg?style=for-the-badge&color=2BB4AB" alt="License"></a>
</div>

---

### The Problem
We all love using autonomous AI coding agents like Cursor, Windsurf, Claude Code, and Aider to accelerate our workflows. However, these tools require local shell execution and extensive filesystem access to function optimally. 

**This introduces an enormous blind spot.** When an agent is navigating your machine at 1,000 WPM, it becomes nearly impossible to verify structurally safe behavior:
- What `.env` config files or SSH keys did it read?
- Did it accidentally copy your Stripe tokens into the systemic clipboard?
- Did a community script or CLI tool ping an unknown external telemetry server?

**Sandspy visualizes the invisible.** It is a lightweight, background sensor designed specifically to audit AI coding agents in real-time, giving you total peace of mind without slowing down your development.

<br>

<div align="center">
  <!-- TODO: Replace with actual asset path before launch -->
  <img src="https://raw.githubusercontent.com/user/sandspy/main/assets/dashboard.gif" alt="Sandspy TUI Dashboard in Action" width="800" style="border: 1px solid #333; border-radius: 4px;">
</div>

<br>

## ✨ Features

- 🎯 **Auto-Attach**: Instantly discovers and hooks into active Agent PIDs (Cursor, Windsurf, Aider, etc.) with zero configuration required.
- 📡 **Deep Network Forensics**: Intercepts and categorizes every background `TCP/UDP` connection the agent initiates.
- 🔐 **Regex Secret Sniffing**: Memory-safe memory scanning. Instantly triggers **CRITICAL** risk alerts if the agent touches an AWS key, Stripe live token, or OpenAI secret.
- 📝 **Clipboard Monitoring**: Detects when malicious shell commands or agent responses poison your systemic clipboard.
- 🛡️ **Self-Healing Daemon**: If the AI process exits, the Sandspy daemon silently resets and waits in an infinite loop to seamlessly re-attach to the next spawned process.
- 📊 **Beautiful HTML Audits**: Generates stunning, minimalist HTML executive summaries for your team to review post-session telemetry.

## 🚀 Quick Start

### Installation

Sandspy is a lightweight Rust binary. Since it is currently natively hosted on GitHub, install it directly like this:

```bash
cargo install --git https://github.com/YOUR_USERNAME/sandspy.git
```
*(Requires Rust 1.88+)*

### 1. The Real-Time Dashboard
To open the 60fps telemetry terminal UI and automatically hook into the nearest AI agent process:

```bash
sandspy watch --dashboard
```

### 2. The Headless Daemon
To run Sandspy silently in the background (perfect for continuous monitoring):

```bash
sandspy watch
```

### 3. Generate HTML Audit Reports
After an agent session cleanly exits, generate a beautiful HTML report to review exactly what files and networks it touched.

```bash
sandspy history                  # See recent sessions
sandspy report --session <ID> --format Html
```

## 🏗️ Under The Hood

Sandspy is designed for raw performance and enterprise-grade memory safety. 
- **Lock-Free Event Bus**: Powered by `tokio` multi-threaded MPSC channels handling >10,000 events/sec without blocking your terminal.
- **Cross-Platform**: Operates flawlessly across Windows (`Win32` / Native APIs), Linux (`procfs`), and macOS.
- **Zero-Friction Engine**: Does not require root elevation (`sudo`) or complex kernel drivers to observe process network tables. It safely hooks from standard user-space.

## ❤️ Contributing

Sandspy is completely open-source and we would **love** your help to make it better! We want to support every AI agent in the world, and we need the community to help us establish baseline security.

Here are ways you can easily contribute today:
1. **Add an Agent Profile**: Did we miss an AI agent? You can add support for it in 2 minutes without knowing Rust. Just create a simple TOML configuration file in the `profiles/` directory. Check out [CONTRIBUTING_PROFILES.md](./CONTRIBUTING_PROFILES.md) for a quick guide!
2. **Improve OS Abstractions**: Expand our memory hooks for macOS and Linux.
3. **Regex Expansion**: Help us build out more complex Regex algorithms in `src/analysis/secrets.rs` to detect obscure database connection strings.

Please check out our detailed [CONTRIBUTING.md](./CONTRIBUTING.md) to get started!

---
<div align="center">
  <i>"Trust your agents. Verify their execution."</i>
</div>
