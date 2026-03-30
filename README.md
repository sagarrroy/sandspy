<div align="center">
  <h1>🕵️‍♂️ Sandspy</h1>
  <p><b>Real-time security auditing and zero-trust monitoring for AI Coding Agents.</b></p>
  
  <p>
    <a href="https://github.com/sagarrroy/sandspy/actions"><img src="https://img.shields.io/badge/build-passing-brightgreen" alt="Build Status"></a>
    <a href="https://crates.io/crates/sandspy"><img src="https://img.shields.io/crates/v/sandspy.svg" alt="Crates.io"></a>
    <a href="https://github.com/sagarrroy/sandspy/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License"></a>
  </p>
</div>

---

**Sandspy** is a lightweight, blazing-fast Rust daemon that watches exactly what your AI coding agents (Claude Code, Cursor, Windsurf, Aider) are doing on your machine in real-time. 

AI agents are incredibly powerful, but giving an autonomous stochastic model full access to your filesystem, network, and shell is a massive security risk. **Sandspy gives you back your visibility.**

![Sandspy Dashboard](https://github.com/sagarrroy/sandspy/assets/placeholder-dashboard.png)

## ✨ Why Sandspy?

Vibe-coding is the future, but raw terminal execution is dangerous. Sandspy attaches directly to the process tree of your AI agent and intercepts its activity without slowing it down. 

- **🔍 File System Auditing:** See every file the agent reads, modifies, or deletes.
- **🔐 Secret Detection Engine:** Instantly alerts you if the agent touches, generates, or copies sensitive credentials (AWS, Anthropic, OpenAI, Stripe, Private Keys, etc.).
- **🌐 Network De-anonymization:** Tracks every outbound HTTP/TCP request the agent makes and categorizes the destination IP (Google, AWS, Azure, Cloudflare) so you know exactly where your code is being sent.
- **💻 Shell Command Tracking:** Intercepts and flags dangerous terminal commands spawned by the agent.
- **📋 Clipboard & Env Profiling:** Warns you if the agent accesses sensitive environment variables or copies secrets to your clipboard.

## 🚀 QuickStart

Install Sandspy globally via Cargo:
```bash
cargo install --path .
```

To monitor an agent, simply run `sandspy watch` and point it at the process name. 

**Monitoring Cursor:**
```bash
sandspy watch --dashboard "Code"
```

**Monitoring Claude Code:**
```bash
sandspy watch --dashboard "claude"
```

**Monitoring Antigravity:**
```bash
sandspy watch --dashboard "Antigravity"
```

## ⌨️ TUI Keybindings

Sandspy features a high-performance terminal UI (TUI) powered by `ratatui`.

| Key | Action |
|---|---|
| `1` | Dashboard (Live Feed + Risk Meter) |
| `2` | File Diff Viewer |
| `3` | Network Traffic |
| `a` | Alerts & High-Risk Findings |
| `j` / `↓` | Scroll older |
| `k` / `↑` | Scroll newer |
| `G` | Snap to live tail |
| `q` | Quit |

## 🧠 How it Works

Sandspy does not require admin privileges (for basic mode). It relies on OS-level polling and memory-safe process tree traversal:
1. It anchors to the target Process ID (PID) and its parent executable directory.
2. It walks the entire tree, discovering every background language server, node worker, and shell subprocess spawned by the agent.
3. It aggregates `notify` filesystem events, `netstat2` socket tables, and `sysinfo` process tables.
4. It passes all strings through a highly optimized, embedded regex engine to calculate a **live danger score**.

## 🛡️ License

MIT License. See `LICENSE` for more information. Built for the vibe-coding generation.
