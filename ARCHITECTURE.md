# Sandspy Architecture

Sandspy is a high-performance, zero-friction security daemon designed to run entirely in user-space without requiring administrative or root privileges. It provides real-time observability of autonomous AI agent processes (e.g., Cursor, Windsurf, Claude Code) by systematically hooking into the process tree and network tables.

## System Design
The core engine is built strictly in memory-safe Rust using the `tokio` asynchronous runtime. 

1. **The Watcher Daemon:** A cross-platform process crawler (`sysinfo` on Windows/MacOS, `procfs` on Linux) traverses the OS process table to auto-detect target binaries matching designated agent profiles.
2. **The Event Bus:** Once a target PID is identified, multiple concurrent monitors (Files, Process, Memory, Network) spawn and begin scraping telemetry. Every action is immediately packaged into an `Event` struct and pushed through a high-bandwidth lock-free MPSC (Multi-Producer, Single-Consumer) channel.
3. **The Intelligence Engine:** `src/events.rs`. Every ingested event passes through a deterministic regex and heuristics engine that dynamically assigns a `RiskScore`. For example, touching `.env` or copying a string matching `sk-[a-zA-Z0-9]+` (OpenAI/Anthropic keys) applies a critical multiplier.
4. **The Collector:** The receiver thread aggregates events into an abstract UI State (`AppState`). This ensures the presentation layer never blocks the telemetry telemetry scraping. 
5. **The Storage Adapter:** Upon target process exit, the daemon dynamically writes the structured `Event` feed to disk as compressed `JSONL`, and cleanly terminates or self-heals depending on configuration. 

## Module Overview

- **`src/main.rs`**: Application entrypoint and CLI router (`clap`).
- **`src/daemon.rs`**: The heartbeat. Manages `tokio` workers, the MPSC channel spawning, and agent auto-detection retry logic.
- **`src/ui/`**: `ratatui` state machines rendering the 60fps local terminal dashboard.
- **`src/monitor/`**: OS-specific hardware and filesystem integration code.
- **`src/analysis/`**: Contains the regex intelligence suites for isolating AWS, Stripe, JWTs, and LLM provider keys from memory streams.
- **`src/report/`**: HTML templating engine generating the Brutalist Vercel-style executive summaries.
