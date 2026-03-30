# Adding a New AI Agent to Sandspy

Sandspy uses plain `.toml` files to instantly auto-detect any new AI coding agent. We call these "Agent Profiles." You do **not** need to know how to code in Rust to add a new AI agent!

If there's an agent we forgot (e.g., Codeium, GitHub Copilot CLI, an experimental open-source scraper), follow these steps to contribute a profile to the project.

## Step-by-Step Guide

### 1. Identify the Process
Find out exactly what the AI agent executable is called when running actively on your machine.
- For example, if you open Task Manager (Windows) or `htop` (Mac/Linux), you might see `cursor.exe` or `claude-code`.

### 2. Create the TOML File
Create a new file in the `profiles/` directory of the repository. Name it `agent-name.toml`.

```toml
# profiles/new-agent.toml
name = "MyNewAgent"
description = "A brief description of what this AI code agent does."
processes = ["new-agent", "new-agent.exe", "new-agent-cli"]
```

### 3. Identify Known Directories
AI agents usually read and write to specific system folders (e.g., their own log directories or local AI cache). Tell Sandspy to filter these directories out as "System Noise" so it doesn't pollute the telemetry logs.

```toml
[noise_filters]
# Directories that should be ignored when looking at file-reads
directories = [
    "~/.new-agent",
    "~/.config/new-agent",
    "%APPDATA%\\NewAgent"
]
```

### 4. Create a Pull Request!
That is literally it. Commit your new `agent-name.toml` file and open a Pull Request against our `main` branch. 
Sandspy will automatically parse the TOML file at runtime and users everywhere will instantly gain the ability to monitor your configured agent!
