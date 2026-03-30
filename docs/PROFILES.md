# Sandspy Profile Configuration Schema

To allow infinite extensibility without modifying core Rust code, Sandspy utilizes TOML configurations stored locally in the `profiles/` directory.

We call these definition files "Agent Profiles."

---

## Example Profile

```toml
# profiles/claude-code.toml
name = "Claude Code"
version = "1.0.0"
description = "Anthropic's CLI-based autonomous programming agent."

# The literal executable binaries tracked by the daemon
processes = [
    "claude", 
    "claude-mcp"
]

[noise_filters]
# Regex patterns of files that are noisy internal telemetry we shouldn't alert for.
ignored_files = [
    "\\.claude\\.json",
    "\\.mcp/*"
]

# Absolute or relative directories to globally ignore file access within. 
ignored_directories = [
    "~/.claude/cache/",
    "~/.mcp/telemetry/"
]
```

## Schema Map

### Root Metadata

- **`name`** *(String, Required)*: The presentation name inside the Sandspy UI Dashboard (e.g., `"Cursor"`, `"OpenDevin"`).
- **`version`** *(String, Optional)*: Profile manifest version notation.
- **`description`** *(String, Optional)*: Explains the specific use-case of the agent to the user natively interacting.
- **`processes`** *(Array[String], Required)*: The critical tracking mechanism. An exhaustive array of literal OS-level processes Sandspy will attempt to hunt on launch. Example: `["cursor.exe", "cursor-server"]`.

### `[noise_filters]` Object
These parameters establish "Safe" zones. These paths define telemetry or operations that inherently occur as part of standard agent lifecycle routines, avoiding flooding the intelligence matrix with "Critical" file-read alerts.

- **`ignored_files`** *(Array[String], Optional)*: Precise regex boundaries for safe dotfiles and binaries exclusively used internally.
- **`ignored_directories`** *(Array[String], Optional)*: Absolute or platform-normalized relative (like `~/.config`) application cache bounds. Any I/O interaction passing through these paths is instantly discarded in the UI state.
