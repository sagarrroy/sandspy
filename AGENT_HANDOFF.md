# Sandspy — Agent Handoff Doc
> Last updated: 2026-03-31. Paste this entire file into a new chat to resume exactly where we left off.

---

## What is Sandspy?

**Sandspy** is a real-time security monitor / audit tool for AI coding agents (Claude, Gemini, Cursor, Windsurf, etc.) running on a developer's machine. It watches a target process tree and logs:
- Files read/written/deleted (with secret scanning)
- Network connections (with owner labels: Google/AWS/Azure/Cloudflare/Unknown)
- Processes spawned
- Shell commands executed (with danger classification)
- Secrets detected in files, env vars, and clipboard
- Environment variables accessed

It's a **Rust CLI** with a **ratatui TUI** (terminal dashboard). The target audience is vibe coders and developers who want transparency over what their AI agent is doing.

**Run command:**
```
cargo build; cargo run -- watch --dashboard "Antigravity"
```
Replace `"Antigravity"` with whatever agent process name to monitor.

**Project path:** `c:\Users\sagar\Desktop\projects\sandspy`

---

## Repo State (as of handoff)

**Latest commit:** `dad33d4` — `Fix: complete security detection overhaul - embedded patterns, startup scan, risk scores on all events`

**All tests passing:** 30+ tests, 0 failures. Run with `cargo test`.

### Recent commits (newest first):
```
dad33d4  Fix: complete security detection overhaul
13bdfea  Fix: correct j/k scroll direction — j=older, k=newer, G=live
8f5b2e4  Fix: working scroll with live-tail mode, PAUSED indicator, G=live
9d1a3e1  Fix: filter blank events from feed, show IP owner instead of 0B, Google IP ranges
bec39ce  Fix: additive risk scoring, Esc=back, dynamic TUI width, Electron noise filter
```

---

## Architecture

```
src/
├── main.rs                  — CLI entry point (clap)
├── events.rs                — EventKind enum, Event struct, event bus
├── analysis/
│   ├── secrets.rs           ← JUST REWRITTEN — embedded patterns, no file dep
│   └── resolver.rs          — IP → IpCategory (Google/AWS/Cloudflare/etc)
├── monitor/
│   ├── filesystem.rs        ← JUST REWRITTEN — startup scan, risk scores
│   ├── network.rs           — netstat2 polling, IP owner classification
│   ├── process.rs           — sysinfo process tree tracking
│   ├── command.rs           — shell command detection + danger classification
│   ├── environment.rs       ← JUST REWRITTEN — expanded 40+ sensitive var names
│   └── clipboard.rs         — arboard clipboard polling, secret scanning
├── ui/
│   ├── app.rs               — App state, ingest_event, risk accumulation
│   ├── mod.rs               — Key handler, tab routing
│   ├── dashboard.rs         — Main TUI panel (feed, stats, risk bar)
│   └── theme.rs             — Colors, styles
└── platform/
    └── windows.rs           — Windows process tree via ToolHelp32

signatures/
├── expected_apis.toml       — Known-safe domains (Google APIs, GitHub, npm, etc.)
├── suspicious_patterns.toml — (LEGACY — no longer used for secret scanning)
└── trackers.toml            — Tracking/telemetry domains

profiles/
└── agents/                  — Agent process name configs (Antigravity, Cursor, etc.)
```

---

## What Was Fixed In This Session

### 1. Secret Scanner — was completely broken
**Root cause:** `OnceLock` + `fs::read_to_string(current_dir()/signatures/...)`. If CWD was wrong at first call, it silently cached `Vec::new()` forever. **Zero patterns — nothing ever detected.**

**Fix:** `src/analysis/secrets.rs` completely rewritten. Patterns are now **embedded in Rust source** — no file dependency, no failure modes. 15+ patterns covering Anthropic, OpenAI, AWS, GitHub, Stripe, Slack, JWT, private keys, connection strings, env file format.

### 2. Pre-existing secrets never scanned
Filesystem monitor only triggered on `notify` events. A `.env` file that existed before `sandspy` launched was never scanned.

**Fix:** `startup_secret_scan()` in `filesystem.rs` runs at launch, walks the project tree, scans every sensitive file immediately.

### 3. All secret events had risk 0
`Event::new()` always sets `risk_score = 0`. The risk gauge never moved for secrets.

**Fix:** Every `SecretAccess` event now carries calibrated risk: Anthropic/OpenAI key = 25, AWS key = 25, GitHub token = 20, env file = 15, etc.

### 4. Secrets not shown in Alerts panel
`SecretAccess` events were not converted to `Finding` entries.

**Fix:** `app.rs` now creates High-severity findings for `SecretAccess` and Medium findings for sensitive `EnvVarRead`.

### 5. 216.239.x.x Google IPs showed as UNKNOWN
Google's `216.239.x.x` anycast/infrastructure range was not in the CIDR table.

**Fix:** `resolver.rs` now covers: Google (142.x, 216.58/239, 34.x, 35.x, 74.125), AWS (3.x, 52.x, 54.x), Azure (13.x, 20.x, 40.x), Cloudflare (104.16-32, 162.158, 172.64-72).

### 6. Feed showed blank lines
`ProcessExit` events render as empty lines.

**Fix:** `render_feed()` in `dashboard.rs` filters with `is_displayable()` before rendering. Also fixed iterator chain (collect before rev/take).

### 7. Bytes always showed "0B"
`netstat2` never returns byte counts — the column was permanently `0B UNKNOWN`. Made the whole tool look broken.

**Fix:** Replaced the bytes column with an **IP owner label** (`Google`, `AWS`, `Azure`, `Cloudflr`, `unknown`) derived from `infer_owner()` in `dashboard.rs`.

### 8. Scrolling didn't work
`scroll_offset` was tracked in `App` but never used by `render_feed()`.

**Fix:** `render_feed()` now uses a proper scroll window: `offset=0` = live tail, increasing offset = older events. Title shows `[PAUSED ↑N G=live]` when scrolled. Keys:
- `j/↓` = older
- `k/↑` = newer
- `G` = snap to live
- `g` = go to oldest
- `PageUp/PageDown` = jump 10

---

## Known Remaining Issues / Next Steps

### High priority:
1. **Process tree doesn't self-heal** — if the target agent restarts, sandspy loses track of it. Need to re-detect the agent on each poll loop when `tracked_pids` is empty.

2. **Network: no actual byte counting** — `netstat2` doesn't provide it. To get real bytes you'd need ETW (Windows Event Tracing) or WFP (Windows Filtering Platform). Both require admin rights but would give real-time per-connection byte counts. Alternative: use `Get-NetTCPConnection` via PowerShell subprocess for more data.

3. **Command detection is limited** — currently reads the cmdline of spawned processes to infer "dangerous" commands. Doesn't catch shell builtins (e.g., `Remove-Item` typed in a PowerShell that was already running). True detection needs ETW's `Microsoft-Windows-PowerShell` provider.

4. **`FileRead` events never fire** — `notify` (inotify/ReadDirectoryChangesW) only tracks writes and deletes, not reads. `FileRead` events in the schema are never emitted. Fixing this requires ETW's `Microsoft-Windows-Kernel-File` provider (admin) or a driver. For now, the `FileRead` event kind exists in the schema but is dead code.

5. **TUI layout: stats panel text can overflow on narrow terminals** — no responsive truncation in the 4-column stats block.

6. **Sessions aren't automatically exported** — `%USERPROFILE%\.sandspy\sessions\<timestamp>\events.jsonl` accumulates raw JSONL but there's no `report` subcommand to render them as HTML or PDF yet. The `report/json.rs` was planned but not implemented.

7. **No Linux/macOS validation** — code is cross-platform by intent but only tested on Windows.

### Medium priority:
8. **Risk gauge resets on restart** — risk is in-memory only, not persisted across restarts.
9. **`.env` detection only works in the watched directory** — agent might load env vars from parent directories or `~/.env`.
10. **Chromium/Electron noise filter** — was implemented but needs re-validation after the process.rs refactor.

### Nice to have:
11. **Agent profile auto-detection** — currently requires `--dashboard <name>` flag. Should auto-detect known agents from `profiles/agents/`.
12. **Persistent findings** — findings in Alerts panel disappear on restart.
13. **Web dashboard** — pipe events to a local HTTP server for a browser-based view.

---

## Key File Details

### `src/analysis/secrets.rs`
Patterns are embedded as `&[(&'static str, &str)]` tuples in `build_patterns()`. To add a new pattern, just add a line there — no TOML file needed. The `signatures/suspicious_patterns.toml` file is **no longer used** for secret scanning (it's still loaded by the network monitor for domain categorization).

### `src/monitor/filesystem.rs`
Key functions:
- `startup_secret_scan()` — runs at launch, scans existing files
- `emit_secret_access_events_with_source()` — scans a single file and emits `SecretAccess` events with risk scores
- `is_sensitive_path()` — determines if a path should be deeply scanned (`.env`, `.pem`, `.aws/credentials`, etc.)

### `src/ui/app.rs`
- `ingest_event()` — the main event processing function. Updates stats, creates findings, accumulates risk.
- `update_risk()` — **additive** (not max). Each event's `risk_score` is added to the total, capped at 100.
- `scroll_offset` — 0 = live tail, N = show events ending N from bottom

### `src/ui/dashboard.rs`
- `render_feed()` — the live event list. Filters `ProcessExit`, uses scroll_offset window.
- `format_event_line()` — formats each event as a colored Line for ratatui.
- `infer_owner()` — pure function: parses IP octets → returns "Google"/"AWS"/"Azure"/"Cloudflr"/"unknown"

### `src/analysis/resolver.rs`
- `categorize_v4()` — CIDR-based IP classification. Covers all major cloud providers.
- The `IpCategory` is now used as **fallback** in `categorize_target()` in `network.rs` — if no domain resolves and the IP is Google/AWS/Cloudflare, it defaults to `ExpectedApi` instead of `Unknown`.

---

## How to Test Secret Detection

Create a `.env` file in the project root with real-looking keys:
```
ANTHROPIC_API_KEY=sk-ant-api01-aaabbbcccdddeeefffggghhh
OPENAI_API_KEY=sk-proj-abc1234567890abcdefghijklmnopqrstuvwxyz0123
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
STRIPE_SECRET_KEY=sk_live_abcdefghijklmnopqrstuvwxyz12345
```

Sandspy should immediately detect these at startup (via `startup_secret_scan`) and emit `SecretAccess` events with risk scores. The risk gauge should spike. Alerts panel (`[a]`) should show findings.

Then delete the file — sandspy should emit `FileDelete` with +20 risk ("covering tracks").

---

## How Sessions Work

Every `watch` run creates a new session directory:
```
%USERPROFILE%\.sandspy\sessions\<YYYY-MM-DD-HHmmss>\events.jsonl
```

Each line is a JSON-encoded `Event { timestamp, kind, risk_score }`. You can read past sessions to debug detection.

To inspect the latest session:
```powershell
$p = (Get-ChildItem "$env:USERPROFILE\.sandspy\sessions\" | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
Get-Content "$p\events.jsonl" | ForEach-Object { $_ | ConvertFrom-Json } | Select-Object timestamp, @{n='kind';e={($_.kind | Get-Member -MemberType NoteProperty).Name}}, risk_score
```

---

## TUI Key Reference

| Key | Action |
|-----|--------|
| `1` | Dashboard (live feed + stats) |
| `2` | Files tab |
| `3` | Network tab |
| `4` | Diffs tab |
| `5` | Summary tab |
| `a` | Alerts (findings) |
| `j / ↓` | Scroll feed older |
| `k / ↑` | Scroll feed newer |
| `G` | Snap to live tail |
| `g` | Jump to oldest |
| `PageUp` | Jump 10 older |
| `PageDown` | Jump 10 newer |
| `Esc` | Back to Dashboard |
| `q` | Quit |

---

## What the User Cares About

Sagar wants this to be a **viral, impressive tool** that vibe coders would actually use. The goal is **zero friction + immediately impressive output**. Key frustrations from the session:

1. "Nothing ever shows up" — the secret scanner being broken was the #1 issue
2. "0B UNKNOWN" on every network line looked broken — now shows owner names
3. Blank lines in the feed from ProcessExit events — now filtered
4. Scrolling didn't work — now works with PAUSED indicator
5. 216.239.x.x Google IPs falsely flagged as UNKNOWN — now resolved

The user is building this for the developer community ("vibe coders") who are uncomfortable with AI agents having unchecked access to their machine. The pitch: **"see exactly what your AI agent is doing, in real time."**

---

## Next Conversation Starter Suggestions

- "Wire up the report subcommand — export the session as a formatted HTML report"
- "Make agent auto-detection work without needing --dashboard flag"
- "Fix the process tree self-healing when the agent restarts"
- "Add a test script that exercises all detection categories"
- "Improve the TUI — the stats panel needs better layout on narrow terminals"
