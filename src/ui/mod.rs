// sandspy::ui — TUI runner and module exports (Steps 3.2 + 3.6)
//
// Exports all UI submodules. The `run_dashboard` function implements
// the full 30fps Ratatui event loop with keyboard navigation.

pub mod alerts_panel;
pub mod app;
pub mod dashboard;
pub mod diff_viewer;
pub mod files_panel;
pub mod live;
pub mod network_panel;
pub mod summary;
pub mod summary_panel;
pub mod theme;

use crate::events::Event;
use crate::ui::app::{App, Tab};
use crate::ui::live::SessionStats;
use anyhow::Result;
use crossterm::{
    event::{self, Event as CEvent, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Frame, Terminal};
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;

/// Run the full interactive TUI dashboard.
///
/// Blocks until the user quits (q / Ctrl+C).
/// Returns a SessionStats snapshot so main.rs can print the post-session summary.
pub async fn run_dashboard(
    mut rx: mpsc::Receiver<Event>,
    _agent_label: String,
    _agent_pid: Option<u32>,
    no_color: bool,
) -> Result<SessionStats> {
    let app = Arc::new(Mutex::new(App::new(None, no_color)));
    let app_writer = app.clone();

    // Spawn background task: receives monitor events → updates App state
    let receiver_handle = tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            if let Ok(mut state) = app_writer.lock() {
                state.ingest_event(event);
            }
        }
    });

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.hide_cursor()?;

    // Render loop at ~30fps (33ms per frame)
    loop {
        // Draw
        {
            let state = app.lock().unwrap();
            terminal.draw(|f: &mut Frame| render_frame(f, &state))?;
        }

        // Non-blocking keyboard poll — Duration::ZERO means check and return immediately
        while event::poll(Duration::ZERO)? {
            if let Ok(CEvent::Key(key)) = event::read() {
                let mut state = app.lock().unwrap();
                handle_key(&mut state, key.code, key.modifiers);
            }
        }

        // Check quit flag
        if app.lock().unwrap().should_quit {
            break;
        }

        // Yield to tokio for 33ms (lets the receiver task run)
        tokio::time::sleep(Duration::from_millis(33)).await;
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    drop(terminal);

    receiver_handle.abort();

    // Build session stats from app state for the post-summary
    let state = app.lock().unwrap();
    let stats = SessionStats {
        event_count: state.events.len(),
        risk_score: state.risk.score,
        start: std::time::Instant::now(),
        events: state.events.iter().cloned().collect(),
        files_read: state.stats.files_read,
        files_written: state.stats.files_written,
        net_connections: state.stats.net_connections,
        net_unknown: state.stats.net_unknown,
        commands: state.stats.commands_total,
        secrets: state.stats.secrets_accessed,
        alerts: state.findings.len(),
        clipboard_reads: state.stats.clipboard_reads,
    };

    Ok(stats)
}

// ─── Render dispatcher ───────────────────────────────────────────────────────

fn render_frame(frame: &mut Frame, app: &App) {
    let area = frame.area();
    match app.active_tab {
        Tab::Dashboard => dashboard::render(frame, area, app),
        Tab::Files => files_panel::render(frame, area, app),
        Tab::Network => network_panel::render(frame, area, app),
        Tab::Diffs => diff_viewer::render(frame, area, app),
        Tab::Summary => summary_panel::render(frame, area, app),
        Tab::Alerts => alerts_panel::render(frame, area, app),
    }
}

// ─── Keyboard handler (Step 3.6) ─────────────────────────────────────────────

fn handle_key(app: &mut App, code: KeyCode, modifiers: KeyModifiers) {
    match code {
        // Quit — only 'q' and Ctrl+C
        KeyCode::Char('q') => app.should_quit = true,
        KeyCode::Char('c') if modifiers.contains(KeyModifiers::CONTROL) => {
            app.should_quit = true;
        }

        // Escape — go back to dashboard (or quit if already there)
        KeyCode::Esc => {
            if app.active_tab == Tab::Dashboard {
                app.should_quit = true;
            } else {
                app.switch_tab(Tab::Dashboard);
            }
        }

        // Tab switching — letters
        KeyCode::Char('f') => app.switch_tab(Tab::Files),
        KeyCode::Char('n') => app.switch_tab(Tab::Network),
        KeyCode::Char('d') => app.switch_tab(Tab::Diffs),
        KeyCode::Char('s') => app.switch_tab(Tab::Summary),
        KeyCode::Char('a') => app.switch_tab(Tab::Alerts),
        KeyCode::Char('1') => app.switch_tab(Tab::Dashboard),
        KeyCode::Char('2') => app.switch_tab(Tab::Files),
        KeyCode::Char('3') => app.switch_tab(Tab::Network),
        KeyCode::Char('4') => app.switch_tab(Tab::Diffs),
        KeyCode::Char('5') => app.switch_tab(Tab::Summary),
        KeyCode::Char('6') => app.switch_tab(Tab::Alerts),

        // Tab cycling
        KeyCode::Tab => app.switch_tab(app.active_tab.next()),
        KeyCode::BackTab => app.switch_tab(app.active_tab.prev()),

        // Scroll — offset=0 is live tail, higher = further back in time
        // j/Down = older events = increase offset
        KeyCode::Char('j') | KeyCode::Down => app.scroll_down(),
        // k/Up = newer events = decrease offset toward live
        KeyCode::Char('k') | KeyCode::Up => app.scroll_up(),
        // G = snap to live tail (offset=0)
        KeyCode::Char('G') => app.scroll_top(),
        // g = go to oldest possible
        KeyCode::Char('g') => app.scroll_offset = 999_999,
        // PageUp/PageDown jump 10 at a time
        KeyCode::PageUp => {
            for _ in 0..10 {
                app.scroll_down();
            }
        }
        KeyCode::PageDown => {
            for _ in 0..10 {
                app.scroll_up();
            }
        }

        _ => {}
    }
}
