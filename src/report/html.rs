use crate::events::{Event, EventKind};
use crate::report::{extract_findings, SessionMetadata};
use chrono::TimeZone;

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
     .replace('<', "&lt;")
     .replace('>', "&gt;")
     .replace('"', "&quot;")
     .replace('\'', "&#39;")
}

pub fn build_html_report(metadata: &SessionMetadata, events: &[Event]) -> String {
    let findings = extract_findings(events);
    
    // Build findings HTML
    let mut findings_html = String::new();
    if findings.is_empty() {
        findings_html.push_str("<div class='p-4 text-gray-500 italic'>No high-risk findings detected.</div>");
    } else {
        for finding in &findings {
            let color = match finding.severity {
                crate::events::RiskLevel::Critical => "text-red-500 bg-red-500/10 border-red-500/20",
                crate::events::RiskLevel::High => "text-orange-500 bg-orange-500/10 border-orange-500/20",
                crate::events::RiskLevel::Medium => "text-yellow-500 bg-yellow-500/10 border-yellow-500/20",
                crate::events::RiskLevel::Low => "text-blue-500 bg-blue-500/10 border-blue-500/20",
            };
            let sev_str = match finding.severity {
                crate::events::RiskLevel::Critical => "CRITICAL",
                crate::events::RiskLevel::High => "HIGH",
                crate::events::RiskLevel::Medium => "MEDIUM",
                crate::events::RiskLevel::Low => "LOW",
            };
            
            findings_html.push_str(&format!(
                "<div class='flex items-start gap-3 p-3 border-b border-gray-800/50 hover:bg-white/[0.02] transition-colors'>
                    <div class='mt-0.5 px-2 py-0.5 text-xs font-bold rounded border {}'>{}</div>
                    <div class='text-sm text-gray-300 font-mono break-all'>{}</div>
                </div>",
                color, sev_str, escape_html(&finding.message)
            ));
        }
    }

    // Build timeline HTML (last 50 events)
    let mut feed_html = String::new();
    let mut count = 0;
    for event in events.iter().rev() {
        if count >= 50 { break; }
        
        let time_str = format!("{}", event.timestamp.format("%H:%M:%S"));
        
        let (icon, color, label, details) = match &event.kind {
            EventKind::FileRead { path, .. } => ("📄", "text-blue-400", "File Read", path.display().to_string()),
            EventKind::FileWrite { path, .. } => ("💾", "text-green-400", "File Write", path.display().to_string()),
            EventKind::FileDelete { path } => ("🗑️", "text-red-400", "File Delete", path.display().to_string()),
            EventKind::ProcessSpawn { cmdline, .. } => ("⚙️", "text-gray-400", "Process Spawn", cmdline.clone()),
            EventKind::ProcessExit { .. } => { continue; } // Skip noise
            EventKind::NetworkConnection { domain, remote_addr, remote_port, category, .. } => {
                let target = domain.clone().unwrap_or_else(|| remote_addr.clone());
                let cat_str = format!("{:?}", category);
                ("🌐", "text-purple-400", "Network", format!("{}:{} [{}]", target, remote_port, cat_str))
            },
            EventKind::ShellCommand { command, .. } => ("$_", "text-yellow-400", "Command", command.clone()),
            EventKind::SecretAccess { name, .. } => ("🔑", "text-red-500", "Secret Detected", name.clone()),
            EventKind::EnvVarRead { name, .. } => ("📦", "text-cyan-400", "Env Read", name.clone()),
            EventKind::ClipboardRead { .. } => ("📋", "text-gray-400", "Clipboard", "Read operation".to_string()),
            EventKind::Alert { message, .. } => ("⚠️", "text-orange-500", "Alert", message.clone()),
            _ => ("•", "text-gray-500", "Other", "Unknown event".to_string())
        };

        feed_html.push_str(&format!(
            "<div class='flex items-center gap-3 py-1.5 border-b border-gray-800/30 font-mono text-xs hover:bg-white/[0.02]'>
                <div class='text-gray-500 w-16 shrink-0'>{}</div>
                <div class='w-6 text-center'>{}</div>
                <div class='w-24 shrink-0 {} truncate'>{}</div>
                <div class='text-gray-300 truncate'>{}</div>
                <div class='ml-auto text-gray-600 text-[10px] w-8 text-right'>+{}</div>
            </div>",
            time_str, icon, color, label, escape_html(&details), event.risk_score
        ));
        
        count += 1;
    }

    let template = format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sandspy Audit Report - {agent_name}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body {{
            background-color: #0d1117;
            color: #c9d1d9;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
        }}
        .glass-panel {{
            background: rgba(22, 27, 34, 0.6);
            backdrop-filter: blur(12px);
            border: 1px solid rgba(48, 54, 61, 0.5);
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
        }}
    </style>
</head>
<body class="min-h-screen p-8 antialiased">
    <div class="max-w-5xl mx-auto space-y-6">
        
        <!-- Header -->
        <header class="flex items-end justify-between border-b border-gray-800 pb-6">
            <div>
                <div class="flex items-center gap-3 mb-2">
                    <span class="text-3xl">🕵️‍♂️</span>
                    <h1 class="text-3xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-blue-400 to-indigo-500 tracking-tight">
                        Sandspy Audit
                    </h1>
                </div>
                <p class="text-gray-400 font-mono text-sm tracking-wide">ZERO-TRUST AGENT ACTIVITY REPORT</p>
            </div>
            <div class="text-right">
                <p class="text-sm text-gray-500 font-mono">Generated on</p>
                <p class="text-lg text-gray-300 font-mono">{date}</p>
            </div>
        </header>

        <!-- Top Metrics -->
        <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div class="glass-panel rounded-xl p-5">
                <p class="text-xs text-gray-500 tracking-wider font-semibold uppercase mb-1">Target Agent</p>
                <p class="text-2xl font-mono text-white truncate">{agent_name}</p>
            </div>
            <div class="glass-panel rounded-xl p-5">
                <p class="text-xs text-gray-500 tracking-wider font-semibold uppercase mb-1">Duration</p>
                <p class="text-2xl font-mono text-white">{duration}s</p>
            </div>
            <div class="glass-panel rounded-xl p-5">
                <p class="text-xs text-gray-500 tracking-wider font-semibold uppercase mb-1">Total Events</p>
                <p class="text-2xl font-mono text-white">{events_count}</p>
            </div>
            <div class="glass-panel rounded-xl p-5 border-t-4 {risk_color}">
                <p class="text-xs text-gray-500 tracking-wider font-semibold uppercase mb-1">Net Risk Score</p>
                <p class="text-3xl font-mono font-bold text-white">{risk_score}</p>
            </div>
        </div>

        <!-- Two Column Layout -->
        <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
            
            <!-- Findings Panel (Left 1/3) -->
            <div class="glass-panel rounded-xl flex flex-col h-[600px]">
                <div class="p-4 border-b border-gray-800 bg-black/20">
                    <h2 class="text-sm font-semibold text-gray-300 uppercase tracking-widest flex items-center gap-2">
                        <span class="text-red-400">⚠️</span> Detected Findings
                    </h2>
                </div>
                <div class="flex-1 overflow-y-auto">
                    {findings_html}
                </div>
            </div>

            <!-- Timeline Panel (Right 2/3) -->
            <div class="lg:col-span-2 glass-panel rounded-xl flex flex-col h-[600px]">
                <div class="p-4 border-b border-gray-800 bg-black/20 flex justify-between items-center">
                    <h2 class="text-sm font-semibold text-gray-300 uppercase tracking-widest flex items-center gap-2">
                        <span class="text-blue-400">⏱️</span> Event Timeline (Last 50)
                    </h2>
                    <span class="text-xs text-gray-500 font-mono">LIVE TRACE</span>
                </div>
                <div class="p-2 flex-1 overflow-y-auto bg-[#0a0c10]">
                    {feed_html}
                </div>
            </div>
        </div>
        
        <footer class="text-center pt-8 text-xs text-gray-600 font-mono">
            Powered by Sandspy • Rust Performance Engine • Zero-Trust Developer Tooling
        </footer>
    </div>
</body>
</html>"#,
        agent_name = metadata.agent_name,
        date = metadata.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
        duration = metadata.duration,
        events_count = metadata.event_count,
        risk_score = metadata.risk_score,
        risk_color = if metadata.risk_score > 50 { "border-t-red-500" } else if metadata.risk_score > 20 { "border-t-orange-500" } else { "border-t-blue-500" },
        findings_html = findings_html,
        feed_html = feed_html
    );

    template
}
