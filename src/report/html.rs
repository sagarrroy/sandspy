use crate::events::Event;
use crate::report::{extract_findings, SessionMetadata};
use chrono::Local;

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
        findings_html.push_str("<div class='p-4 text-gray-500 text-sm font-mono'>0 high-risk findings detected.</div>");
    } else {
        for finding in &findings {
            let color = match finding.severity {
                crate::events::RiskLevel::Critical => "text-red-500 border-red-500/20",
                crate::events::RiskLevel::High => "text-orange-500 border-orange-500/20",
                crate::events::RiskLevel::Medium => "text-yellow-500 border-yellow-500/20",
                crate::events::RiskLevel::Low => "text-blue-500 border-blue-500/20",
            };
            let sev_str = match finding.severity {
                crate::events::RiskLevel::Critical => "CRITICAL",
                crate::events::RiskLevel::High => "HIGH",
                crate::events::RiskLevel::Medium => "MEDIUM",
                crate::events::RiskLevel::Low => "LOW",
            };
            
            findings_html.push_str(&format!(
                "<div class='flex items-start gap-4 p-4 border-b border-[#222] transition-colors hover:bg-[#111]'>
                    <div class='mt-0.5 px-2 py-0.5 text-[10px] tracking-wider font-bold rounded border uppercase {}'>{}</div>
                    <div class='text-sm text-[#eaeaea] font-mono break-all leading-relaxed'>{}</div>
                </div>",
                color, sev_str, escape_html(&finding.message)
            ));
        }
    }

    // Build timeline HTML (last 500 events to provide real logs)
    let mut feed_html = String::new();
    let mut count = 0;
    for event in events.iter().rev() {
        if count >= 500 { break; }
        
        // Convert Utc strictly to Local Timezone for display
        let local_time = event.timestamp.with_timezone(&Local);
        let time_str = format!("{}", local_time.format("%H:%M:%S"));
        
        let (color, label, details) = match &event.kind {
            crate::events::EventKind::FileRead { path, .. } => ("text-[#888]", "FILE_READ", path.display().to_string()),
            crate::events::EventKind::FileWrite { path, .. } => ("text-[#eaeaea]", "FILE_WRITE", path.display().to_string()),
            crate::events::EventKind::FileDelete { path } => ("text-red-400", "FILE_DELETE", path.display().to_string()),
            crate::events::EventKind::ProcessSpawn { cmdline, .. } => ("text-[#888]", "PROC_SPAWN", cmdline.clone()),
            crate::events::EventKind::ProcessExit { .. } => { continue; } 
            crate::events::EventKind::NetworkConnection { domain, remote_addr, remote_port, .. } => {
                let target = domain.clone().unwrap_or_else(|| remote_addr.clone());
                ("text-blue-400", "NETWORK_TCP", format!("{}:{}", target, remote_port))
            },
            crate::events::EventKind::ShellCommand { command, .. } => ("text-yellow-400", "SHELL_EXEC", command.clone()),
            crate::events::EventKind::SecretAccess { name, .. } => ("text-red-500", "SECRET_HIT", name.clone()),
            crate::events::EventKind::EnvVarRead { name, .. } => ("text-cyan-400", "ENV_READ", name.clone()),
            crate::events::EventKind::ClipboardRead { .. } => ("text-[#888]", "CLIPBOARD", "Read operation".to_string()),
            crate::events::EventKind::Alert { message, .. } => ("text-orange-500", "ALERT_SYS", message.clone()),
            _ => ("text-[#555]", "UNKNOWN", "Unknown event".to_string())
        };

        let risk_badge = if event.risk_score > 0 {
            format!("<div class='w-8 text-right text-red-500 font-bold'>+{}</div>", event.risk_score)
        } else {
            String::new()
        };

        feed_html.push_str(&format!(
            "<div class='flex items-center gap-4 py-2 border-b border-[#222] font-mono text-[11px] hover:bg-[#111] px-4'>
                <div class='text-[#666] w-16 shrink-0'>{}</div>
                <div class='w-24 shrink-0 font-bold {}'>{}</div>
                <div class='text-[#ccc] overflow-x-auto whitespace-nowrap flex-1 scrollbar-hide mr-4'>{}</div>
                {}
            </div>",
            time_str, color, label, escape_html(&details), risk_badge
        ));
        
        count += 1;
    }

    let local_session_time = metadata.timestamp.with_timezone(&Local);
    
    let template = format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sandspy Session // {agent_name}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
    <style>
        body {{
            background-color: #000000;
            color: #eaeaea;
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
        }}
        .font-mono {{
            font-family: 'JetBrains Mono', monospace;
        }}
        .metric-box {{
            background: #000;
            border: 1px solid #333;
        }}
        /* Minimalist scrollbar */
        ::-webkit-scrollbar {{
            width: 8px;
            height: 8px;
        }}
        ::-webkit-scrollbar-track {{
            background: #000;
        }}
        ::-webkit-scrollbar-thumb {{
            background: #333;
            border-radius: 4px;
        }}
        ::-webkit-scrollbar-thumb:hover {{
            background: #555;
        }}
        /* Hidden scrollbars for inline horizontal content */
        .scrollbar-hide::-webkit-scrollbar {{
            display: none;
        }}
        .scrollbar-hide {{
            -ms-overflow-style: none; /* IE and Edge */
            scrollbar-width: none; /* Firefox */
        }}
    </style>
</head>
<body class="min-h-screen p-8 antialiased selection:bg-white selection:text-black">
    <div class="max-w-6xl mx-auto space-y-6">
        
        <!-- Header Minimalist -->
        <header class="flex items-end justify-between border-b-2 border-[#333] pb-6">
            <div>
                <h1 class="text-2xl font-bold tracking-tight text-white mb-1">
                    SANDSPY_AUDIT
                </h1>
                <p class="text-[#888] font-mono text-xs uppercase tracking-widest">Zero-Trust Agent Telemetry</p>
            </div>
            <div class="text-right">
                <p class="text-xs text-[#666] font-mono uppercase tracking-widest mb-1">Generated</p>
                <p class="text-sm text-[#eaeaea] font-mono">{date}</p>
            </div>
        </header>

        <!-- Top Metrics (Vercel Style) -->
        <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div class="metric-box p-5 rounded-md">
                <p class="text-[10px] text-[#888] font-bold uppercase tracking-widest mb-2">Target Agent</p>
                <p class="text-xl font-mono text-white truncate">{agent_name}</p>
            </div>
            <div class="metric-box p-5 rounded-md">
                <p class="text-[10px] text-[#888] font-bold uppercase tracking-widest mb-2">Duration</p>
                <p class="text-xl font-mono text-white">{duration}s</p>
            </div>
            <div class="metric-box p-5 rounded-md">
                <p class="text-[10px] text-[#888] font-bold uppercase tracking-widest mb-2">Total Events</p>
                <p class="text-xl font-mono text-white">{events_count}</p>
            </div>
            <div class="metric-box p-5 rounded-md border border-t-2 {risk_border} bg-[#111]">
                <p class="text-[10px] text-[#888] font-bold uppercase tracking-widest mb-2">Risk Score</p>
                <p class="text-2xl font-mono font-bold {risk_text}">{risk_score}</p>
            </div>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-3 gap-6 pt-4">
            
            <!-- Findings Panel -->
            <div class="metric-box rounded-md flex flex-col h-[650px]">
                <div class="p-4 border-b border-[#333] bg-[#000]">
                    <h2 class="text-xs font-bold text-[#eaeaea] uppercase tracking-widest">
                        High-Risk Findings
                    </h2>
                </div>
                <div class="flex-1 overflow-y-auto bg-[#000]">
                    {findings_html}
                </div>
            </div>

            <!-- Timeline Panel -->
            <div class="lg:col-span-2 metric-box rounded-md flex flex-col h-[650px]">
                <div class="p-4 border-b border-[#333] bg-[#000] flex justify-between items-center">
                    <h2 class="text-xs font-bold text-[#eaeaea] uppercase tracking-widest">
                        Event Trajectory
                    </h2>
                    <span class="text-[10px] text-[#666] font-mono tracking-widest uppercase pb-1">500 entries shown</span>
                </div>
                <div class="flex-1 overflow-y-auto bg-[#000]">
                    {feed_html}
                </div>
            </div>
        </div>
        
        <footer class="text-center pt-10 pb-4 text-[10px] text-[#555] font-mono tracking-widest uppercase">
            SANDSPY
        </footer>
    </div>
</body>
</html>"#,
        agent_name = metadata.agent_name,
        date = local_session_time.format("%Y-%m-%d %H:%M:%S %Z"),
        duration = metadata.duration,
        events_count = metadata.event_count,
        risk_score = metadata.risk_score,
        risk_border = if metadata.risk_score > 50 { "border-t-red-500 border-red-900/40 border-l-[#333] border-r-[#333] border-b-[#333]" } 
                     else if metadata.risk_score > 20 { "border-t-orange-500 border-orange-900/40 border-l-[#333] border-r-[#333] border-b-[#333]" } 
                     else { "border-t-blue-500 border-[#333]" },
        risk_text = if metadata.risk_score > 50 { "text-red-500" } else if metadata.risk_score > 20 { "text-orange-500" } else { "text-white" },
        findings_html = findings_html,
        feed_html = feed_html
    );

    template
}
