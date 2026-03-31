// sandspy::monitor::network — Network connection tracking

use crate::analysis::resolver;
use crate::events::{Event, EventKind, NetCategory};
use crate::monitor::process::PidSet;
use anyhow::{Context, Result};
use netstat2::{get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time;

#[derive(Debug, Deserialize)]
struct SignatureEntry {
    domains: Vec<String>,
    category: Option<String>,
}

#[derive(Debug, Default)]
struct SignatureDb {
    expected_domains: Vec<String>,
    trackers: Vec<SignatureEntry>,
}

pub async fn run(tx: mpsc::Sender<Event>, pids: PidSet) -> Result<()> {
    let signatures = load_signatures().unwrap_or_default();
    let mut seen_connections = HashSet::new();

    loop {
        if tx.is_closed() {
            return Ok(());
        }

        let tracked_pids = {
            let guard = pids.read().await;
            guard.clone()
        };

        if tracked_pids.is_empty() {
            time::sleep(Duration::from_millis(50)).await;
            continue;
        }

        let sockets = match get_sockets_info(
            AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6,
            ProtocolFlags::TCP | ProtocolFlags::UDP,
        ) {
            Ok(sockets) => sockets,
            Err(error) => {
                tracing::warn!(%error, "failed to poll network sockets");
                time::sleep(Duration::from_millis(500)).await;
                continue;
            }
        };

        for socket in sockets {
            let owned_by_tree = socket
                .associated_pids
                .iter()
                .any(|pid| tracked_pids.contains(pid));

            if !owned_by_tree {
                continue;
            }

            let (remote_addr, remote_port) = match socket.protocol_socket_info {
                ProtocolSocketInfo::Tcp(tcp) => (tcp.remote_addr.to_string(), tcp.remote_port),
                ProtocolSocketInfo::Udp(_) => {
                    continue;
                }
            };

            if remote_addr.is_empty() || remote_port == 0 {
                continue;
            }

            // Skip loopback/link-local — these are internal IPC, not interesting
            if remote_addr.starts_with("127.")
                || remote_addr == "::1"
                || remote_addr.starts_with("0.0.0.0")
                || remote_addr.starts_with("fe80:")
            {
                continue;
            }

            let key = format!("{remote_addr}:{remote_port}");
            if !seen_connections.insert(key) {
                continue;
            }

            let (domain, ip_category) = resolver::resolve(&remote_addr);
            let category =
                categorize_target(&remote_addr, domain.as_deref(), ip_category, &signatures);
            let risk_score = match category {
                NetCategory::Unknown => 8,
                NetCategory::Tracking => 5,
                NetCategory::Telemetry => 2,
                NetCategory::ExpectedApi => 0,
            };
            let event = Event::with_risk(
                EventKind::NetworkConnection {
                    remote_addr,
                    remote_port,
                    domain,
                    category,
                    bytes_sent: 0,
                    bytes_recv: 0,
                },
                risk_score,
            );

            if tx.send(event).await.is_err() {
                return Ok(());
            }
        }

        // 50ms poll — fast enough to catch short-lived HTTPS connections
        time::sleep(Duration::from_millis(50)).await;
    }
}

fn load_signatures() -> Result<SignatureDb> {
    let root = std::env::current_dir().context("failed to resolve current directory")?;
    let expected_path = root.join("signatures").join("expected_apis.toml");
    let trackers_path = root.join("signatures").join("trackers.toml");

    let expected_entries = load_signature_map(&expected_path).with_context(|| {
        format!(
            "failed to load expected api signatures: {}",
            expected_path.display()
        )
    })?;
    let tracker_entries = load_signature_map(&trackers_path).with_context(|| {
        format!(
            "failed to load tracker signatures: {}",
            trackers_path.display()
        )
    })?;

    let expected_domains = expected_entries
        .values()
        .flat_map(|entry| entry.domains.clone())
        .collect::<Vec<_>>();

    let trackers = tracker_entries.into_values().collect::<Vec<_>>();

    Ok(SignatureDb {
        expected_domains,
        trackers,
    })
}

fn load_signature_map(path: &Path) -> Result<HashMap<String, SignatureEntry>> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read signature file: {}", path.display()))?;
    let parsed = toml::from_str::<HashMap<String, SignatureEntry>>(&content)
        .with_context(|| format!("failed to parse signature file: {}", path.display()))?;
    Ok(parsed)
}

fn categorize_target(
    target: &str,
    domain: Option<&str>,
    ip_category: crate::analysis::resolver::IpCategory,
    signatures: &SignatureDb,
) -> NetCategory {
    if let Some(domain_name) = domain {
        if signatures
            .expected_domains
            .iter()
            .any(|pattern| domain_matches(pattern, domain_name))
        {
            return NetCategory::ExpectedApi;
        }

        for tracker in &signatures.trackers {
            if tracker
                .domains
                .iter()
                .any(|pattern| domain_matches(pattern, domain_name))
            {
                return match tracker.category.as_deref() {
                    Some("tracking") => NetCategory::Tracking,
                    _ => NetCategory::Telemetry,
                };
            }
        }
    }

    if signatures
        .expected_domains
        .iter()
        .any(|pattern| domain_matches(pattern, target))
    {
        return NetCategory::ExpectedApi;
    }

    for tracker in &signatures.trackers {
        if tracker
            .domains
            .iter()
            .any(|pattern| domain_matches(pattern, target))
        {
            return match tracker.category.as_deref() {
                Some("tracking") => NetCategory::Tracking,
                _ => NetCategory::Telemetry,
            };
        }
    }

    // Fallback: use IP range classification
    // Known cloud providers are not "unknown" — they're expected infrastructure
    use crate::analysis::resolver::IpCategory;
    match ip_category {
        IpCategory::Google => NetCategory::ExpectedApi,
        IpCategory::Aws => NetCategory::ExpectedApi,
        IpCategory::Cloudflare => NetCategory::ExpectedApi,
        IpCategory::Private
        | IpCategory::Loopback
        | IpCategory::LinkLocal
        | IpCategory::Multicast
        | IpCategory::Documentation => NetCategory::ExpectedApi,
        IpCategory::Unknown => NetCategory::Unknown,
    }
}

fn domain_matches(pattern: &str, target: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    let target = target.to_ascii_lowercase();

    if let Some(suffix) = pattern.strip_prefix("*.") {
        target == suffix || target.ends_with(&format!(".{suffix}"))
    } else {
        target == pattern
    }
}
