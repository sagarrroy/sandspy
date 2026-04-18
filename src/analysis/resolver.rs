// sandspy::analysis::resolver — IP -> Domain categorization

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

const DNS_CACHE_TTL: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpCategory {
    Private,
    Aws,
    Azure,
    Cloudflare,
    Google,
    Loopback,
    LinkLocal,
    Multicast,
    Documentation,
    Unknown,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    host: Option<String>,
    category: IpCategory,
    expires_at: Instant,
}

static CACHE: OnceLock<Mutex<HashMap<IpAddr, CacheEntry>>> = OnceLock::new();

pub fn resolve(addr: &str) -> (Option<String>, IpCategory) {
    let ip = match addr.parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(_) => return (None, IpCategory::Unknown),
    };

    if let Some(entry) = cached(&ip) {
        return (entry.host, entry.category);
    }

    let category = categorize_ip(ip);
    let host = reverse_dns(ip);
    store_cache(ip, host.clone(), category);
    (host, category)
}

fn cached(ip: &IpAddr) -> Option<CacheEntry> {
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = match cache.lock() {
        Ok(value) => value,
        Err(_) => return None,
    };

    if let Some(entry) = guard.get(ip) {
        if Instant::now() <= entry.expires_at {
            return Some(entry.clone());
        }
    }

    guard.remove(ip);
    None
}

fn store_cache(ip: IpAddr, host: Option<String>, category: IpCategory) {
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = match cache.lock() {
        Ok(value) => value,
        Err(_) => return,
    };

    guard.insert(
        ip,
        CacheEntry {
            host,
            category,
            expires_at: Instant::now() + DNS_CACHE_TTL,
        },
    );
}

fn reverse_dns(ip: IpAddr) -> Option<String> {
    dns_lookup::lookup_addr(&ip)
        .ok()
        .map(|value| value.trim_end_matches('.').to_string())
        .filter(|value| !value.is_empty())
}

fn categorize_ip(ip: IpAddr) -> IpCategory {
    match ip {
        IpAddr::V4(v4) => categorize_v4(v4),
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                IpCategory::Loopback
            } else if v6.is_multicast() {
                IpCategory::Multicast
            } else {
                IpCategory::Unknown
            }
        }
    }
}

fn categorize_v4(ip: Ipv4Addr) -> IpCategory {
    if ip.is_private() {
        return IpCategory::Private;
    }

    if ip.is_loopback() {
        return IpCategory::Loopback;
    }

    if ip.is_link_local() {
        return IpCategory::LinkLocal;
    }

    if ip.is_multicast() {
        return IpCategory::Multicast;
    }

    // === AWS ===
    // 52.0.0.0/8, 54.0.0.0/8 (classic EC2 ranges)
    if in_cidr(ip, Ipv4Addr::new(52, 0, 0, 0), 8) || in_cidr(ip, Ipv4Addr::new(54, 0, 0, 0), 8) {
        return IpCategory::Aws;
    }
    // 3.0.0.0/8 — AWS us-east modern range
    if in_cidr(ip, Ipv4Addr::new(3, 0, 0, 0), 8) {
        return IpCategory::Aws;
    }

    // === Cloudflare ===
    // 104.16.0.0/13, 162.158.0.0/15, 172.64.0.0/13, 108.162.192.0/18
    if in_cidr(ip, Ipv4Addr::new(104, 16, 0, 0), 13)
        || in_cidr(ip, Ipv4Addr::new(162, 158, 0, 0), 15)
        || in_cidr(ip, Ipv4Addr::new(172, 64, 0, 0), 13)
        || in_cidr(ip, Ipv4Addr::new(108, 162, 192, 0), 18)
        || in_cidr(ip, Ipv4Addr::new(188, 114, 96, 0), 20)
    {
        return IpCategory::Cloudflare;
    }

    // === Google ===
    // 142.250.0.0/15, 142.251.0.0/16 — Google Services
    if in_cidr(ip, Ipv4Addr::new(142, 250, 0, 0), 15)
        || in_cidr(ip, Ipv4Addr::new(142, 251, 0, 0), 16)
    {
        return IpCategory::Google;
    }
    // 216.58.0.0/16, 216.239.0.0/16 — Google infrastructure / Anycast
    if in_cidr(ip, Ipv4Addr::new(216, 58, 0, 0), 16)
        || in_cidr(ip, Ipv4Addr::new(216, 239, 0, 0), 16)
    {
        return IpCategory::Google;
    }
    // 34.0.0.0/8 — Google Cloud (GCP)
    if in_cidr(ip, Ipv4Addr::new(34, 0, 0, 0), 8) {
        return IpCategory::Google;
    }
    // 35.186.0.0/16, 35.190.0.0/16, 35.192.0.0/12 — more GCP
    if in_cidr(ip, Ipv4Addr::new(35, 0, 0, 0), 8) {
        return IpCategory::Google;
    }
    // 74.125.0.0/16 — Google core
    if in_cidr(ip, Ipv4Addr::new(74, 125, 0, 0), 16) {
        return IpCategory::Google;
    }
    // 66.249.64.0/19 — Googlebot / crawlers
    if in_cidr(ip, Ipv4Addr::new(66, 249, 64, 0), 19) {
        return IpCategory::Google;
    }

    // === Microsoft Azure ===
    // 20.0.0.0/8 — Azure public IPs (massive range)
    if in_cidr(ip, Ipv4Addr::new(20, 0, 0, 0), 8) {
        return IpCategory::Azure;
    }
    // 40.64.0.0/10 — Azure
    if in_cidr(ip, Ipv4Addr::new(40, 64, 0, 0), 10) {
        return IpCategory::Azure;
    }
    // 13.64.0.0/11, 13.104.0.0/14 — Azure Global
    if in_cidr(ip, Ipv4Addr::new(13, 64, 0, 0), 11) || in_cidr(ip, Ipv4Addr::new(13, 104, 0, 0), 14)
    {
        return IpCategory::Azure;
    }

    // === Documentation / RFC5737
    if in_cidr(ip, Ipv4Addr::new(192, 0, 2, 0), 24)
        || in_cidr(ip, Ipv4Addr::new(198, 51, 100, 0), 24)
        || in_cidr(ip, Ipv4Addr::new(203, 0, 113, 0), 24)
    {
        return IpCategory::Documentation;
    }

    IpCategory::Unknown
}

fn in_cidr(ip: Ipv4Addr, base: Ipv4Addr, prefix: u8) -> bool {
    let prefix = prefix.min(32);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    };

    (u32::from(ip) & mask) == (u32::from(base) & mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn categorizes_private_ranges() {
        let (_, category) = resolve("10.10.10.10");
        assert_eq!(category, IpCategory::Private);
    }

    #[test]
    fn categorizes_cloudflare_range() {
        let (_, category) = resolve("104.16.1.1");
        assert_eq!(category, IpCategory::Cloudflare);
    }

    #[test]
    fn categorizes_google_range() {
        let (_, category) = resolve("142.250.190.78");
        assert_eq!(category, IpCategory::Google);
    }
}
