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

	if in_cidr(ip, Ipv4Addr::new(52, 0, 0, 0), 8) {
		return IpCategory::Aws;
	}

	if in_cidr(ip, Ipv4Addr::new(104, 16, 0, 0), 13) {
		return IpCategory::Cloudflare;
	}

	if in_cidr(ip, Ipv4Addr::new(142, 250, 0, 0), 15) {
		return IpCategory::Google;
	}

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
