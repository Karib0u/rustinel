mod dns;
mod process;
mod sid;

pub use dns::{DnsCache, DnsEntry};
pub use process::{ProcessCache, ProcessMetadata};
pub use sid::SidCache;

#[cfg(test)]
mod tests {
    use super::{DnsCache, SidCache};
    use std::net::IpAddr;

    #[test]
    fn sid_cache_prewarm_resolves() {
        let cache = SidCache::new();
        assert_eq!(
            cache.resolve("S-1-5-18"),
            Some("NT AUTHORITY\\SYSTEM".to_string())
        );
        assert_eq!(
            cache.resolve("S-1-5-19"),
            Some("NT AUTHORITY\\LOCAL SERVICE".to_string())
        );
        assert_eq!(
            cache.resolve("S-1-5-20"),
            Some("NT AUTHORITY\\NETWORK SERVICE".to_string())
        );
    }

    #[test]
    fn sid_cache_returns_none_for_empty() {
        let cache = SidCache::new();
        assert_eq!(cache.resolve(""), None);
    }

    #[test]
    fn sid_cache_returns_cached_entry() {
        let cache = SidCache::new();
        {
            let mut map = cache.cache.write().unwrap();
            map.insert("S-1-5-99".to_string(), "TEST\\User".to_string());
        }
        assert_eq!(cache.resolve("S-1-5-99"), Some("TEST\\User".to_string()));
    }

    #[test]
    fn dns_cache_resolves_recent_entry() {
        let cache = DnsCache::with_limits(10, 60);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        cache.update(ip, "example.com".to_string());
        assert_eq!(cache.lookup(&ip), Some("example.com".to_string()));
    }

    #[test]
    fn dns_cache_expires_on_hit() {
        let cache = DnsCache::with_limits(10, 0);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        cache.update(ip, "example.com".to_string());
        assert_eq!(cache.lookup(&ip), None);
    }

    #[test]
    fn dns_cache_trim_frees_headroom_for_same_second_inserts() {
        // Every insert lands in the same second, so a median cutoff would evict
        // nothing. The trim must still drop a quarter of the cap.
        let cache = DnsCache::with_limits(100, 60);

        for i in 0..101u32 {
            let ip: IpAddr = format!("10.{}.{}.{}", i / 256, i % 256, 1).parse().unwrap();
            cache.update(ip, format!("host{}.example", i));
        }

        assert_eq!(cache.count(), 75);

        // The freed slots absorb the next inserts without trimming again.
        for i in 101..126u32 {
            let ip: IpAddr = format!("10.{}.{}.{}", i / 256, i % 256, 1).parse().unwrap();
            cache.update(ip, format!("host{}.example", i));
        }

        assert_eq!(cache.count(), 100);
    }

    #[test]
    fn dns_cache_stays_bounded_under_a_same_second_burst() {
        let cache = DnsCache::with_limits(100, 60);

        for i in 0..1_000u32 {
            let ip: IpAddr = format!("10.{}.{}.{}", i / 256, i % 256, 1).parse().unwrap();
            cache.update(ip, format!("host{}.example", i));
            assert!(cache.count() <= 100);
        }
    }

    #[test]
    fn dns_cache_trims_to_limit() {
        let cache = DnsCache::with_limits(2, 60);
        let ip1: IpAddr = "1.2.3.4".parse().unwrap();
        let ip2: IpAddr = "5.6.7.8".parse().unwrap();
        let ip3: IpAddr = "9.9.9.9".parse().unwrap();

        cache.update(ip1, "one.example".to_string());
        cache.update(ip2, "two.example".to_string());
        cache.update(ip3, "three.example".to_string());

        assert!(cache.count() <= 2);
    }
}
