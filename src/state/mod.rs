mod connection;
mod dns;
mod process;
mod sid;

pub use connection::{
    AggregationMeta, AggregationResult, ConnectionAggregator, ConnectionKey, ConnectionState,
    Protocol,
};
pub use dns::{DnsCache, DnsEntry};
pub use process::{ProcessCache, ProcessMetadata};
pub use sid::SidCache;

#[cfg(test)]
mod tests {
    use super::{AggregationResult, ConnectionAggregator, DnsCache, Protocol, SidCache};
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

    #[test]
    fn connection_aggregator_first_connection_emits() {
        let aggregator = ConnectionAggregator::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        let result = aggregator.record(
            "C:\\Windows\\System32\\svchost.exe",
            ip,
            443,
            Protocol::Tcp,
            1234,
        );
        assert_eq!(result, AggregationResult::FirstConnection);
        assert_eq!(aggregator.count(), 1);
    }

    #[test]
    fn connection_aggregator_repeat_connection_aggregates() {
        let aggregator = ConnectionAggregator::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        let result1 = aggregator.record("C:\\app.exe", ip, 443, Protocol::Tcp, 1234);
        let result2 = aggregator.record("C:\\app.exe", ip, 443, Protocol::Tcp, 1234);
        let result3 = aggregator.record("C:\\app.exe", ip, 443, Protocol::Tcp, 1234);

        assert_eq!(result1, AggregationResult::FirstConnection);
        assert_eq!(result2, AggregationResult::Aggregated);
        assert_eq!(result3, AggregationResult::Aggregated);
        assert_eq!(aggregator.count(), 1);
    }

    #[test]
    fn connection_aggregator_starts_new_period_after_window() {
        let aggregator = ConnectionAggregator::with_limits_and_window(10, 10, 60);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        let result1 = aggregator.record_at(100, "C:\\app.exe", ip, 443, Protocol::Tcp, 1234);
        let result2 = aggregator.record_at(101, "C:\\app.exe", ip, 443, Protocol::Tcp, 1234);
        let result3 = aggregator.record_at(161, "C:\\app.exe", ip, 443, Protocol::Tcp, 5678);

        assert_eq!(result1, AggregationResult::FirstConnection);
        assert_eq!(result2, AggregationResult::Aggregated);
        assert_eq!(result3, AggregationResult::FirstConnection);

        let meta = aggregator
            .get_meta("C:\\app.exe", ip, 443, Protocol::Tcp)
            .unwrap();
        assert_eq!(meta.connection_count, 1);
        assert_eq!(meta.unique_pids, vec![5678]);
    }

    #[test]
    fn connection_aggregator_different_destinations_emit() {
        let aggregator = ConnectionAggregator::new();
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();

        let result1 = aggregator.record("C:\\app.exe", ip1, 443, Protocol::Tcp, 1234);
        let result2 = aggregator.record("C:\\app.exe", ip2, 443, Protocol::Tcp, 1234);

        assert_eq!(result1, AggregationResult::FirstConnection);
        assert_eq!(result2, AggregationResult::FirstConnection);
        assert_eq!(aggregator.count(), 2);
    }

    #[test]
    fn connection_aggregator_different_ports_emit() {
        let aggregator = ConnectionAggregator::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        let result1 = aggregator.record("C:\\app.exe", ip, 443, Protocol::Tcp, 1234);
        let result2 = aggregator.record("C:\\app.exe", ip, 80, Protocol::Tcp, 1234);

        assert_eq!(result1, AggregationResult::FirstConnection);
        assert_eq!(result2, AggregationResult::FirstConnection);
        assert_eq!(aggregator.count(), 2);
    }

    #[test]
    fn connection_aggregator_tracks_multiple_pids() {
        let aggregator = ConnectionAggregator::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        aggregator.record("C:\\app.exe", ip, 443, Protocol::Tcp, 1000);
        aggregator.record("C:\\app.exe", ip, 443, Protocol::Tcp, 2000);
        aggregator.record("C:\\app.exe", ip, 443, Protocol::Tcp, 3000);

        let meta = aggregator
            .get_meta("C:\\app.exe", ip, 443, Protocol::Tcp)
            .unwrap();
        assert_eq!(meta.connection_count, 3);
        assert_eq!(meta.unique_pids.len(), 3);
    }

    #[test]
    fn connection_aggregator_trims_to_limit() {
        let aggregator = ConnectionAggregator::with_limits(2, 10);

        for i in 0..5u8 {
            let ip: IpAddr = format!("10.0.0.{}", i).parse().unwrap();
            aggregator.record("C:\\app.exe", ip, 443, Protocol::Tcp, 1234);
        }

        assert!(aggregator.count() <= 2);
    }
}
