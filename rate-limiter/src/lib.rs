//! Rate Limiter Library
//!
//! Provides token bucket rate limiting for protecting endpoints from DoS attacks.
//! Supports per-key (IP address, node name, etc.) rate limiting with configurable
//! burst capacity and refill rates.

use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Token bucket rate limiter for a single source.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    /// Current number of available tokens
    tokens: f64,
    /// Maximum tokens (burst capacity)
    max_tokens: f64,
    /// Tokens added per second
    refill_rate: f64,
    /// Last time tokens were refilled
    last_refill: Instant,
}

impl TokenBucket {
    /// Create a new token bucket.
    ///
    /// # Arguments
    /// * `max_tokens` - Maximum burst capacity
    /// * `refill_rate` - Tokens per second to add
    pub fn new(max_tokens: f64, refill_rate: f64) -> Self {
        Self {
            tokens: max_tokens,
            max_tokens,
            refill_rate,
            last_refill: Instant::now(),
        }
    }

    /// Try to acquire a token. Returns true if successful, false if rate limited.
    pub fn try_acquire(&mut self) -> bool {
        self.refill();
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Try to acquire multiple tokens at once.
    pub fn try_acquire_n(&mut self, n: f64) -> bool {
        self.refill();
        if self.tokens >= n {
            self.tokens -= n;
            true
        } else {
            false
        }
    }

    /// Get current token count (for debugging/monitoring).
    pub fn available_tokens(&mut self) -> f64 {
        self.refill();
        self.tokens
    }

    /// Refill tokens based on elapsed time.
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);
        self.last_refill = now;
    }
}

/// Configuration for a rate limiter.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum burst capacity
    pub max_tokens: f64,
    /// Tokens per second
    pub refill_rate: f64,
    /// How long to keep inactive entries before cleanup
    pub cleanup_after: Duration,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_tokens: 10.0,
            refill_rate: 10.0,
            cleanup_after: Duration::from_secs(300), // 5 minutes
        }
    }
}

impl RateLimitConfig {
    /// Create config for QUIC commands (10/sec per node)
    pub fn quic_commands() -> Self {
        Self {
            max_tokens: 20.0,  // Allow burst of 20
            refill_rate: 10.0, // 10 per second sustained
            cleanup_after: Duration::from_secs(60),
        }
    }

    /// Create config for WebSocket admin (20/sec per IP)
    pub fn websocket_admin() -> Self {
        Self {
            max_tokens: 40.0,  // Allow burst of 40
            refill_rate: 20.0, // 20 per second sustained
            cleanup_after: Duration::from_secs(300),
        }
    }

    /// Create config for ONVIF endpoints (30/sec per IP)
    pub fn onvif() -> Self {
        Self {
            max_tokens: 60.0,  // Allow burst of 60
            refill_rate: 30.0, // 30 per second sustained
            cleanup_after: Duration::from_secs(300),
        }
    }
}

/// Per-key rate limiter that tracks multiple sources.
#[derive(Debug)]
pub struct KeyedRateLimiter<K: std::hash::Hash + Eq + Clone> {
    buckets: DashMap<K, (TokenBucket, Instant)>,
    config: RateLimitConfig,
}

impl<K: std::hash::Hash + Eq + Clone> KeyedRateLimiter<K> {
    /// Create a new keyed rate limiter.
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            buckets: DashMap::new(),
            config,
        }
    }

    /// Check if a request from the given key should be allowed.
    /// Returns true if allowed, false if rate limited.
    pub fn check(&self, key: &K) -> bool {
        let mut entry = self.buckets.entry(key.clone()).or_insert_with(|| {
            (
                TokenBucket::new(self.config.max_tokens, self.config.refill_rate),
                Instant::now(),
            )
        });

        let (bucket, last_access) = entry.value_mut();
        *last_access = Instant::now();
        bucket.try_acquire()
    }

    /// Get the number of tracked keys (for monitoring).
    pub fn tracked_count(&self) -> usize {
        self.buckets.len()
    }

    /// Clean up old entries that haven't been accessed recently.
    pub fn cleanup(&self) {
        let cutoff = Instant::now() - self.config.cleanup_after;
        self.buckets.retain(|_, (_, last_access)| *last_access > cutoff);
    }
}

/// IP-based rate limiter (convenience type).
pub type IpRateLimiter = KeyedRateLimiter<IpAddr>;

/// String-based rate limiter (for node names, etc.).
pub type StringRateLimiter = KeyedRateLimiter<String>;

/// Shared rate limiter that can be cloned and used across async tasks.
#[derive(Clone)]
pub struct SharedRateLimiter<K: std::hash::Hash + Eq + Clone + Send + Sync + 'static> {
    inner: Arc<KeyedRateLimiter<K>>,
}

impl<K: std::hash::Hash + Eq + Clone + Send + Sync + 'static> SharedRateLimiter<K> {
    /// Create a new shared rate limiter.
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            inner: Arc::new(KeyedRateLimiter::new(config)),
        }
    }

    /// Check if a request should be allowed.
    pub fn check(&self, key: &K) -> bool {
        self.inner.check(key)
    }

    /// Get the number of tracked keys.
    pub fn tracked_count(&self) -> usize {
        self.inner.tracked_count()
    }

    /// Clean up old entries.
    pub fn cleanup(&self) {
        self.inner.cleanup()
    }

    /// Start a background cleanup task that runs periodically.
    pub fn start_cleanup_task(self, interval: Duration) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;
                self.cleanup();
            }
        })
    }
}

/// Convenience type for IP-based shared rate limiter.
pub type SharedIpRateLimiter = SharedRateLimiter<IpAddr>;

/// Convenience type for string-based shared rate limiter.
pub type SharedStringRateLimiter = SharedRateLimiter<String>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_bucket_basic() {
        let mut bucket = TokenBucket::new(5.0, 10.0);

        // Should allow 5 requests immediately (burst)
        for _ in 0..5 {
            assert!(bucket.try_acquire());
        }

        // 6th should be denied
        assert!(!bucket.try_acquire());
    }

    #[test]
    fn test_token_bucket_refill() {
        let mut bucket = TokenBucket::new(2.0, 100.0); // Fast refill for testing

        // Drain the bucket
        assert!(bucket.try_acquire());
        assert!(bucket.try_acquire());
        assert!(!bucket.try_acquire());

        // Wait a bit for refill
        std::thread::sleep(Duration::from_millis(50));

        // Should have some tokens now
        assert!(bucket.try_acquire());
    }

    #[test]
    fn test_keyed_rate_limiter() {
        let limiter = KeyedRateLimiter::new(RateLimitConfig {
            max_tokens: 2.0,
            refill_rate: 1.0,
            cleanup_after: Duration::from_secs(60),
        });

        let ip1: IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: IpAddr = "192.168.1.2".parse().unwrap();

        // Each IP gets its own bucket
        assert!(limiter.check(&ip1));
        assert!(limiter.check(&ip1));
        assert!(!limiter.check(&ip1)); // ip1 exhausted

        assert!(limiter.check(&ip2)); // ip2 still has tokens
        assert!(limiter.check(&ip2));
        assert!(!limiter.check(&ip2)); // ip2 exhausted
    }

    #[test]
    fn test_cleanup() {
        let limiter = KeyedRateLimiter::new(RateLimitConfig {
            max_tokens: 10.0,
            refill_rate: 10.0,
            cleanup_after: Duration::from_millis(10),
        });

        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        limiter.check(&ip);

        assert_eq!(limiter.tracked_count(), 1);

        // Wait for cleanup threshold
        std::thread::sleep(Duration::from_millis(20));
        limiter.cleanup();

        assert_eq!(limiter.tracked_count(), 0);
    }
}
