use std::{
    collections::{HashMap, VecDeque},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use tokio::{task::JoinHandle, time::sleep};

/// Wrapper around a pooled item with its creation time.
pub struct Pooled<T> {
    item: T,
    created: Instant,
}

impl<T> Pooled<T> {
    pub fn new(item: T) -> Self {
        Self {
            item,
            created: Instant::now(),
        }
    }

    pub fn age(&self) -> Duration {
        self.created.elapsed()
    }

    pub fn into_inner(self) -> T {
        self.item
    }
}

/// Unique key for segregating pools by connection capabilities.
#[derive(Hash, Eq, PartialEq, Clone)]
pub struct PoolKey {
    pub addr: String,
    pub protocol: String,
    pub features: Vec<String>,
}

/// Trait for pooled connections that can verify their health before reuse.
#[async_trait::async_trait]
pub trait HealthCheck {
    async fn is_healthy(&mut self) -> bool;
}

/// Connection pool segmented by [`PoolKey`] that retires a fraction of oldest
/// items periodically. The aging interval adapts based on the current load.
pub struct ConnectionPool<T: Send + 'static> {
    pools: HashMap<PoolKey, VecDeque<Pooled<T>>>,
    min_idle: Duration,
    max_idle: Duration,
    retire_percent: f64,
    depth: Arc<AtomicUsize>,
}

impl<T: Send + 'static> ConnectionPool<T> {
    /// Create a new pool with minimum/maximum idle time, retire percentage
    /// (0.0-1.0), and a shared queue depth indicator.
    pub fn new(
        min_idle: Duration,
        max_idle: Duration,
        retire_percent: f64,
        depth: Arc<AtomicUsize>,
    ) -> Self {
        Self {
            pools: HashMap::new(),
            min_idle,
            max_idle,
            retire_percent,
            depth,
        }
    }

    /// Add a new connection into the pool for a specific [`PoolKey`].
    pub fn add(&mut self, key: PoolKey, item: T) {
        self.pools
            .entry(key)
            .or_default()
            .push_back(Pooled::new(item));
    }

    /// Retrieve the next healthy connection for the given [`PoolKey`].
    pub async fn get(&mut self, key: &PoolKey) -> Option<T>
    where
        T: HealthCheck,
    {
        if let Some(q) = self.pools.get_mut(key) {
            while let Some(mut pooled) = q.pop_front() {
                if pooled.item.is_healthy().await {
                    return Some(pooled.into_inner());
                }
            }
        }
        None
    }

    /// Retire a fraction of oldest connections from all pools.
    pub fn retire_oldest(&mut self) {
        for q in self.pools.values_mut() {
            let len = q.len();
            if len == 0 {
                continue;
            }
            let mut retire = (len as f64 * self.retire_percent).ceil() as usize;
            if retire == 0 {
                retire = 1;
            }
            for _ in 0..retire {
                q.pop_front();
            }
        }
    }

    fn aging_interval(&self) -> Duration {
        if self.depth.load(Ordering::SeqCst) > 10 {
            self.max_idle
        } else {
            self.min_idle
        }
    }

    /// Spawn a background task that periodically retires connections.
    pub fn spawn_aging(pool: Arc<Mutex<Self>>) -> JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                let interval = {
                    let guard = pool.lock().unwrap();
                    guard.aging_interval()
                };
                sleep(interval).await;
                let mut guard = pool.lock().unwrap();
                guard.retire_oldest();
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng, rngs::StdRng};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    #[derive(Debug)]
    struct MockConn {
        closed: Arc<AtomicUsize>,
    }

    impl MockConn {
        fn new(closed: Arc<AtomicUsize>) -> Self {
            Self { closed }
        }
    }

    impl Drop for MockConn {
        fn drop(&mut self) {
            self.closed.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[async_trait::async_trait]
    impl HealthCheck for MockConn {
        async fn is_healthy(&mut self) -> bool {
            true
        }
    }

    #[test]
    fn retires_fraction_over_time() {
        let closed = Arc::new(AtomicUsize::new(0));
        let depth = Arc::new(AtomicUsize::new(0));
        let mut pool = ConnectionPool::new(
            Duration::from_secs(5),
            Duration::from_secs(10),
            0.1,
            depth,
        );
        for _ in 0..100 {
            let counter = Arc::clone(&closed);
            pool.add(
                PoolKey {
                    addr: String::new(),
                    protocol: String::new(),
                    features: Vec::new(),
                },
                MockConn::new(counter),
            );
        }

        for expected in [10usize, 19, 28] {
            pool.retire_oldest();
            assert_eq!(closed.load(Ordering::SeqCst), expected);
        }
    }

    #[tokio::test]
    async fn chaos_mode_random_discards_recover() {
        let closed = Arc::new(AtomicUsize::new(0));
        let depth = Arc::new(AtomicUsize::new(0));
        let mut pool = ConnectionPool::new(
            Duration::from_millis(10),
            Duration::from_millis(20),
            0.5,
            Arc::clone(&depth),
        );
        let key = PoolKey {
            addr: String::new(),
            protocol: String::new(),
            features: Vec::new(),
        };
        for _ in 0..20 {
            let counter = Arc::clone(&closed);
            pool.add(
                PoolKey {
                    addr: key.addr.to_owned(),
                    protocol: key.protocol.to_owned(),
                    features: key.features.to_vec(),
                },
                MockConn::new(counter),
            );
        }
        let mut rng = StdRng::seed_from_u64(7);
        if let Some(q) = pool.pools.get_mut(&key) {
            let len = q.len();
            for _ in 0..len {
                if rng.gen_bool(0.5) {
                    q.pop_front();
                }
            }
        }
        pool.add(
            PoolKey {
                addr: key.addr.to_owned(),
                protocol: key.protocol.to_owned(),
                features: key.features.to_vec(),
            },
            MockConn::new(Arc::clone(&closed)),
        );
        let got = pool
            .get(&PoolKey {
                addr: key.addr.to_owned(),
                protocol: key.protocol.to_owned(),
                features: key.features.to_vec(),
            })
            .await;
        assert!(got.is_some());
    }
}
