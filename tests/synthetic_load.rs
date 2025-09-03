use apicon::{
    pool::{ConnectionPool, HealthCheck, PoolKey},
    DualEwma,
};
use std::{
    sync::{
        atomic::AtomicUsize,
        Arc,
    },
    time::Duration,
};

#[tokio::test]
async fn ocsp_outage_increases_ewma_ratio() {
    let mut ewma = DualEwma::default();
    for _ in 0..5 {
        ewma.record(50.0, 1, 50.0, 25.0);
    }
    for _ in 0..3 {
        ewma.record(500.0, 1, 50.0, 25.0);
    }
    assert!(ewma.ratio() > 1.0);
}

#[tokio::test]
async fn rapid_latency_changes_spike_ratio() {
    let mut ewma = DualEwma::default();
    for _ in 0..10 {
        ewma.record(30.0, 1, 30.0, 9.0);
    }
    ewma.record(300.0, 1, 30.0, 9.0);
    assert!(ewma.ratio() > 1.0);
}

#[derive(Default)]
struct Droppy {
    healthy: bool,
}

#[async_trait::async_trait]
impl HealthCheck for Droppy {
    async fn is_healthy(&mut self) -> bool {
        let res = self.healthy;
        self.healthy = false;
        res
    }
}

#[tokio::test]
async fn connection_drop_recovery() {
    let depth = Arc::new(AtomicUsize::new(0));
    let mut pool = ConnectionPool::new(
        Duration::from_millis(10),
        Duration::from_millis(20),
        0.1,
        Arc::clone(&depth),
    );
    let key = PoolKey {
        addr: String::new(),
        protocol: String::new(),
        features: Vec::new(),
    };
    pool.add(
        PoolKey {
            addr: key.addr.to_owned(),
            protocol: key.protocol.to_owned(),
            features: key.features.to_vec(),
        },
        Droppy { healthy: true },
    );
    let key_get = PoolKey {
        addr: key.addr.to_owned(),
        protocol: key.protocol.to_owned(),
        features: key.features.to_vec(),
    };
    let first = pool.get(&key_get).await;
    assert!(first.is_some());
    let second = pool.get(&key_get).await;
    assert!(second.is_none());
    pool.add(
        PoolKey {
            addr: key.addr.to_owned(),
            protocol: key.protocol.to_owned(),
            features: key.features.to_vec(),
        },
        Droppy { healthy: true },
    );
    let recovered = pool.get(&key_get).await;
    assert!(recovered.is_some());
}
