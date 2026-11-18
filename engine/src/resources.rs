#![allow(dead_code)]
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, LazyLock};

use parking_lot::{Mutex, RwLock};

use crate::atomic::AtomicU64;
use crate::config::GlobalLimits;

static LIMITS: LazyLock<RwLock<GlobalLimits>> = LazyLock::new(Default::default);

pub(crate) fn limits() -> GlobalLimits {
    *LIMITS.read()
}

pub(crate) fn configure(limits: GlobalLimits) -> std::io::Result<()> {
    limits.validate()?;
    let mut current = LIMITS.write();
    CONNECTIONS.set_limit(limits.max_connections);
    STREAMS.set_limit(limits.max_streams);
    *current = limits;
    Ok(())
}

#[derive(Debug, Default)]
pub(crate) struct BudgetSnapshot {
    pub active: usize,
    pub peak: usize,
    pub rejected: u64,
}

#[derive(Debug, Default)]
struct BudgetState {
    limit: Option<usize>,
    active: usize,
    peak: usize,
    rejected: u64,
}

#[derive(Debug)]
pub(crate) struct Budget(Mutex<BudgetState>, Arc<tokio::sync::Notify>);

impl Budget {
    pub(crate) fn new(limit: Option<usize>) -> Self {
        Self(
            Mutex::new(BudgetState {
                limit,
                ..Default::default()
            }),
            Arc::new(tokio::sync::Notify::new()),
        )
    }

    fn set_limit(&self, limit: Option<usize>) {
        self.0.lock().limit = limit;
        self.1.notify_waiters();
    }

    pub(crate) fn limit(&self) -> Option<usize> {
        self.0.lock().limit
    }

    pub(crate) fn released(&self) -> tokio::sync::futures::OwnedNotified {
        self.1.clone().notified_owned()
    }

    pub(crate) fn acquire(self: &Arc<Self>, count: usize) -> Option<BudgetPermit> {
        let mut state = self.0.lock();
        let active = state.active.checked_add(count)?;
        if state.limit.is_some_and(|limit| active > limit) {
            state.rejected += 1;
            return None;
        }
        state.active = active;
        state.peak = state.peak.max(active);
        Some(BudgetPermit {
            budget: self.clone(),
            count,
        })
    }

    pub(crate) fn snapshot(&self) -> BudgetSnapshot {
        let state = self.0.lock();
        BudgetSnapshot {
            active: state.active,
            peak: state.peak,
            rejected: state.rejected,
        }
    }

    #[cfg(test)]
    pub(crate) fn available_permits(&self) -> usize {
        let state = self.0.lock();
        state
            .limit
            .unwrap_or(usize::MAX)
            .saturating_sub(state.active)
    }
}

#[derive(Debug)]
pub(crate) struct BudgetPermit {
    budget: Arc<Budget>,
    count: usize,
}

impl BudgetPermit {
    pub(crate) fn merge(&mut self, mut other: Self) {
        assert!(Arc::ptr_eq(&self.budget, &other.budget));
        self.count += other.count;
        other.count = 0;
    }

    pub(crate) fn split(&mut self, count: usize) -> Self {
        assert!(count <= self.count);
        self.count -= count;
        Self {
            budget: self.budget.clone(),
            count,
        }
    }
}

impl Drop for BudgetPermit {
    fn drop(&mut self) {
        if self.count != 0 {
            self.budget.0.lock().active -= self.count;
            self.budget.1.notify_waiters();
        }
    }
}

static CONNECTIONS: LazyLock<Arc<Budget>> = LazyLock::new(|| Arc::new(Budget::new(None)));
static STREAMS: LazyLock<Arc<Budget>> = LazyLock::new(|| Arc::new(Budget::new(None)));
static PEERS: LazyLock<Mutex<HashMap<IpAddr, usize>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static PEER_REJECTIONS: AtomicU64 = AtomicU64::new(0);

pub(crate) struct ConnectionPermit {
    _global: BudgetPermit,
    peer: Option<IpAddr>,
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        if let Some(peer) = self.peer {
            let mut peers = PEERS.lock();
            if let Some(count) = peers.get_mut(&peer) {
                *count -= 1;
                if *count == 0 {
                    peers.remove(&peer);
                }
            }
        }
    }
}

pub(crate) fn try_connection(peer: Option<IpAddr>) -> Option<ConnectionPermit> {
    let limits = LIMITS.read();
    let permit = CONNECTIONS.acquire(1)?;
    let peer = peer.map(|ip| match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        ip => ip,
    });
    if let Some(peer) = peer {
        let mut peers = PEERS.lock();
        let count = peers.entry(peer).or_default();
        if limits
            .max_connections_per_ip
            .is_some_and(|limit| *count >= limit)
        {
            PEER_REJECTIONS.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        *count += 1;
    }
    Some(ConnectionPermit {
        _global: permit,
        peer,
    })
}

pub(crate) fn try_stream() -> Option<BudgetPermit> {
    STREAMS.acquire(1)
}

#[derive(Debug)]
struct ResourceExhausted(String);

impl std::fmt::Display for ResourceExhausted {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for ResourceExhausted {}

pub(crate) fn is_exhausted(mut error: &(dyn std::error::Error + 'static)) -> bool {
    loop {
        if error.is::<ResourceExhausted>() {
            return true;
        }
        let source = match error.downcast_ref::<std::io::Error>() {
            Some(error) => error.get_ref().map(|inner| inner as &dyn std::error::Error),
            None => error.source(),
        };
        let Some(source) = source else { return false };
        error = source;
    }
}

pub(crate) fn exhausted() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::ConnectionRefused,
        ResourceExhausted("process resource budget exhausted".into()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_acquire_split_merge_and_release() {
        let budget = Arc::new(Budget::new(Some(3)));
        assert_eq!(budget.available_permits(), 3);
        let mut p1 = budget.acquire(2).unwrap();
        assert_eq!(budget.available_permits(), 1);
        assert!(budget.acquire(2).is_none());
        let p2 = p1.split(1);
        p1.merge(p2);
        drop(p1);
        assert_eq!(budget.available_permits(), 3);
        let snap = budget.snapshot();
        assert_eq!(snap.active, 0);
        assert_eq!(snap.peak, 2);
        assert_eq!(snap.rejected, 1);
    }
}
