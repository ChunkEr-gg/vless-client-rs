#![allow(dead_code)]
use std::future::Future;
use std::time::Duration;

use tokio::task::JoinSet;

/// Accepted connections may drain after stop, bounded by a grace period.
pub(crate) struct ListenerTasks {
    tasks: JoinSet<()>,
    grace: Duration,
}

impl ListenerTasks {
    pub fn immediate() -> Self {
        Self::with_grace(Duration::ZERO)
    }

    pub fn new() -> Self {
        Self::with_grace(Duration::from_secs(
            crate::resources::limits().reload_grace_secs,
        ))
    }

    fn with_grace(grace: Duration) -> Self {
        Self {
            tasks: JoinSet::new(),
            grace,
        }
    }

    pub fn spawn(&mut self, future: impl Future<Output = ()> + Send + 'static) {
        crate::network_tasks::spawn_in(&mut self.tasks, future);
    }

    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    pub async fn join_next(&mut self) {
        if let Some(Err(error)) = self.tasks.join_next().await {
            log::warn!("Connection task failed: {error}");
        }
    }
}

impl Drop for ListenerTasks {
    fn drop(&mut self) {
        if self.tasks.is_empty() || self.grace.is_zero() {
            return;
        }
        if tokio::runtime::Handle::try_current().is_err() {
            return;
        }
        let mut tasks = std::mem::take(&mut self.tasks);
        let deadline = tokio::time::Instant::now() + self.grace;
        crate::network_tasks::spawn(async move {
            let drained = tokio::time::timeout_at(deadline, async {
                while let Some(result) = tasks.join_next().await {
                    if let Err(error) = result {
                        log::warn!("Draining connection task failed: {error}");
                    }
                }
            })
            .await;
            if drained.is_err() {
                log::info!(
                    "Drain grace expired; cancelling {} connections",
                    tasks.len()
                );
                tasks.shutdown().await;
            }
        });
    }
}
