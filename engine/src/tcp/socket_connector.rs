use std::fmt::Debug;
use std::sync::Arc;

use async_trait::async_trait;

use crate::address::ResolvedLocation;
use crate::async_stream::{AsyncMessageStream, AsyncStream};
use crate::resolver::Resolver;

#[async_trait]
#[allow(
    clippy::double_must_use,
    reason = "async-trait adds must_use to boxed futures"
)]
pub trait SocketConnector: Send + Sync + Debug {
    async fn connect(
        &self,
        resolver: &Arc<dyn Resolver>,
        address: &ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncStream>>;

    async fn connect_udp_bidirectional(
        &self,
        resolver: &Arc<dyn Resolver>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>>;

    fn bind_interface(&self) -> Option<&str>;
}
