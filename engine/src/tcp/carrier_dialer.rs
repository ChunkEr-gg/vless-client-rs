use std::{fmt::Debug, io};

use async_trait::async_trait;

use crate::async_stream::AsyncStream;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct RouteKey(pub Vec<usize>);

#[async_trait]
pub trait CarrierDialer: Debug + Send + Sync {
    fn route_key(&self) -> &RouteKey;
    async fn open_stream(&self) -> io::Result<Box<dyn AsyncStream>>;
}
