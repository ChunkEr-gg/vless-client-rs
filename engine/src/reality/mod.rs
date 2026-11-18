//! REALITY authentication and certificate policy over rustls (`PLAN.md` §6).

mod reality_auth;
#[cfg(test)]
mod reality_certificate;
mod reality_certificate_verify;
mod reality_cipher_suite;
mod reality_client;
mod reality_client_handler;
mod reality_config;
mod reality_hello;
mod reality_rustls_adapter;
#[cfg(test)]
mod reality_server;
#[cfg(test)]
mod reality_target_flight;
#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) use tests::reality_fixtures::{default_target_records, established_pair};

pub use reality_cipher_suite::{CipherSuite, DEFAULT_CIPHER_SUITES};
pub(crate) use reality_config::parse_server_name;
#[allow(unused_imports)]
pub use reality_config::{
    decode_private_key, decode_public_key, decode_short_id, generate_keypair,
};

pub use reality_client::RealityClientConfig;
pub use reality_client_handler::RealityClientHandler;
#[cfg(test)]
pub use reality_server::RealityServerConfig;
