//! Factory functions for creating VLESS + TLS / VLESS + REALITY client handlers from typed config.

use std::sync::Arc;

use log::debug;

use crate::address::NetLocation;
use crate::config::{
    ResolvedClientProxyConfig, ResolvedTlsClientConfig, validate_resolved_client_vision_protocol,
};
use crate::reality::RealityClientHandler;
use crate::resolver::Resolver;
use crate::rustls_config_util::try_create_client_config;
use crate::tcp::tcp_handler::TcpClientHandler;
use crate::tls_client_handler::TlsClientHandler;
use crate::uuid_util::parse_uuid;
use crate::vless::vless_client_handler::VlessTcpClientHandler;

pub fn create_tcp_client_handler(
    client_proxy_config: ResolvedClientProxyConfig,
    hop_location: &NetLocation,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<Box<dyn TcpClientHandler>> {
    let default_sni_hostname = hop_location.address().hostname().map(str::to_owned);
    create_with_hop_context(
        client_proxy_config,
        hop_location,
        default_sni_hostname,
        resolver,
    )
}

pub(crate) fn tls_verification_name(
    sni: Option<String>,
    hop: &NetLocation,
) -> std::io::Result<rustls::pki_types::ServerName<'static>> {
    let identity = sni.unwrap_or_else(|| hop.address().to_string());
    rustls::pki_types::ServerName::try_from(identity).map_err(std::io::Error::other)
}

#[allow(clippy::only_used_in_recursion)]
pub(crate) fn create_with_hop_context(
    client_proxy_config: ResolvedClientProxyConfig,
    hop_location: &NetLocation,
    default_sni_hostname: Option<String>,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<Box<dyn TcpClientHandler>> {
    Ok(match client_proxy_config {
        ResolvedClientProxyConfig::Direct => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "direct cannot be used as an inner proxy protocol",
            ));
        }
        ResolvedClientProxyConfig::Vless {
            user_id,
            vision,
            udp_enabled,
        } => {
            if vision {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "VLESS Vision requires an enclosing TLS or REALITY transport",
                ));
            }
            Box::new(VlessTcpClientHandler::new(&user_id, udp_enabled)?)
        }
        ResolvedClientProxyConfig::Tls(tls_client_config) => {
            let ResolvedTlsClientConfig {
                key_exchange_groups,
                verify,
                server_fingerprints,
                sni_hostname,
                alpn_protocols,
                tls_buffer_size,
                client_cert_and_key,
                vision,
                protocol,
            } = tls_client_config;
            key_exchange_groups.validate_vision(vision)?;
            validate_resolved_client_vision_protocol(vision, &protocol, "TLS")?;

            let sni_hostname = if sni_hostname.is_unspecified() {
                if let Some(ref hostname) = default_sni_hostname {
                    debug!("Using default sni hostname for TLS client connection: {hostname}");
                }
                default_sni_hostname
            } else {
                sni_hostname.into_option()
            };

            let key_and_cert_bytes = client_cert_and_key.map(|(cert, key)| (key, cert));

            let client_config = Arc::new(try_create_client_config(
                verify,
                server_fingerprints.into_vec(),
                alpn_protocols.into_vec(),
                sni_hostname.is_some(),
                key_and_cert_bytes,
                false,
                &key_exchange_groups,
            )?);

            let server_name = tls_verification_name(sni_hostname, hop_location)?;

            if vision {
                let ResolvedClientProxyConfig::Vless {
                    user_id,
                    udp_enabled,
                    ..
                } = protocol.as_ref()
                else {
                    unreachable!("validated by validate_resolved_client_vision_protocol");
                };
                let user_id_bytes = parse_uuid(user_id)?.into_boxed_slice();
                Box::new(TlsClientHandler::new_vision_vless(
                    client_config,
                    tls_buffer_size,
                    server_name,
                    user_id_bytes,
                    *udp_enabled,
                ))
            } else {
                let handler = create_with_hop_context(*protocol, hop_location, None, resolver)?;
                Box::new(TlsClientHandler::new(
                    client_config,
                    tls_buffer_size,
                    server_name,
                    handler,
                ))
            }
        }
        ResolvedClientProxyConfig::Reality {
            public_key,
            short_id,
            sni_hostname,
            cipher_suites,
            vision,
            protocol,
        } => {
            validate_resolved_client_vision_protocol(vision, &protocol, "REALITY")?;
            let public_key_bytes =
                crate::reality::decode_public_key(&public_key).map_err(std::io::Error::other)?;
            let short_id_bytes =
                crate::reality::decode_short_id(&short_id).map_err(std::io::Error::other)?;
            let Some(sni_hostname) = sni_hostname.or(default_sni_hostname) else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "REALITY client requires sni_hostname",
                ));
            };
            let server_name = crate::reality::parse_server_name(&sni_hostname)?;
            let cipher_suites = cipher_suites.into_vec();

            if vision {
                let ResolvedClientProxyConfig::Vless {
                    user_id,
                    udp_enabled,
                    ..
                } = protocol.as_ref()
                else {
                    unreachable!("validated by validate_resolved_client_vision_protocol");
                };
                let user_id_bytes = parse_uuid(user_id)?.into_boxed_slice();
                Box::new(RealityClientHandler::new_vision_vless(
                    public_key_bytes,
                    short_id_bytes,
                    server_name,
                    cipher_suites,
                    user_id_bytes,
                    *udp_enabled,
                ))
            } else {
                let inner_handler =
                    create_with_hop_context(*protocol, hop_location, None, resolver)?;
                Box::new(RealityClientHandler::new(
                    public_key_bytes,
                    short_id_bytes,
                    server_name,
                    cipher_suites,
                    inner_handler,
                ))
            }
        }
    })
}
