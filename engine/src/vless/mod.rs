// VLESS protocol implementation with Vision and XUDP support (`PLAN.md` §6)

pub mod vless_client_handler;
#[cfg(test)]
pub mod vless_message_stream;
#[cfg(test)]
pub mod vless_server_handler;

mod tls_fuzzy_deframer;
mod tls_handshake_util;
pub(crate) mod vision_filter;
mod vision_pad;
mod vision_stream;
pub(crate) use vision_stream::VisionWriteErrorPolicy;
mod vision_transport;
mod vision_unpad;
mod vless_response_stream;
mod vless_util;
