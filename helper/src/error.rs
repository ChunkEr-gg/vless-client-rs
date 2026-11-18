//! Error types for `vless-tray-helper`.

use std::io;

use thiserror::Error;
use vless_ipc::HelperValidationError;

/// Unified error type for privileged helper operations, validation, authentication, and journaling.
#[derive(Debug, Error)]
pub enum HelperError {
    #[error("validation error: {0}")]
    Validation(#[from] HelperValidationError),

    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("unauthorized caller: {0}")]
    Unauthorized(String),

    #[error("invalid owner-uid configuration: {0}")]
    OwnerUidConfig(String),

    #[error("invalid helper state transition: {0}")]
    InvalidState(String),

    #[error("state journal error: {0}")]
    Journal(String),

    #[error("system command `{program}` failed ({status}): {stderr}")]
    CommandFailed {
        program: String,
        status: String,
        stderr: String,
    },

    #[error("system backend error: {0}")]
    Backend(String),
}
