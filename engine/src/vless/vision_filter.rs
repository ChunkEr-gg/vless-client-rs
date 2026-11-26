use crate::buf_reader::BufReader;

// TLS record & handshake constants
const TLS_HEADER_LEN: usize = 5;
const TLS_CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
const TLS_HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
const TLS_HANDSHAKE_TYPE_SERVER_HELLO: u8 = 0x02;
const TLS_EXT_SUPPORTED_VERSIONS: u16 = 0x002b;

/// RFC 8446 §4.1.3 SHA-256("HelloRetryRequest") magic ServerHello.random value.
const RETRY_REQUEST_RANDOM_BYTES: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

pub(crate) struct ParsedServerHello {
    pub cipher_suite: u16,
    pub is_tls13: bool,
}

/// Strictly parses a TLS ServerHello record to detect negotiated version and cipher suite.
pub(crate) fn parse_server_hello(server_hello_frame: &[u8]) -> std::io::Result<ParsedServerHello> {
    if server_hello_frame.len() < 47 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "ServerHello frame too short",
        ));
    }
    if server_hello_frame[0] != TLS_CONTENT_TYPE_HANDSHAKE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "expected handshake content type",
        ));
    }
    if server_hello_frame[1] != 3 || server_hello_frame[2] != 3 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "unexpected record TLS version {}.{}",
                server_hello_frame[1], server_hello_frame[2]
            ),
        ));
    }

    let mut reader = BufReader::new(&server_hello_frame[TLS_HEADER_LEN..]);
    if reader.read_u8()? != TLS_HANDSHAKE_TYPE_SERVER_HELLO {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "expected ServerHello handshake type",
        ));
    }

    let message_len = reader.read_u24_be()? as usize;
    if reader.remaining() < message_len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "ServerHello message length exceeds frame",
        ));
    }
    let mut reader = BufReader::new(reader.read_slice(message_len)?);
    let version_major = reader.read_u8()?;
    let version_minor = reader.read_u8()?;
    if version_major != 3 || version_minor != 3 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("expected TLS version 3.3, got {version_major}.{version_minor}"),
        ));
    }

    let server_random = reader.read_slice(32)?;
    if server_random == RETRY_REQUEST_RANDOM_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "server sent a HelloRetryRequest",
        ));
    }

    let session_id_len = reader.read_u8()?;
    if session_id_len > 32 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid session_id_len {session_id_len}, max is 32"),
        ));
    }
    reader.skip(session_id_len as usize)?;

    let cipher_suite = reader.read_u16_be()?;
    reader.skip(1)?; // compression method
    let mut is_tls13 = false;
    if !reader.is_consumed() {
        let extensions_len = reader.read_u16_be()? as usize;
        if reader.remaining() < extensions_len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "extensions length exceeds remaining data",
            ));
        }
        let extensions_data = reader.read_slice(extensions_len)?;
        if !reader.is_consumed() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "trailing data after ServerHello extensions",
            ));
        }
        let mut ext_reader = BufReader::new(extensions_data);
        while !ext_reader.is_consumed() {
            let ext_type = ext_reader.read_u16_be()?;
            let ext_len = ext_reader.read_u16_be()?;
            if ext_type == TLS_EXT_SUPPORTED_VERSIONS {
                if ext_len != 2 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("supported_versions extension should be 2 bytes, got {ext_len}"),
                    ));
                }
                let version_bytes = ext_reader.read_slice(2)?;
                is_tls13 = version_bytes[0] == 0x03 && version_bytes[1] == 0x04;
            } else {
                ext_reader.skip(ext_len as usize)?;
            }
        }
    }

    Ok(ParsedServerHello {
        cipher_suite,
        is_tls13,
    })
}

/// VISION protocol filter state
///
/// This structure maintains only the state needed for TLS record filtering
/// and detection, tracking TLS patterns and remaining records to analyze.
#[derive(Debug)]
pub struct VisionFilter {
    /// Number of records remaining to analyze for TLS patterns
    record_filter_count: usize,

    /// Any TLS version detected (ClientHello seen)
    is_tls: bool,

    /// TLS 1.2 or above detected (ServerHello seen)
    is_tls12_or_above: bool,

    /// Whether XTLS can be enabled (TLS 1.3 + supported cipher)
    supports_xtls: bool,
}

impl VisionFilter {
    /// Create a new VisionFilter with default record count
    pub fn new() -> Self {
        Self::new_with_record_count(8)
    }

    fn new_with_record_count(record_count: usize) -> Self {
        Self {
            record_filter_count: record_count,
            supports_xtls: false,
            is_tls: false,
            is_tls12_or_above: false,
        }
    }

    /// Check if filtering is complete
    pub fn is_filtering(&self) -> bool {
        self.record_filter_count > 0
    }

    pub fn decrement_filter_count(&mut self) {
        self.record_filter_count = self.record_filter_count.saturating_sub(1);
    }

    pub fn stop_filtering(&mut self, reason: String) {
        log::debug!("VISION: Stopping filtering - {}", reason);
        self.record_filter_count = 0;
    }

    /// Returns true if any TLS version has been detected (ClientHello seen)
    pub fn is_tls(&self) -> bool {
        self.is_tls
    }

    /// Returns true if TLS 1.2 or above has been detected (ServerHello seen)
    pub fn is_tls12_or_above(&self) -> bool {
        self.is_tls12_or_above
    }

    /// Returns true if XTLS can be enabled (TLS 1.3 + supported cipher)
    pub fn supports_xtls(&self) -> bool {
        self.supports_xtls
    }

    /// Analyze a complete TLS record for patterns and update state accordingly
    ///
    /// Caller must extract complete TLS records using TlsDeframer before calling this.
    /// This method detects ClientHello, ServerHello, TLS version, cipher suite, and
    /// ApplicationData to determine when to switch to direct copy mode.
    ///
    /// This is a public method now - VisionStream will call it after recordizing.
    pub fn filter_record(&mut self, data: &[u8]) {
        if self.record_filter_count == 0 {
            return;
        }

        self.record_filter_count = self.record_filter_count.saturating_sub(1);

        if data.len() < 5 {
            // invalid record length
            self.stop_filtering(format!("invalid record length: {}", data.len()));
            return;
        }

        // Detect ClientHello - minimal check for TLS handshake record
        if !self.is_tls
            && data.len() >= 6
            && data[0] == TLS_CONTENT_TYPE_HANDSHAKE
            && data[1] == 0x03 // TLS version major
            && data[5] == TLS_HANDSHAKE_TYPE_CLIENT_HELLO
        {
            self.is_tls = true;
            log::debug!("VISION: Detected TLS ClientHello");
        }

        // Detect and parse ServerHello
        if !self.is_tls12_or_above
            && data.len() >= 6
            && data[0] == TLS_CONTENT_TYPE_HANDSHAKE
            && data[1] == 0x03 // TLS version major
            && data[2] == 0x03 // TLS version minor (1.2)
            && data[5] == TLS_HANDSHAKE_TYPE_SERVER_HELLO
        {
            self.is_tls12_or_above = true;
            self.is_tls = true;

            // Parse ServerHello properly - delegate to vision_tls_util
            match parse_server_hello(data) {
                Ok(parsed) => {
                    log::debug!(
                        "VISION: Detected TLS cipher suite: 0x{:04x}",
                        parsed.cipher_suite
                    );

                    if parsed.is_tls13 {
                        log::debug!("VISION: Detected TLS 1.3 via supported_versions extension");

                        // Xray and Mihomo allow GCM, ChaCha20 and CCM, but not CCM_8 or unknown suites.
                        if matches!(parsed.cipher_suite, 0x1301..=0x1304) {
                            self.supports_xtls = true;
                            log::debug!(
                                "VISION: TLS 1.3 with supported cipher 0x{:04x} - XTLS enabled",
                                parsed.cipher_suite
                            );
                        } else {
                            log::warn!(
                                "VISION: TLS 1.3 detected but cipher 0x{:04x} not supported for XTLS",
                                parsed.cipher_suite
                            );
                        }

                        // Stop filtering early
                        self.stop_filtering("TLS 1.3 handshake detected".to_string());
                    }
                }
                Err(e) => {
                    self.stop_filtering(format!("invalid ServerHello: {}", e));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vision_filter_initialization() {
        let filter = VisionFilter::new();

        assert!(filter.is_filtering());
        assert!(!filter.supports_xtls());
        assert!(!filter.is_tls());
        assert!(!filter.is_tls12_or_above());
    }

    #[test]
    fn test_vision_filter_with_custom_record_count() {
        let filter = VisionFilter::new_with_record_count(5);

        assert!(filter.is_filtering());
        assert!(!filter.supports_xtls());
        assert!(!filter.is_tls());
    }

    #[test]
    fn test_stop_filtering() {
        let mut filter = VisionFilter::new();

        assert!(filter.is_filtering());

        filter.stop_filtering("test".to_string());

        assert!(!filter.is_filtering());
    }

    #[test]
    fn test_detect_client_hello() {
        let mut filter = VisionFilter::new();

        // Mock ClientHello record
        let client_hello = vec![
            0x16, 0x03, 0x01, // TLS Handshake, version 3.1
            0x00, 0x05, // Length: 5
            0x01, // ClientHello type
            0x00, 0x00, 0x00, // Rest of handshake
        ];

        filter.filter_record(&client_hello);

        assert!(filter.is_tls());
        assert!(!filter.supports_xtls()); // Not enabled until TLS 1.3 ServerHello
    }

    #[test]
    fn test_detect_server_hello_tls12() {
        let mut filter = VisionFilter::new();

        // Mock ServerHello record (TLS 1.2)
        let server_hello = vec![
            0x16, 0x03, 0x03, // TLS Handshake, version 3.3 (TLS 1.2)
            0x00, 0x05, // Length: 5
            0x02, // ServerHello type
            0x00, 0x00, 0x00, // Rest of handshake
        ];

        filter.filter_record(&server_hello);

        assert!(filter.is_tls());
        assert!(filter.is_tls12_or_above());
    }

    #[test]
    fn test_detect_application_data() {
        let mut filter = VisionFilter::new();

        // First detect TLS
        let client_hello = vec![
            0x16, 0x03, 0x01, // TLS Handshake
            0x00, 0x05, // Length: 5
            0x01, // ClientHello type
            0x00, 0x00, 0x00,
        ];
        filter.filter_record(&client_hello);

        // Then ApplicationData
        let app_data = vec![
            0x17, 0x03, 0x03, // ApplicationData, TLS 1.2
            0x00, 0x05, // Length: 5
            0x00, 0x00, 0x00, 0x00, 0x00, // Encrypted data
        ];

        filter.filter_record(&app_data);

        assert!(filter.is_tls());
        assert!(filter.is_filtering());
    }

    #[test]
    fn test_record_count_decrements() {
        let mut filter = VisionFilter::new_with_record_count(3);

        let dummy_record = vec![0x16, 0x03, 0x01, 0x00, 0x05, 0x00];

        filter.filter_record(&dummy_record);
        assert!(filter.is_filtering());

        filter.filter_record(&dummy_record);
        assert!(filter.is_filtering());

        filter.filter_record(&dummy_record);
        assert!(!filter.is_filtering());

        // Further calls should not decrement
        filter.filter_record(&dummy_record);
        assert!(!filter.is_filtering());
    }

    #[test]
    fn test_filter_record_no_processing_when_complete() {
        let mut filter = VisionFilter::new();
        filter.stop_filtering("test".to_string());

        let data = vec![0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00];

        // Should return immediately without processing
        filter.filter_record(&data);

        assert!(!filter.is_tls()); // State shouldn't change
        assert!(!filter.is_filtering());
    }

    #[test]
    fn test_short_record_ignored() {
        let mut filter = VisionFilter::new();

        let short_record = vec![0x16, 0x03, 0x01]; // Less than 6 bytes

        filter.filter_record(&short_record);

        assert!(!filter.is_tls()); // Should not detect anything
        assert!(!filter.is_filtering()); // Filtering stopped due to invalid record
    }

    #[test]
    fn test_non_tls_record_ignored() {
        let mut filter = VisionFilter::new();

        let non_tls_record = vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];

        filter.filter_record(&non_tls_record);

        assert!(!filter.is_tls());
        assert!(!filter.supports_xtls());
        assert!(filter.is_filtering());
    }

    #[test]
    fn test_filter_record_client_hello() {
        let mut filter = VisionFilter::new();

        // Simulate ClientHello
        let client_hello = vec![0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00];

        filter.filter_record(&client_hello);

        assert!(filter.is_tls());
        assert!(!filter.supports_xtls()); // Not optimistically enabled anymore
    }

    #[test]
    fn test_filter_record_server_hello() {
        let mut filter = VisionFilter::new();

        // Simulate ServerHello
        let server_hello = vec![0x16, 0x03, 0x03, 0x00, 0x05, 0x02, 0x00, 0x00, 0x00, 0x00];

        filter.filter_record(&server_hello);

        assert!(filter.is_tls());
        assert!(filter.is_tls12_or_above());
    }

    #[test]
    fn test_client_hello_only_detected_once() {
        let mut filter = VisionFilter::new();

        let client_hello = vec![0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00];

        filter.filter_record(&client_hello);
        assert!(filter.is_tls());
        assert!(filter.is_filtering());

        // Send again - should not reset state
        filter.filter_record(&client_hello);
        assert!(filter.is_tls());
        assert!(filter.is_filtering());
    }

    #[test]
    fn test_server_hello_only_detected_once() {
        let mut filter = VisionFilter::new();

        let server_hello = vec![0x16, 0x03, 0x03, 0x00, 0x05, 0x02, 0x00, 0x00, 0x00, 0x00];

        filter.filter_record(&server_hello);
        assert!(filter.is_tls12_or_above());
        // Note: This mock ServerHello is too short and will cause parse_server_hello to fail,
        // which stops filtering. This is expected behavior - invalid records stop filtering.
        assert!(!filter.is_filtering());
    }
}
