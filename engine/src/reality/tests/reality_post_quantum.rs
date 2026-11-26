use std::io::{Read, Write};

use crate::reality::DEFAULT_CIPHER_SUITES;
use crate::reality::reality_hello::RealityGroup;

use super::reality_fixtures::{configs, handshake, target_records};

#[test]
fn reality_pq_handshake_and_data_all_suites() {
    for &cipher in DEFAULT_CIPHER_SUITES {
        for group in [RealityGroup::X25519MlKem768, RealityGroup::X25519] {
            let (cc, sc) = configs(cipher);
            let (mut client, mut server) = handshake(cc, sc, group, target_records, 37);
            let expected = vec![17; 200_000];
            let mut wire = Vec::new();
            for chunk in expected.chunks(8192) {
                client.writer().write_all(chunk).unwrap();
                while client.wants_write() {
                    client.write_tls(&mut wire).unwrap();
                }
            }
            let mut actual = Vec::new();
            for chunk in wire.chunks(1024) {
                server.feed(chunk).unwrap();
                let mut buffer = [0; 16384];
                loop {
                    match server.reader().read(&mut buffer) {
                        Ok(0) => break,
                        Ok(n) => actual.extend_from_slice(&buffer[..n]),
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(e) => panic!("{e}"),
                    }
                }
            }
            assert_eq!(actual, expected);
            server.writer().write_all(b"response").unwrap();
            wire.clear();
            server.write_tls(&mut wire).unwrap();
            client.feed(&wire).unwrap();
            let mut response = [0; 8];
            client.reader().read_exact(&mut response).unwrap();
            assert_eq!(&response, b"response");
            client.send_close_notify();
            wire.clear();
            client.write_tls(&mut wire).unwrap();
            server.feed(&wire).unwrap();
            assert_eq!(server.reader().read(&mut response).unwrap(), 0);
        }
    }
}
