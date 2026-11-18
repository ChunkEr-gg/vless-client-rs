# What Was Removed from `shoes`, and What Was Added

`engine/` (`vless-engine` / `vless_engine`) is a focused strip-down of
[`cfal/shoes`](https://github.com/cfal/shoes) (`v0.3.8`, MIT) at commit
`7680938b96a245a21d9e481ad009205b956e4436` (2026-11-16).

The goal is a minimal, low-impact macOS client engine purpose-built for the two
listener types of [`reality-ktls`](https://github.com/ChunkEr-gg/reality-ktls):

1. **`REALITY`**: VLESS + REALITY (`X25519MLKEM768` / `X25519` + Ed25519 HMAC
   certificate authentication) + `xtls-rprx-vision`, TCP via command `0x01`,
   UDP via Mux `0x03` carrying XUDP.
2. **`kTLS`**: VLESS over plain TLS 1.3 (`rustls`), empty VLESS wire flow,
   verified against the macOS System Keychain (`Security.framework`) or an
   optional SHA-256 leaf certificate pin (`pcs`), TCP via command `0x01`, UDP
   via Mux `0x03` carrying XUDP.

Everything out of scope was **deleted from the source tree**, not hidden behind
Cargo feature flags. Upstream git history preserves the removed subsystems.

---

## 1. Origin & Baseline Reduction

| Metric | Upstream `cfal/shoes` @ `7680938b` | Stripped `engine/` (`vless-engine`) | Delta |
|---|---:|---:|---:|
| License | MIT (`LICENSE`) | MIT (`LICENSE` + `NOTICE`) | Unchanged |
| Crate targets | `rlib`, `cdylib`, `staticlib`, bin `shoes` | `rlib` (`vless_engine`), bin `vless-engine` | C/JNI FFI targets removed |
| `src/` Rust source | 450 `.rs` files (~220,441 lines) | ~115 `.rs` files (~39,700 lines) | **~82% source reduction** |
| `tests/` + `benches/` Rust code | 133 `.rs` files (~56,407 lines) | Struct-based E2E + binary IPC tests | YAML/multi-protocol harnesses removed |
| Total Rust lines in repo | 584 `.rs` files (~276,962 lines) | ~40k lines in `engine/` (~55k across all 4 workspace crates) | **~85% reduction vs upstream** |
| Direct runtime/target dependencies | 77 crates + 9 `[patch.crates-io]` overrides | 29 crates + 2 `[patch.crates-io]` overrides | **50 crates & 7 git patches dropped** |

---

## 2. Deleted Source Modules

### 2.1 Protocols & Obfuscation Layers

`vless-tray` speaks VLESS (`encryption=none`) exclusively to `reality-ktls`
servers. Every other proxy protocol, obfuscation wrapper, post-quantum VLESS
inner cipher, and legacy UDP framing path was removed.

| Deleted Module | Upstream Location | Rationale |
|---|---|---|
| VMess | `src/vmess/**` (11 files) | AEAD/legacy VMess client and server handlers, replay cache, CRC32/FNV1a/MD5 framing; unsupported by `reality-ktls`. |
| Shadowsocks & SS-2022 | `src/shadowsocks/**` (11 files) | AEAD and BLAKE3-keyed Shadowsocks-2022 TCP/UDP handlers and salt replay checkers. |
| Trojan | `src/trojan_handler.rs` | SHA-224 password-authenticated Trojan client and server handler. |
| Snell | `src/snell/**` (4 files) | Snell v1–v3 client/server streams and UDP framing. |
| Hysteria2 server | `src/hysteria2_server.rs` | QUIC-based Hysteria2 server inbound and Salamander obfuscator. |
| TUIC v5 server | `src/tuic_server.rs`, `src/tuic_server/pre_auth.rs` | QUIC-based TUIC v5 server inbound and pre-authentication state machine. |
| AnyTLS | `src/anytls/**` (14 files) | AnyTLS session multiplexer, idle connection pool, and padding scheme. |
| NaiveProxy | `src/naiveproxy/**` (11 files) | HTTP/2 CONNECT tunnel (`hyper`), padding stream, and server handler. |
| WireGuard | `src/wireguard/**` (5 files) | Userspace WireGuard (`gotatun`) endpoint, detour dialer, and TUN I/O loop. |
| ShadowTLS v3 | `src/shadow_tls/**` (9 files) | ShadowTLS v3 client/server handshake wrapper and HMAC record stream. |
| Sudoku mask | `src/sudoku_mask/**` (8 files) | Byte-substitution obfuscation codec, Go RNG table generator, and stream wrapper. |
| Sing-box UoT | `src/uot/**` (4 files) | `sp.v1.udp-over-tcp.arpa` / `sp.v2.udp-over-tcp.arpa` UDP-over-TCP framing; `reality-ktls` uses XUDP (`COMMAND_MUX` `0x03`) exclusively. |
| VLESS native encryption | `src/vless/encryption/**` (17 files) | Experimental ML-KEM / XOR-masked inner VLESS encryption and session resumption; `vless-tray` enforces `encryption=none` inside TLS 1.3 / REALITY. |
| REALITY ML-DSA-65 | `src/reality/reality_mldsa.rs` | Optional ML-DSA-65 server signature verification; `reality-ktls` authenticates REALITY certificates with Ed25519 + HMAC-SHA512 (`verify_certificate_hmac`) while offering `X25519MLKEM768` + `X25519` key exchange. |
| Plain `0x02` VLESS client UDP | `write_vless_udp_header` in `src/vless/vless_client_handler.rs`, client use of `src/vless/vless_message_stream.rs`, `src/vless/vless_message_stream/tests.rs` | Upstream `shoes` sent single-target `COMMAND_UDP` (`0x02`) when Vision was off. Replaced by unified `COMMAND_MUX` (`0x03`) + `XudpClientStream` so both REALITY and `kTLS` share one XUDP implementation. |

### 2.2 Transports & Linux Zero-Copy Splice

`vless-tray` enforces `type=tcp` for remote VLESS connections and HTTP/1.1 +
SOCKS5 for local proxy listeners.

| Deleted Module | Upstream Location | Rationale |
|---|---|---|
| WebSocket (`ws` / `wss`) | `src/websocket/**` (6 files) | `hyper-tungstenite` WebSocket upgrade transport and `Sec-WebSocket-Protocol` early-data stream. |
| XHTTP / SplitHTTP | `src/xhttp/**` (12 files) | Xray SplitHTTP / XHTTP (`h1`, `h2`, `h3`) packetized HTTP carrier, client, and server. |
| `h2mux` | `src/h2mux/**` (13 files) | Sing-box HTTP/2 stream multiplexer, activity tracker, and padding framing. |
| HTTP/2 proxy | `src/http2/**` (8 files) | HTTP/2 CONNECT client and server transport (`h2` + `hyper`); local HTTP proxy inbound uses lightweight HTTP/1.1 (`httparse`). |
| QUIC client & server stack | `src/quic_client/**` (10 files), `src/quic_endpoint.rs`, `src/quic_endpoint/tests.rs`, `src/quic_server.rs`, `src/quic_stream.rs` | `quinn` / `quinn-proto` / `h3` endpoints, port-hopping client dialer, Hysteria2/TUIC QUIC clients, and QUIC server listener. |
| Linux `splice(2)` | `src/splice.rs`, `src/splice/tests.rs`, `src/vless/vision_stream/tests/{splice,native_splice,native_decisions,native_errors}.rs` | Linux-specific pipe `splice(2)` zero-copy relay for Vision direct-copy mode; XNU/macOS has no `splice(2)` syscall. |

### 2.3 Server-Side Listeners, Certificate Automation & Insecure Verifier

`vless-engine` is strictly a client; its only listeners are the unprivileged
local `127.0.0.1` mixed HTTP/SOCKS5 proxy and the userspace `smoltcp` `utun`
stack.

| Deleted Module | Upstream Location | Rationale |
|---|---|---|
| Inbound TLS server | `src/tls_server_handler.rs` | Server-side TLS termination, SNI routing, and fallback forwarding. |
| Port forwarder | `src/port_forward_handler.rs` | Standalone TCP/UDP port-forwarding server inbound. |
| Server handler factory | `src/tcp/tcp_server_handler_factory.rs` | Constructed multi-protocol server listeners from YAML server blocks. |
| ACME & certificate rotation | `src/certificates/**` (7 files) | `instant-acme` HTTP-01 / TLS-ALPN-01 certificate issuance, PEM file hot-rotation, and QUIC server cert reloader. |
| `DisabledVerifier` (`allowInsecure`) | `DisabledVerifier`, `get_disabled_verifier` in `src/rustls_config_util.rs` | Accepted arbitrary untrusted server certificates when `verify: false`. Deleted so unverified TLS without an explicit SHA-256 leaf pin (`pcs`) is rejected at config build time. |

### 2.4 Control Plane, Multi-Config Supervisor & External Rule Sets

| Deleted Module | Upstream Location | Rationale |
|---|---|---|
| Clash REST/WS API | `src/clash_api/**` (7 files) | Clash-compatible HTTP/WebSocket control API, token auth, traffic/memory streams, and group selector endpoints. |
| Runtime control catalog | `src/control/**` (15 files) | Proxy group store, URL-test latency prober, active flow registry, connection notes, and live rule switcher. |
| External rule sets & updater | `src/rule_set/**` (11 files), `src/rule_updater/**` (5 files) | V2Ray GeoIP/GeoSite `.dat` (`prost`), Sing-box `.srs` (`ruzstd`/`flate2`), and Mihomo `.mrs` parsers plus periodic HTTP rule-set downloaders. |
| File watcher & YAML supervisor | `src/file_watcher.rs`, `src/process.rs`, `src/process/tests.rs` | `notify` config-file hot reloader and multi-config daemon supervisor. Process lifecycle is now managed by `vless-tray` over `stdin`/`stdout` JSON-lines. |
| Multi-file YAML config compiler | `src/config/**` (43 files), `src/rules/{compile,config}.rs`, `src/client_proxy_chain/composition.rs` | Multi-document YAML parser (`serde_yaml`, `yaml-rust2`), multi-hop chain builder, and group compiler. Replaced by typed `EngineConfig` (`engine/src/config.rs`). |
| Rotating file logger & old CLI | `src/logging.rs`, `src/logging/file.rs`, `src/logging/file/tests.rs`, `src/cli.rs` | Replaced by JSON-lines `EngineToApp::Log` streaming to the app UI and the slim `vless-engine` entrypoint. |

### 2.5 DNS Stack

| Deleted Module | Upstream Location | Rationale |
|---|---|---|
| Full upstream DNS subsystem | `src/dns/**` (29 files: `hickory_resolver`, DoH/DoT/DoQ, `fake_ip/*`, `tendns_resolver`, `hosts`, `composite_resolver`, `proxy_runtime`, `bootstrap`, `guard`, `system`), `src/cli/tendns_generator.rs` | Replaced by `engine/src/dns_proxy.rs` (`PLAN.md` §5.4): intercepts TUN UDP/TCP port 53 (`IngressTarget::LocalDns`) and forwards DNS queries over a single long-lived XUDP association to `<dns_resolver>:53` (default `1.1.1.1:53`) with DNS ID rewriting and automatic reconnect, eliminating `hickory-*`, `tendns`, DoH/DoT, and Fake-IP state. |

### 2.6 Platform-Specific Linux/Mobile Code, FFI & NTP

| Deleted Module | Upstream Location | Rationale |
|---|---|---|
| Linux desktop privileges | `src/desktop/**` (13 files: `nft.rs`, `routes.rs`, `resolved.rs`, `underlay.rs`, `journal.rs`, etc.) | Linux `nftables`, `rtnetlink`, and `systemd-resolved` automation. macOS root privilege isolation lives in the dedicated `helper/` crate (`vless-tray-helper`). |
| Mobile C/JNI FFI | `src/ffi/**` (9 files: `android.rs`, `ios.rs`, `common.rs`, `stub.rs`, tests) | Android JNI (`jni`, `ndk-sys`, `android_logger`) and iOS C staticlib bindings. |
| Linux TUN creation, offload & retained FDs | `src/tun/{platform,offload,retained}.rs` | `/dev/net/tun` creation via the `tun` crate, Linux VirtIO GSO/GRO offload ioctls, and FFI hot-reload fd retention. On macOS, `vless-tray-helper` opens `com.apple.net.utun_control` and passes the sole `utun` fd over `SCM_RIGHTS`. |
| Built-in SNTP client | `src/ntp.rs`, `src/ntp/tests.rs`, NTP offset in `src/clock.rs` | macOS synchronizes system clocks via `timed`; REALITY authentication failures caused by clock skew surface a clear `REALITY_AUTH_OR_CLOCK_ERROR` diagnostic (`PLAN.md` §5.6). |
| Unused buffers & Linux socket mark | `src/slide_buffer.rs`, `src/udp_fragments.rs`, `src/routing/udp_relay.rs`, `src/rustls_connection_util.rs`, `src/thread_util.rs`, `build.rs`, Linux `SO_MARK` in `src/socket_policy.rs` | Dead helpers left unreferenced once VMess, QUIC, UoT, TLS server inbound, YAML worker sizing, and Linux routing marks were removed. |

### 2.7 Repository Material

Deleted non-engine repository assets from upstream `shoes`:

- `docs/` (Astro static documentation site, Node.js scripts, and manuals)
- `examples/` (63 multi-protocol YAML configuration files)
- `benches/` (`path_measurement.rs`, `selector_measurement.rs`, `sudoku_measurement.rs`, and `.mjs`/`.sh` benchmark runners)
- `Dockerfile`, `.dockerignore`, `Cross.toml` (Linux container and cross-build configs)
- `cbindgen.toml`, `include/shoes.h` (C header generation for mobile FFI)
- `scripts/` (13 Python/Node release packaging, Docker smoke, and license scripts)
- `about.toml`, `DEPENDENCIES.md`, `THIRD_PARTY_NOTICES.md`, `licenses/`, `CHANGELOG.md`, `.github/`

Upstream's `LICENSE` (MIT) is preserved unchanged at the workspace root, and
`NOTICE` records `cfal/shoes` alongside the pinned `rustls` and `smoltcp` forks.

---

## 3. Test-Only Counterparties (`#[cfg(test)]`)

Following the same pattern as `reality-ktls`, a small set of server-side
protocol counterparties are retained **strictly under `#[cfg(test)]`** so
in-process handshake, Vision framing, and XUDP multiplexing tests run against
real cryptographic peers without compiling any server code into release
binaries (`vless-engine`, `vless-tray`):

| Test-Only Module | Location in `engine/src/` | Role in Tests |
|---|---|---|
| `reality_certificate`, `reality_server`, `reality_target_flight` (`RealityServerConfig`) | `engine/src/reality/{mod,reality_certificate,reality_server,reality_target_flight}.rs` (`reality_server_handler.rs` deleted) | Authenticates REALITY `ClientHello`s, signs temporary Ed25519 certificates with HMAC-SHA512, and constructs synthetic target flights for `reality::tests` and `e2e_tests` (including cover-site fallback tests). |
| `vless_server_handler` (`VlessTcpServerHandler`, `setup_custom_tls_vision_vless_server_stream`) & `vless_message_stream` | `engine/src/vless/{mod,vless_server_handler,vless_message_stream}.rs` | Terminates VLESS `COMMAND_TCP` (`0x01`) and `COMMAND_MUX` (`0x03`) streams (with and without `xtls-rprx-vision`) for `vless_client_handler::tests` and `e2e_tests`. |
| `xudp::message_stream` (`XudpMessageStream`) | `engine/src/xudp/{mod,message_stream}.rs` | Server-side session-multiplexed XUDP frame decoder/encoder counterparty for `XudpClientStream` unit and E2E tests. |
| `try_create_server_config`, `with_test_roots` | `engine/src/rustls_config_util.rs` | Builds `rustls::ServerConfig` instances and scoped test root stores for TLS 1.3 and `pcs` SHA-256 pinning unit tests. |

---

## 4. Targeted Modifications & Additions to Kept Code

| Area | Files in `engine/` & `ipc/` | Change vs Upstream `shoes` |
|---|---|---|
| **Non-Vision VLESS Mux `0x03` + `XudpClientStream` for `kTLS`** | `engine/src/vless/vless_client_handler.rs` | Upstream `VlessTcpClientHandler::setup_client_udp_bidirectional` sent `COMMAND_UDP` (`0x02`) + `VlessMessageStream`. Replaced with a 19-byte VLESS Mux header (`0x00 \|\| uuid(16B) \|\| addon_len=0x00 \|\| COMMAND_MUX=0x03`, omitting the implicit `v1.mux.cool:666` destination), wrapped in `VlessResponseStream` + `XudpClientStream`. Matches `reality-ktls`'s `ktls` listener (`src/server/ktls.rs`) and unifies UDP framing across REALITY and `kTLS`. |
| **macOS Keychain Verification, `pcs` Leaf Pinning & Minimal DER Parser** | `engine/src/rustls_config_util.rs`, `engine/src/reality/reality_certificate_verify.rs` | Added `rustls-platform-verifier` so `verify = true` validates server certificates against the macOS System Keychain (`Security.framework`, with `webpki-roots` fallback on non-macOS test hosts lacking system CA bundles). Kept `ServerFingerprintVerifier` (`aws-lc-rs` SHA-256 over end-entity DER) for `pcs=<64-hex>` leaf pinning (supporting self-signed `kTLS` servers when pinned). Deleted `DisabledVerifier`. Replaced `x509-parser` in `reality_certificate_verify.rs` with a strict minimal ASN.1 DER X.509 parser extracting the 32-byte Ed25519 SPKI and verifying its 64-byte HMAC-SHA512 signature in constant time (`subtle::ConstantTimeEq`). |
| **`REALITY_AUTH_OR_CLOCK_ERROR` Cover-Site Fallback Diagnostic** | `engine/src/reality/reality_client_handler.rs`, `engine/src/lib.rs`, `ipc/src/engine_ipc.rs` | When a REALITY server rejects `ClientHello` authentication (`pbk`, `sid`, `sni`, or clock skew exceeding `maxTimeDiffMs`) and hands the session to the cover site, certificate HMAC verification fails. `map_reality_handshake_error` maps that failure to `"The server did not accept this client. Check pbk, sid and sni, and that the Mac's clock is correct (within the server's maxTimeDiffMs)."` and publishes `EngineStatus::Error` to the app. |
| **macOS `IP_BOUND_IF` / `IPV6_BOUND_IF` Outbound Socket Binding & Live `NetworkChanged` Updates** | `engine/src/socket_policy.rs`, `engine/src/socket_util.rs`, `engine/src/config.rs`, `engine/src/main.rs` | Upstream `bind_socket_interface` panicked on macOS (`unsupported platform`). Implemented `IP_BOUND_IF` and `IPV6_BOUND_IF` via `libc::if_nametoindex` / `libc::if_indextoname` and `socket2::SockRef::bind_device_by_index_v4` / `bind_device_by_index_v6` for all non-loopback outbound TCP and UDP sockets. When `vless-tray-helper`'s `PF_ROUTE` monitor emits `HelperMessage::NetworkChanged`, `vless-engine` updates the bound physical interface index dynamically for subsequent outbound flows. |
| **Raw-FD `utun` `AF_INET`/`AF_INET6` Framing, Single-Association XUDP Port-53 DNS Forwarder & Direct Server Re-Resolution** | `engine/src/tun/{mod,tun_server,tcp_stack_direct}.rs`, `engine/src/dns_proxy.rs`, `engine/src/client_proxy_selector.rs`, `engine/src/resolver.rs`, `engine/src/main.rs` | `run_tun_with_owned_fd` runs `smoltcp` over the `utun` `OwnedFd` received via `SCM_RIGHTS` with `packet_information = true` (4-byte big-endian `AF_INET` / `AF_INET6` header read and `writev` scatter-gather write on macOS). `dns_proxy.rs` intercepts TUN port-53 traffic and multiplexes DNS queries over one long-lived XUDP association to `<dns_resolver>:53` (rewriting 16-bit DNS IDs to demultiplex concurrent lookups and reconnecting on demand). `ServerEndpointResolver` pins the VLESS server's IPs resolved prior to TUN bring-up and refreshes them via direct physical-interface queries (`IP_BOUND_IF` to the original DNS servers recorded in the helper journal) on network changes or wake, preventing tunnel recursion and DNS leaks. |
| **Typed `EngineConfig` & Child/CLI Entrypoints** | `engine/src/config.rs`, `engine/src/tcp/chain_builder.rs`, `engine/src/lib.rs`, `engine/src/main.rs` | Replaced upstream's YAML config hierarchy with `EngineConfig` (`EngineInbound::MixedProxy` and `EngineInbound::Tun`), `EngineHandle`, newline-delimited JSON IPC (`AppToEngine` on `stdin`, `EngineToApp` on `stdout`, keeping VLESS UUIDs out of `ps` and exiting cleanly on `stdin` EOF), and `vless-engine run --link 'vless://...'` for direct CLI testing. |

---

## 5. Cargo Dependencies & Git Forks

### 5.1 Pinned Git Forks (`[patch.crates-io]`)

| Crate | Upstream `shoes` | `vless-client-rs` Workspace | Notes |
|---|---|---|---|
| `rustls` (`=0.23.46`) | `cfal/rustls` @ `f1a23c187330386e9e7f14a21dbae368034dc430` | **Kept** (same commit) | Required for client-side REALITY handshake hooks (`reality_rustls_adapter`). |
| `smoltcp` (`0.14`) | `cfal/smoltcp` @ `7ef43e497f575cb0340a43e4f414f0f0b8760bf6` | **Kept** (same commit) | Preserves TCP ACK sequence numbers during userspace TUN retransmission. |
| `nix` | `nix-rust/nix` @ `3eae6d68ec6382fef7b38cd58f97458e59a71af9` | **Dropped** | Transitive dependency of the `tun` crate; eliminated by passing the raw `utun` fd directly over `SCM_RIGHTS` using `libc` + `OwnedFd`. |
| `blake3` | `cfal/BLAKE3` @ `5bd8a7ef060bac222502a449bb89b7bdcdb8ec09` | **Dropped** | Only used by Shadowsocks-2022 (`blake3_key`). |
| `h3`, `h3-quinn` | `cfal/h3` @ `90e3013710e35143d1969dc3421f5951fbe49966` | **Dropped** | Only used by QUIC / HTTP/3 / DoH3 / XHTTP-H3. |
| `hickory-net`, `hickory-proto`, `hickory-resolver` | `cfal/hickory-dns` @ `93435e55f102ee637eadca89126be85931a804f3` | **Dropped** | Replaced by the single-association XUDP DNS forwarder (`dns_proxy.rs`). |

### 5.2 Dropped Runtime & Target Dependencies (50 Crates)

| Subsystem | Dropped Crates | Reason |
|---|---|---|
| Memory allocator | `tikv-jemallocator` | Replaced by the macOS system allocator (`libsystem_malloc`) for lower idle RSS in a menu-bar client (`PLAN.md` §6). |
| TUN & Linux netlink | `tun`, `rtnetlink` (plus `nix` patch) | Eliminated by direct `com.apple.net.utun_control` creation in `vless-tray-helper` and raw `OwnedFd` `SCM_RIGHTS` passing into `vless-engine`. |
| QUIC & HTTP/2 / HTTP/3 / WebSocket | `quinn`, `quinn-proto`, `h2`, `h3`, `h3-quinn`, `http`, `http-body-util`, `httpdate`, `hyper`, `hyper-util`, `hyper-tungstenite` | Only TCP outbound (`type=tcp`) and HTTP/1.1 (`httparse`) + SOCKS5 local inbound remain. |
| DNS stack & NTP | `hickory-resolver`, `tendns`, `sntpc` | Replaced by `dns_proxy.rs` and macOS system clock (`REALITY_AUTH_OR_CLOCK_ERROR` diagnostic). |
| ACME, server certs & X.509 parsing | `instant-acme`, `rcgen` (moved to `[dev-dependencies]` only), `x509-parser` | ACME deleted; `reality_certificate_verify.rs` uses an inline strict DER parser for Ed25519 SPKI. |
| Removed protocols & crypto | `gotatun`, `ml-kem`, `rust-argon2`, `blake2`, `blake3`, `md-5`, `shake`, `digest`, `rand_core` | Used only by WireGuard, VLESS native encryption, Shadowsocks, VMess, Trojan, and Snell. (`X25519MLKEM768` TLS key exchange comes directly from `aws-lc-rs` via `rustls`.) |
| YAML config, rule sets & hot reload | `serde_yaml`, `yaml-rust2`, `prost`, `ruzstd`, `flate2`, `notify`, `aho-corasick`, `regex`, `regex-automata`, `indexmap` | YAML configs and `.dat`/`.srs`/`.mrs` rule sets deleted; domain bypass matching uses compact suffix/exact matching in `rules/domain.rs`. |
| Clash API, supervisor & FFI | `dashmap`, `memory-stats`, `mime_guess`, `chrono`, `tracing`, `anyhow`, `android_logger`, `jni`, `ndk-sys`, `percent-encoding`, `url` | Control plane, file logger, and Android JNI removed (`url` and `percent-encoding` live in lightweight `vless-ipc` for `vless://` link parsing, not `vless-engine`). |

### 5.3 Kept & Added Dependencies in `engine/Cargo.toml`

- **Kept runtime dependencies (27):** `async-trait`, `aws-lc-rs`, `base64`, `bytes`, `etherparse`, `futures`, `httparse`, `ipnetwork`, `libc`, `log`, `lru`, `memchr`, `parking_lot` (`0.12.5`), `portable-atomic` (32-bit fallback target), `rand` (`0.10`), `rustc-hash`, `rustls` (`=0.23.46`), `serde`, `serde_json`, `smoltcp` (`0.14`), `socket2` (`0.6`), `subtle`, `tokio`, `tokio-util`, `uuid`, `webpki-roots`, `zeroize`.
- **Added runtime dependencies (2):**
  - `rustls-platform-verifier` (`0.6`) — macOS `Security.framework` System Keychain certificate verification for `kTLS` profiles.
  - `vless-ipc` (`path = "../ipc"`) — shared `Profile`, `vless://` URI parser/validator, and IPC wire types.
- **Dev-dependencies:** Kept `rcgen`, `tempfile`, `tokio` (`test-util`), `tokio-rustls`; dropped `shoes-test-support` (`tests/support` YAML/Docker/WireGuard harness) and Linux `nftables`.

---

## 6. Test Suites: Deleted, Kept, Rewritten & macOS IPv6 Targets

### 6.1 Deleted Upstream Integration Suites (`tests/`)

All 14 Cargo `[[test]]` binaries in upstream `tests/` that tested removed
protocols, YAML composition, or Linux-only kernel namespaces—along with the
`shoes-test-support` YAML fixture crate (`tests/support/`) and Go/binary test
vectors (`tests/fixtures/{anytls-peer,rule_sets,sudoku,vless_encryption}`)—were
removed:

| Deleted `[[test]]` Suite | Upstream Path | Why Deleted |
|---|---|---|
| `vless_encryption_interop` | `tests/vless_encryption_interop.rs` | Tested `vless/encryption` (`ml-kem` / XOR masking) against Xray. |
| `xhttp_interop` | `tests/xhttp_interop.rs`, `tests/cases/integration/xhttp_*.rs` | Tested SplitHTTP / XHTTP (`h1`/`h2`/`h3`) transports. |
| `ws_early_data` | `tests/ws_early_data.rs` | Tested WebSocket `2048`-byte early-data headers. |
| `rule_allocation`, `rule_properties`, `matcher_invariants` | `tests/rule_allocation.rs`, `tests/rule_properties.rs`, `tests/matcher_invariants.rs` | Tested `.srs`/`.mrs`/GeoIP/regex rule-set compilers and `aho-corasick` matchers. |
| `retention_allocation` | `tests/retention_allocation.rs`, `tests/cases/retention/{process,quic}.rs` | Tested multi-YAML hot-reload retention (`process.rs`) and QUIC endpoint memory retention. |
| `privileged` | `tests/privileged.rs`, `tests/cases/privileged/**` | Linux root/`CAP_NET_ADMIN` `nftables`, `/dev/net/tun` GSO offload, kernel WireGuard, and NaiveProxy UoT tests. |
| `process_contract` | `tests/process_contract.rs`, `tests/cases/process_contract/**` | Tested ACME certs, Clash API, Fake-IP persistence, rotating file logs, NTP, remote rule updaters, static hosts, and YAML CLI flags. |
| `optional_peer`, `external_network`, `stress`, `integration`, `reality_interop` (YAML harness) | `tests/{optional_peer,external_network,stress,integration,reality_interop}.rs` | Drove multi-protocol YAML server/client topologies via `shoes-test-support`. The VLESS + REALITY + Vision + XUDP and `kTLS` client paths they covered were rewritten as typed `EngineConfig` E2E tests (see §6.3). |

Inline unit test modules for removed subsystems (`vless/encryption/**`,
`reality/reality_mldsa.rs`, `reality/tests/reality_server_handler.rs`,
`vless/vision_stream/tests/*splice*.rs`, `vless/vless_message_stream/tests.rs`,
`client_proxy_chain/{carrier_tests,composition,tests}.rs` YAML multi-hop tests,
and `rustls_config_util/hybrid_tests.rs` server tests) were deleted alongside
their modules.

### 6.2 Kept Unit Test Modules (`engine/src/`)

Over 400 inline unit tests covering the retained protocol, crypto, packet-stack,
and proxy engines are kept intact:

- **Core I/O & framing:** `address`, `atomic`, `clock`, `copy_bidirectional/tests`, `copy_bidirectional_message`, `network_tasks`, `prepend_stream`, `resources`, `stream_reader`, `sync_adapter`, `util`, `uuid_util`.
- **TLS & REALITY:** `crypto/{crypto_handshake, tls_connection}`, `crypto/crypto_tls_stream/tests`, `crypto/tls_deframer/tests`, `reality/{reality_auth, reality_certificate, reality_certificate_verify, reality_config, reality_hello}`, `reality/tests/{reality_handshake, reality_post_quantum}`.
- **VLESS, Vision & XUDP:** `vless/tls_fuzzy_deframer/tests`, `vless/tls_handshake_util`, `vless/{vision_filter, vision_pad, vision_unpad, vless_response_stream, vless_util}`, `vless/vision_stream/{tests, tests/decisions}`, `xudp/{client_stream, message_stream}`, `xudp/frame/tests`.
- **Local Inbound, Routing & Userspace TUN:** `http_handler`, `mixed_handler`, `socks5_udp_relay`, `routing/ingress/peek`, `rules/{mod, domain, ip}`, `sniff/{http, udp, tests}`, `socket_util`, `ip_stack/{packet, tcp_conn, wake, tests}`, `ip_stack/driver/tests`, `tun/tcp_stack_direct/tests`, `tun/udp_handler`.

### 6.3 Rewritten & New Struct-Based Tests (Replacing YAML Fixtures)

Tests that previously relied on `serde_yaml` configs or `shoes-test-support`
were rewritten against `Profile`, `EngineConfig`, and `EngineHandle`:

- `engine/src/e2e_tests.rs`:
  - Full in-process `REALITY` + `xtls-rprx-vision` + `MixedProxy` E2E (HTTP/1.1 `CONNECT`, SOCKS5 `CONNECT`, SOCKS5 `UDP ASSOCIATE` multiplexed over XUDP `COMMAND_MUX` to multiple UDP targets, and `recheck_server` RTT probing).
  - REALITY cover-site fallback E2E: verifies that wrong `sid` / `pbk` / clock skew hands off to the cover TLS 1.3 server and transitions `EngineState` to `EngineStatus::Error` with `REALITY_AUTH_OR_CLOCK_ERROR`.
  - Plain TLS 1.3 (`kTLS`, `vision = false`) E2E: verifies rejection of unpinned self-signed certs, rejection of mismatched `pcs` SHA-256 pins, and full TCP + non-Vision XUDP (`COMMAND_MUX`) round-trips when `pcs` matches.
  - Userspace `smoltcp` TUN E2E over `UnixDatagram` socketpairs in both unframed (`packet_information = false`) and 4-byte `AF_INET`/`AF_INET6` framed (`packet_information = true`) modes, exercising port-53 DNS forwarding (`dns_proxy.rs`), XUDP datagram NAT, and `ServerEndpointResolver` pinned server IPs.
- `engine/src/vless/vless_client_handler.rs` (`xudp_without_vision_speaks_command_mux_and_roundtrips_datagrams`): directly tests the new non-Vision `COMMAND_MUX` + `VlessResponseStream` + `XudpClientStream` client path.
- `engine/src/rustls_config_util.rs`: tests rejection of `verify = false` without a pin and end-to-end TLS 1.3 handshake verification with matching vs mismatched SHA-256 `pcs` pins.
- `engine/src/config.rs`, `engine/src/dns_proxy.rs`, `engine/src/resolver.rs`: unit tests for `EngineConfig` lowering (`REALITY` vs `kTLS`), `TunResourceLimits`, DNS framing/forwarding, and `ServerEndpointResolver` live IP updates.
- `engine/tests/ipc_binary.rs`: spawns the compiled `vless-engine` child binary and verifies the `stdin`/`stdout` JSON-lines lifecycle (`Start` -> `State::Connected` -> `RecheckServer` -> `ServerCheck` -> `Stop` -> `State::Stopped`).

### 6.4 IPv6 Socket Tests Designated for macOS Execution (`PLAN.md` §8)

In an IPv6-disabled Linux build container (`EAFNOSUPPORT`, OS error `97`),
unmodified `shoes` (`cargo +1.100.0 test --lib`) recorded **2,723 passed,
19 failed, 13 ignored**. Fifteen of the 19 failures belonged to deleted modules
(`wireguard`, `ntp`, `rule_updater`, `splice`, `quic`, `tuic`, and `dns/hosts`).
The remaining **4 IPv6 socket tests** exercise kept code and require a host
with dual-stack IPv6 loopback (`::1`), such as macOS:

1. `socks_handler::tests::wildcard_udp_replies_use_control_local_address_through_wrappers`
2. `tcp::tcp_server::lifetime_tests::tcp_preparation_defers_ipv4_mapped_listener_transitions`
3. `tun::udp_tests::raw_fd_ipv6_udp_roundtrips`
4. `tun::udp_tests::framed_raw_fd_ipv6_udp_roundtrips`
