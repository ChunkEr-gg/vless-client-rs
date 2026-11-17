# vless-tray: phase 1 plan

Status: **draft for review**. Nothing in shoes has been deleted yet.

Sources read for this plan:

- cfal/shoes at `7680938b` (2026-11-16), about 220k lines of Rust.
- ChunkEr-gg/reality-ktls at `301844a2`: `README.md`, `STRIPPED.md`,
  `PORTING.md`, `tests/e2e/README.md`, `src/server/ktls.rs`,
  `src/server/vision/request.rs` and `src/protocol/reality/client_hello.rs`.
- Throne's feature list, as a UX reference only. No Throne code is used.

## 1. What is being built

`vless-tray` is a macOS menu-bar VPN client for one server, reality-ktls.

Each profile targets one of the server's two listener types:

- **REALITY**: VLESS + REALITY + `xtls-rprx-vision`. TCP uses command `0x01`.
  UDP uses Mux `0x03` carrying XUDP.
- **kTLS**: VLESS over plain TLS 1.3 (rustls), flow empty. TCP uses `0x01`.
  UDP uses Mux `0x03` carrying XUDP, the same as REALITY.

There are three modes, one at a time: Off, System proxy, and TUN.

The goals are low impact on the Mac (small, quiet when idle, nothing that
parses network traffic runs as root, nothing left behind after quitting) and
full compatibility with the server.

## 2. What I verified in the code, and what it changes

| Finding | Effect on the plan |
|---|---|
| shoes' Vision UDP path, `setup_vision_vless_udp_bidirectional`, sends Mux `0x03` with the Vision flow addon and wraps the stream in `XudpClientStream`. Its outbound cap is `8192 - 666 = 7526` bytes, so larger datagrams are dropped. | This matches the server and stock Xray. Keep it unchanged. |
| shoes has **no XUDP path without Vision**. A non-Vision VLESS client sends plain VLESS UDP (`0x02`, `write_vless_udp_header`). | For kTLS profiles, add about 30 lines: a VLESS header with no addon and command `0x03`, then `VlessResponseStream`, then the same `XudpClientStream`. Then delete the plain `0x02` client path, so there is only one UDP implementation. I checked that reality-ktls's kTLS listener accepts `Command::Mux` with flow none (`src/server/ktls.rs:311`). |
| Vision + REALITY goes through `RealityClientHandler::new_vision_vless` in `src/reality/reality_client_handler.rs`. Vision + plain TLS goes through `TlsClientHandler::new_vision_vless` in `src/tls_client_handler.rs`. | REALITY profiles use the REALITY handler's Vision variant. kTLS profiles use `TlsClientHandler::new` with an inner VLESS handler that has no Vision. The Vision variant of `TlsClientHandler` is not used. I will keep it only if a kept test needs it. |
| shoes' REALITY client depends on a **patched rustls fork** (`cfal/rustls` at `f1a23c18`, pinned with `[patch.crates-io]`, `rustls = "=0.23.46"`). | The fork has to stay. It becomes the main pinned git dependency of the engine. Section 9 has the full list of git pins. |
| The REALITY client offers X25519MLKEM768 and X25519. The reality-ktls server accepts X25519, P-256 and X25519MLKEM768 (`client_hello.rs:37`). | Compatible. ML-DSA-65 server authentication (`reality_mldsa.rs`) is not used by the server, so it is deleted. |
| `decode_short_id` pads short IDs on the right with zeros, up to 16 hex digits. | This is compatible with Xray's `sid` handling. |
| On macOS, the TUN stack accepts a raw fd (`TunServerConfig::raw_fd`) with `packet_information(true)`. That mode handles the 4-byte address-family header that utun puts on each packet (`tcp_stack_direct.rs:982`). | This is exactly what the helper's fd passing needs. shoes' README lists TUN for Linux, Android and iOS only, so the macOS TUN path is new ground. It gets its own tests in phase 3. |
| `bind_interface` is implemented for Linux only. On macOS it reaches `panic!("Could not bind to device, unsupported platform.")` (`socket_util.rs:215`). | Add `IP_BOUND_IF` / `IPV6_BOUND_IF` using socket2's `bind_device_by_index_v4/v6`, which call those options on macOS. Apply it through `socket_policy::apply`, which is already called on every outbound socket. |
| The TLS client verifies certificates against `webpki-roots` (Mozilla's bundle), not the macOS keychain. Certificate pinning exists (`ServerFingerprintVerifier`, SHA-256 of the leaf certificate). | Pinning is kept as it is. For "real certificate" profiles, the brief says to verify against **system** roots, so I'll use `rustls-platform-verifier` (Security.framework) on macOS. The insecure verifier (`get_disabled_verifier`) is deleted. |
| One TUN UDP flow is one `XudpClientStream`, which is one new TCP+TLS connection. This is also what stock Xray does without Mux. | DNS in TUN mode would cost a full REALITY handshake for every lookup, because each query comes from a new source port. The DNS design in section 5.4 avoids this. |

Nothing I found makes any of your decisions unworkable.

## 3. Workspace layout

```text
vless-client-rs/
├─ Cargo.toml            workspace
├─ LICENSE               shoes' MIT licence, unchanged
├─ NOTICE                credits shoes (and the rustls / smoltcp forks)
├─ STRIPPED.md           what was removed from shoes, and why
├─ engine/               lib `vless_engine` (stripped shoes) + bin `vless-engine`
├─ ipc/                  shared types: profiles, the vless:// parser,
│                        app<->engine and engine<->helper messages, SCM_RIGHTS helpers
├─ helper/               bin `vless-tray-helper` (root, launchd)
├─ app/                  bin `vless-tray` (menu bar) + `vless-tray --settings` (window)
└─ dist/                 launchd plist, install/uninstall scripts, .app bundle layout
```

The `vless://` parser lives in `ipc`, because the CLI, the app and the engine
all need it, and the app should not link the whole engine. New code is MIT, to
match shoes. Say if you want something else.

## 4. Processes and privilege

```text
 user                                              root
 ┌─────────────┐ spawn, stdin/stdout ┌──────────────┐  Unix socket  ┌───────────────────┐
 │ vless-tray  │────────────────────▶│ vless-engine │──────────────▶│ vless-tray-helper │
 │ (menu bar)  │ JSON lines          │ (stripped    │ fixed commands│ (launchd daemon)  │
 └─────┬───────┘                     │  shoes)      │◀── utun fd ───│                   │
       │ spawn on demand             └──────────────┘  SCM_RIGHTS   └───────────────────┘
 ┌─────▼───────────────┐
 │ vless-tray --settings│  egui window; exits when closed
 └─────────────────────┘
```

- **The engine is a child process of the app**, not a thread inside it.
  - If the engine crashes, the UI survives and can show the error.
  - The engine reads its profile from stdin, so the UUID never appears in
    `ps`.
  - It exits when stdin reaches EOF, which happens if the app dies.
- **The engine owns the helper session.** It connects to the helper's socket
  and asks for TUN or system proxy. In TUN mode it receives the utun fd, then
  keeps the connection open for as long as the mode is active.
  - When that connection closes for any reason (disconnect, quit, engine
    crash, `kill -9`), the kernel closes the socket and the helper restores
    everything. The brief's cleanup cases all reduce to that one event.
- **The helper never parses network traffic.** It accepts only these
  commands, as serde-decoded enums with validated fields:
  - `StartTun`
  - `StartSystemProxy`
  - `UpdateServerRoute` (for network changes)
  - `Stop`
  - `Status`

  The helper:
  - checks every connection with `getpeereid`: the caller's uid must equal
    the installed user's uid, which is stored in a root-owned file at install
    time
  - runs only fixed binaries (`/sbin/route`, `/sbin/ifconfig`,
    `/usr/sbin/networksetup`) with argv and no shell, or calls
    SystemConfiguration directly
  - checks that interface names, service IDs and CIDRs are well-formed before
    using them
- **The helper keeps no copy of the utun fd** after passing it. The interface
  then disappears when the engine's last copy closes, and any route that
  points at it disappears with it. The routes the helper must remove itself
  are the server host route and the bypass routes through the physical
  gateway.
- **launchd socket activation.** The plist declares the socket, so the helper
  is started only when the engine connects. It exits after teardown, so
  nothing runs as root while the client is off.
  - `RunAtLoad` makes it run once at boot to restore any leftover state.
  - `KeepAlive = {SuccessfulExit = false}` restarts it if it crashes.
- **Install for development:** `vless-tray install-helper` asks for an admin
  password once (`osascript … with administrator privileges`). It copies the
  helper to `/Library/PrivilegedHelperTools/` and the plist to
  `/Library/LaunchDaemons/`.
  - The plist and binary are laid out the way `SMAppService.daemon(plistName:)`
    expects (`BundleProgram`, `Contents/Library/LaunchDaemons/`), so moving to
    it after signing only changes the installer.

## 5. Modes

### 5.1 State journal (shared by both modes)

Before it changes anything, the helper writes what it is about to change to
`/Library/Application Support/vless-tray/helper-state.json` (root, 0600). That
file holds:

- the original default gateways and interfaces (IPv4 and IPv6)
- the DNS settings it overrides
- each network service's proxy settings
- the routes it added

On teardown it restores from the journal and deletes the file. At its next
start, if the file is still there, it restores and deletes it first.

### 5.2 TUN

1. **Resolve the server.** The engine resolves the server's hostname through
   the normal system resolver, before anything changes. It sends the IP
   addresses to the helper in `StartTun`.
2. **Bring up the interface.** The helper creates a utun through the
   `com.apple.net.utun_control` kernel control socket. It assigns
   `198.18.0.1/30` and an fd00::/8 IPv6 address.
3. **Install routes.**
   - `0.0.0.0/1`, `128.0.0.0/1`, `::/1` and `8000::/1` go to the utun. Using
     two halves instead of replacing the default route keeps the original
     default intact for the bypass routes.
   - A host route for each server IP goes through the original gateway.
   - Bypass CIDRs go through the original gateway: `10/8`, `172.16/12`,
     `192.168/16`, `169.254/16`, `224/4`, IPv6 ULA and link-local, and the
     user's own CIDRs.
4. **Pass the fd.** The helper sends the utun fd and the physical interface
   index over `SCM_RIGHTS`.
5. **Bind outbound sockets.** The engine binds every outbound socket to the
   physical interface with `IP_BOUND_IF`, as a second guard against loops.
6. **Capture IPv6 too.** IPv6 is routed into the tunnel even if the server
   has no IPv6 egress, so it cannot leak. In that case IPv6 connections fail
   quickly and Happy Eyeballs falls back to IPv4. This is my call.
7. **Domain bypass entries.** In TUN mode, a domain in the bypass list is
   matched on the TLS SNI or HTTP Host (shoes' `sniff` module). A match is
   dialled directly, bound to the physical interface. CIDR entries are handled
   by routes alone.

### 5.3 System proxy

- The engine listens on `127.0.0.1:<port>` with shoes' mixed (SOCKS5 + HTTP)
  listener, including SOCKS5 UDP ASSOCIATE.
- For every **enabled** network service, the helper saves, then sets, the
  HTTP, HTTPS and SOCKS proxies to that port.
- Each service's `ExceptionsList` gets the bypass list plus `*.local`,
  `169.254/16` and the private ranges.
- Only applications that honour the system proxy are captured, and UDP only
  through SOCKS-aware applications. That is inherent to this mode.
- Note: any local process can use a listener on 127.0.0.1. That is normal for
  this kind of client, and I'm leaving it unauthenticated.

### 5.4 DNS in TUN mode, with no leaks

- The helper sets the system resolver to the configured resolver address
  (default `1.1.1.1`).
  - It writes this as a high-order `State:/Network/Service/…/DNS` entry in the
    dynamic store, not the persistent preferences, so even a hard power-off
    leaves no DNS setting behind.
  - That address is inside the tunnel's routes.
- The engine intercepts UDP and TCP port 53 to that address. Instead of
  opening one XUDP connection per query, it forwards every query over **one
  long-lived XUDP association** to `resolver:53`.
  - It rewrites DNS IDs to keep concurrent queries apart.
  - It reconnects on demand.
  - On the wire this is still "UDP over XUDP to the resolver", as the brief
    asks, but a lookup costs one round trip instead of a new REALITY
    handshake.
  - This replaces shoes' hickory-based DNS stack, so hickory, DoH, DoT and
    fake-IP are all deleted.
- **The server's own hostname** is never resolved through the tunnel. The
  engine resolves it before TUN comes up. After a network change, the engine
  sends one DNS query bound to the physical interface, to the original DNS
  servers recorded in the journal.

### 5.5 Sleep, wake and network changes (phase 6)

- The helper watches the default route through a `PF_ROUTE` socket, which is
  cheap when idle.
- When the gateway or interface changes, it moves the server host route and
  the bypass routes to the new gateway, and tells the engine the new
  interface index.
- The engine re-binds new sockets to the new interface and lets old flows
  fail. shoes dials one VLESS connection per flow, so "reconnecting" means new
  flows dial fresh.
- The app watches `NSWorkspace` wake notifications and asks the engine to
  re-resolve the server and check it.

### 5.6 Clock skew

- A REALITY handshake that the server does not authenticate is handed to the
  cover site. The client then sees a certificate it cannot verify.
- From the client side, a clock that is too far off looks the same as a wrong
  `pbk`, `sid` or `sni`.
- The engine reports this failure as: "The server did not accept this client.
  Check pbk, sid and sni, and that the Mac's clock is correct (within the
  server's maxTimeDiffMs)." There is no NTP module.

## 6. Keep and delete list for shoes

Everything in the delete column is removed from the tree, not feature-gated.
`STRIPPED.md` will record each item, in the same style as reality-ktls's.

### Kept, trimmed where noted

| Area | Files | Trimming |
|---|---|---|
| Core I/O | `address`, `async_stream`, `atomic`, `buf_reader`, `copy_bidirectional{,_message}`, `prepend_stream`, `stream_reader`, `slide_buffer`, `sync_adapter`, `util`, `uuid_util`, `thread_util`, `option_util`, `resources`, `network_tasks`, `listener_tasks` | Remove helpers that only deleted code used |
| TLS plumbing | `crypto/*`, `rustls_config_util`, `rustls_connection_util` | Client side only: drop the server config, ACME and the insecure verifier; add `rustls-platform-verifier` |
| REALITY client | `reality/{reality_auth, reality_certificate, reality_certificate_verify, reality_cipher_suite, reality_client, reality_client_handler, reality_config, reality_hello, reality_rustls_adapter}` | Drop the ML-DSA option |
| REALITY server | `reality_server`, `reality_server_handler`, `reality_target_flight` | Kept only as `#[cfg(test)]` counterparties for the existing handshake tests, the way reality-ktls kept its client pieces. Not in the binary. |
| VLESS / Vision | `vless/{vision_filter, vision_pad, vision_stream, vision_transport, vision_unpad, tls_fuzzy_deframer, tls_handshake_util, vless_client_handler, vless_response_stream, vless_util}` | Remove the encryption branches and the plain UDP (`0x02`) client path; add XUDP without Vision |
| XUDP | `xudp/{frame, client_stream}` | `message_stream` (the server side) is kept only if a kept test needs it |
| TLS client | `tls_client_handler` | Keep only the `Default(VLESS)` inner handler; remove the shadow-tls, websocket and xhttp branches |
| TCP outbound | `tcp/{tcp_handler, socket_connector{,_impl}, proxy_connector{,_impl}, chain_builder, tcp_client_handler_factory}` | TCP only (no QUIC or port hopping), single hop, two handler shapes |
| Local inbound | `tcp/{tcp_server, tcp_server_handler_factory, ingress}`, `socks_handler`, `http_handler`, `mixed_handler`, `socks5_udp_relay`, `udp_fragments`, `routing/{udp_router, udp_relay, ingress}` | HTTP/1.1 only (no `http2`); no UoT |
| Routing | `client_proxy_selector`, `client_proxy_chain`, `rules/{mod, compile, domain, ip, config}`, `sniff` | Exactly two outcomes, direct or proxy, from the bypass list. No groups, URL tests or control catalog. |
| TUN | `tun/{mod, tun_server, tcp_stack_direct, udp_handler, udp_manager}`, `ip_stack/*` | Drop Linux device creation, offload and retained devices, and the FFI `platform` module |
| Sockets | `socket_util`, `socket_policy` | Add the macOS `IP_BOUND_IF` policy; drop the Linux mark policy |
| Misc | `resolver` (native only), `clock` (time provider without the NTP offset), `logging` (slim) | |
| Config | `config/*` | **Replaced** by one small typed `EngineConfig` built from a profile. The app never needs YAML ("custom JSON configs" is out of scope). Kept tests that build fixtures with YAML switch to that struct. |
| CLI | `cli.rs` | Replaced by `vless-engine run --link 'vless://…' [--listen 127.0.0.1:2080] [--tun-fd N]` |

### Deleted

| Category | Items |
|---|---|
| Protocols | `vmess`, `shadowsocks`, `trojan_handler`, `snell`, `hysteria2_server`, `tuic_server`, `anytls`, `naiveproxy`, `wireguard`, `shadow_tls`, `sudoku_mask`, `uot`, `vless/encryption`, `vless_server_handler` (unless a kept test needs it) |
| Transports | `websocket`, `xhttp`, `h2mux`, `http2`, `quic_client`, `quic_endpoint`, `quic_server`, `quic_stream`, `splice` |
| Server-side | `tls_server_handler`, `port_forward_handler`, `certificates` (ACME, file rotation) |
| Control and rules | `clash_api`, `control/*`, `rule_set`, `rule_updater`, `file_watcher`, `process.rs` (the multi-config supervisor) |
| DNS | `dns/*` (hickory, DoH/DoT, fake-IP, tendns, hosts), `cli/tendns_generator`. Replaced by the forwarder in section 5.4. |
| Platform | `desktop/linux`, `ffi`, `tun/{offload, retained, platform}`, Android and iOS code, `ntp` |
| Repository material | `docs/` (the website), `examples/`, `benches/` for removed code, `Dockerfile`, `Cross.toml`, `cbindgen.toml`, `include/`, `scripts/` for removed features, `CHANGELOG.md` |
| Integration tests | `vless_encryption_interop`, `xhttp_interop`, `ws_early_data`, `rule_allocation`, `rule_properties`, `matcher_invariants`, `retention_allocation`, the Linux `privileged` suite. The other suites (`integration`, `process_contract`, `stress`, `external_network`) are kept only for cases that exercise what remains. `reality_interop` (against Xray) is kept and adapted. |

Expected dependencies to drop: `quinn`, `quinn-proto`, `h2`, `h3`, `h3-quinn`,
`hyper*`, `hyper-tungstenite`, `hickory-resolver`, `instant-acme`, `rcgen`,
`gotatun`, `rtnetlink`, `jni`, `android_logger`, `ndk-sys`, `rust-argon2`,
`blake2`, `blake3`, `md-5`, `shake`, `sntpc`, `tendns`, `prost`, `ruzstd`,
`flate2`, `yaml-rust2`, `serde_yaml`, `notify`, `memory-stats`, `regex*`,
`aho-corasick` (if domain matching does not need it), `mime_guess`,
`x509-parser`, `tikv-jemallocator`.

I'm proposing to drop jemalloc. The system allocator keeps a lower idle RSS,
which fits the low-impact goal, and phase 6 measures the difference.

A note on the test rule: the brief says to keep every test of what remains.
Some existing tests exercise kept code only through YAML configs or deleted
inbounds. Those tests will be rewritten against the new entry points, not
deleted. `STRIPPED.md` will list every test that was rewritten.

## 7. The app

- **Menu bar:** `tray-icon` + `muda`, on a `winit` event loop with
  `ControlFlow::Wait`, so the process uses no CPU when nothing happens. The
  menu has:
  - status
  - Connect / Disconnect
  - a mode switch (Off / System proxy / TUN)
  - a profile picker
  - Settings…
  - Quit
- **Settings window: egui (eframe), as a separate short-lived process**
  (`vless-tray --settings`).
  - The menu-bar process never loads a renderer or GPU context, so it stays
    at a few MB.
  - The window's memory is fully returned to the system when it closes.
  - This also avoids winit's limit of one event loop per process, which would
    otherwise get in the way of creating and destroying the window on demand.
  - egui repaints only on input when it is idle.
  - Alternatives I rejected: Slint looks more native, but its licence choice
    (GPL or royalty-free with attribution) and DSL add friction. iced is
    heavier. Pure AppKit through `objc2` looks best, but needs several times
    more code. Neither option embeds a webview.
- **Window contents:**
  - profiles: list, add, import from clipboard, edit, delete
  - the bypass list
  - the DNS resolver
  - a log view, which tails the engine's log through the app
- **Storage:** profiles and settings live in
  `~/Library/Application Support/vless-tray/` as JSON with mode 0600. Files
  are written atomically (temp file, `fsync`, rename), with the mode set on
  creation.
- **Import validation**, with clear errors:
  - The UUID must be valid. `encryption` must be `none`. `type` must be `tcp`.
  - REALITY: `pbk` must be 32 bytes of base64url, `sid` at most 16 hex
    digits, and `sni` must be a DNS name. `flow` must be `xtls-rprx-vision`.
  - kTLS: `sni` must be a DNS name. `alpn` defaults to `http/1.1`. A pinned
    SHA-256 is optional; with a self-signed certificate, the connection fails
    unless it is set.
  - `security=tls` with `flow=xtls-rprx-vision` gets a warning: "this server
    treats Vision on the TLS port as a probe; the connection will look dead".
  - An unsupported `security`, `type` or transport is an error.
  - `fp` is stored but has no effect until the browser-profile phase.
  - `spx` is ignored.

## 8. How each phase will be verified

| Phase | Verification here (Linux) | Needs a Mac |
|---|---|---|
| 2: engine CLI | reality-ktls built and run natively, with both listeners, a local nginx as the cover and fallback, and `blockPrivate: false` for loopback targets. Checks: `curl` through SOCKS5 and HTTP to local targets; DNS through SOCKS5 UDP ASSOCIATE (XUDP) to a local DNS responder; large-file sha256; Vision-on-kTLS reaching the fallback; wrong sid or pbk reported clearly. Then the same checks with the stock Xray client side by side (the release download is reachable from here). Plus `cargo test` for everything kept. | No |
| 3: TUN | The helper state machine against a mock system backend; IPC and `SCM_RIGHTS` framing; the TUN stack fed from a Linux `socketpair` with a 4-byte AF header | **Yes:** utun, routes, DNS, cleanup after `kill -9` |
| 4: system proxy | Journal and restore logic against the mock backend | **Yes:** `networksetup` / SCPreferences |
| 5: app | Link parser and profile store unit tests | **Yes:** menu bar and window |
| 6: hardening | | **Yes:** sleep and wake, Wi-Fi switch, idle CPU and RSS |

**Baseline (unmodified shoes, `cargo +1.100.0 test --lib`, run in this
sandbox):** 2723 passed, 19 failed, 13 ignored. Every failing test needs IPv6
sockets, which this sandbox does not have (`EAFNOSUPPORT`, os error 97). Four
of them cover code that is kept, and they will be run on a Mac:

- `socks_handler::tests::wildcard_udp_replies_use_control_local_address_through_wrappers`
- `tcp::tcp_server::lifetime_tests::tcp_preparation_defers_ipv4_mapped_listener_transitions`
- `tun::udp_tests::raw_fd_ipv6_udp_roundtrips`
- `tun::udp_tests::framed_raw_fd_ipv6_udp_roundtrips`

The other 15 cover code that is being deleted: wireguard, ntp, rule_updater,
splice, quic, tuic and dns/hosts.

**This session has no Mac.** The cloud container is Linux and no computer of
yours is attached. I can type-check the Mac-only crates here, but I can't run
them. See question 1 below.

## 9. Risks

- **Pinned git forks:** `cfal/rustls` (REALITY), `cfal/smoltcp` (a
  retransmission fix) and `nix` (an upstream commit). Updates follow shoes'
  pins. `NOTICE` will record them.
- **shoes needs Rust 1.99.1 or newer.** I'll pin the toolchain in
  `rust-toolchain.toml`. 1.100.0 is installed here.
- **TUN on macOS is not tested upstream** (shoes lists Linux, Android and iOS).
  Phase 3 owns that risk.
- **Fingerprint:** the kTLS ClientHello is plain rustls until the
  browser-profile phase, so `fp=chrome` is cosmetic until then.

## 10. Questions for you

Asked in the chat message that goes with this document. Your answers will be
recorded here.
