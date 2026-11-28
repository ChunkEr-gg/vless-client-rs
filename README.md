# VLESS clients for reality-ktls

Version tags produce signed Android, iOS and macOS packages through the [distribution workflow](#distribution-builds). The table lists development builds from individual platform workflows.

| Platform | Artifact | How to open it |
| --- | --- | --- |
| macOS | [VLESS-Profiles-macOS](https://github.com/ChunkEr-gg/vless-client-rs/actions/workflows/desktop-profiles.yml) | Extract the download and open `VLESS Profiles.app` from the packaged ZIP. The app is ad hoc signed. |
| Windows | [VLESS-Profiles-Windows](https://github.com/ChunkEr-gg/vless-client-rs/actions/workflows/desktop-profiles.yml) | Extract the packaged ZIP to a folder and launch `vless-desktop.exe`. Keep `reality-sing-box.exe` beside it. |
| Android | [vless-client-android-arm64](https://github.com/ChunkEr-gg/vless-client-rs/actions/workflows/android-client.yml) | Extract and install the debug APK on an ARM64-compatible device. |
| iPhone | [VlessClient-iPhone-unsigned](https://github.com/ChunkEr-gg/vless-client-rs/actions/workflows/ios-client.yml) | Extract the device archive. Installation requires Apple signing and provisioning for both the app and its packet tunnel extension. |
| iOS Simulator | [VlessClient-iOS-Simulator](https://github.com/ChunkEr-gg/vless-client-rs/actions/workflows/ios-client.yml) | Extract the simulator app on an Apple Silicon Mac. With an iPhone simulator booted, run `xcrun simctl install booted VlessClient.app`. Physical devices require a separately signed device build. |

## Build for a registered iPhone

On a Mac with Xcode, XcodeGen, and Rustup, set `VLESS_BUNDLE_IDENTIFIER` in
`ios/project.yml` to an identifier registered to your Apple Developer team.
The app uses that identifier and the packet tunnel extension adds `.tunnel`.
Enable the Network Extensions capability with Packet Tunnel for both explicit
App IDs. See [Apple's Network Extensions setup](https://developer.apple.com/documentation/xcode/configuring-network-extensions/).

```sh
xcodegen generate --spec ios/project.yml
open ios/VlessClient.xcodeproj
```

In **Signing & Capabilities**, select the same developer team and enable
automatic signing for `VlessClient` and `PacketTunnel`. Select your registered
iPhone as the run destination and run the `VlessClient` scheme. See
[Apple's device setup instructions](https://developer.apple.com/documentation/xcode/running-your-app-on-simulated-or-physical-devices).

## macOS menu-bar client

The repository also includes a privilege-separated menu-bar VPN client for
[`reality-ktls`](https://github.com/ChunkEr-gg/reality-ktls) servers.

- **Two profile types** matching `reality-ktls`'s two listeners:
  - **`REALITY`**: VLESS + REALITY (`X25519MLKEM768` / `X25519` + Ed25519 HMAC) + `xtls-rprx-vision`, UDP over XUDP (`0x03`).
  - **`kTLS`**: VLESS over plain TLS 1.3 (`rustls`), empty VLESS wire flow, UDP over XUDP (`0x03`), verified against the macOS System Keychain (`Security.framework`) or an optional `pcs` SHA-256 leaf certificate pin.
- **Three operating modes** (one active at a time): **`Off`**, **`System Proxy`**, and **`TUN`**.
- **Low-impact design**:
  - Nothing that parses network packets ever runs as `root`.
  - Nothing runs as `root` while disconnected (`launchd` on-demand socket activation).
  - No GPU or windowing context lives in the menu-bar agent; Settings runs as a short-lived child process (`vless-tray --settings`) whose memory returns to macOS immediately on close.
  - Zero leftover routes, DNS overrides, or system proxy settings after quitting, crashing, `kill -9`, or hard power-off.

The VLESS/REALITY/Vision/XUDP/TUN protocol engine (`engine/`) is derived and
stripped down from [`cfal/shoes`](https://github.com/cfal/shoes) at commit
`7680938b` (~220k lines reduced by >80%). See [`STRIPPED.md`](STRIPPED.md) for
the full audit of removed modules, dependencies, and tests.

---

## Desktop Profiles

The Profiles window from reality-ktls draft PR #9 includes searchable profiles,
link import, a live connection card and Ping, Speed, URL and Country tests
through the selected proxy. The macOS menu-bar client remains available.

For a local build, run `cargo build --release -p vless-desktop` and
`./desktop/desktop-core/build.sh` before launching `target/release/vless-desktop`.

## Windows SOCKS proxy

The Windows x64 workflow builds the `vless-proxy-windows-x64` artifact. Extract both
`vless-proxy.exe` and the included Xray 26.11.9 runtime into the same folder.
CI verifies the upstream archive digest and transfers a payload through the packaged binaries. To compile the launcher locally, run
`cargo build --locked --release -p vless-proxy`.

Copy a VLESS link to the clipboard, then run this command in PowerShell from the
directory containing both executables.

```powershell
Get-Clipboard -Raw | .\vless-proxy.exe .\xray.exe 1080
```

Configure your application to use SOCKS5 at `127.0.0.1:1080`. Use remote DNS
in applications that support it. Press Ctrl+C in the foreground console to stop.
The launcher sends the profile to Xray over its standard input. Windows system
proxy integration and VPN mode are still under development.

## Architecture

```text
 user (unprivileged)                                           root (launchd)
 ┌─────────────────────┐  stdin / stdout  ┌──────────────┐   /var/run/vless-tray.sock   ┌───────────────────┐
 │ vless-tray          │─────────────────▶│ vless-engine │─────────────────────────────▶│ vless-tray-helper │
 │ (menu bar, muda +   │  JSON lines      │ (stripped    │   5 fixed serde commands     │ (socket-activated │
 │  winit Wait loop)   │◀─────────────────│  shoes)      │◀──── utun fd (SCM_RIGHTS) ───│  LaunchDaemon)    │
 └─────────┬───────────┘                  └──────────────┘                              └───────────────────┘
           │ spawn on demand
 ┌─────────▼───────────┐
 │ vless-tray          │  short-lived eframe/egui window;
 │   --settings        │  exits & frees GPU memory on close
 └─────────────────────┘
```

### Workspace Layout

| Crate / Directory | Target(s) | Role |
|---|---|---|
| `ipc/` | lib `vless_ipc` | Shared `Profile` model, strict `vless://` URI parser/serializer, atomic `0600` config store, App↔Engine JSON-lines frames, Engine↔Helper length-prefixed frames, and `SCM_RIGHTS` file-descriptor passing. |
| `engine/` | lib `vless_engine`, bin `vless-engine` | Stripped `shoes` engine: REALITY + Vision, plain TLS 1.3 (`kTLS`) + Keychain/`pcs` verifier, unified XUDP (`0x03`), HTTP/1.1 + SOCKS5 mixed proxy, `smoltcp` userspace TUN stack, single-association XUDP port-53 DNS forwarder, and `IP_BOUND_IF` socket policy. |
| `helper/` | lib `vless_tray_helper`, bin `vless-tray-helper` | Privileged `launchd` daemon: `getpeereid(2)` caller UID check against `/Library/Application Support/vless-tray/owner-uid`, `utun` kernel control creation, atomic state journaling (`helper-state.json`), routing/DNS/`SystemConfiguration` mutations, and `PF_ROUTE` physical gateway monitoring. |
| `app/` | lib `vless_tray`, bin `vless-tray` | macOS menu-bar supervisor (`tray-icon` + `muda`), `NSWorkspace` wake observer, `eframe`/`egui` `--settings` UI, and `install-helper` privilege-elevation CLI. |
| `dist/` | Packaging & `launchd` assets | `Info.plist`, `io.vless-tray.helper.plist` (dev & `SMAppService` variants), `package-app.sh`, `install-helper.sh`, and `uninstall-helper.sh` (see [`dist/README.md`](dist/README.md)). |

### Process & Security Invariants

1. **Unprivileged packet engine (`vless-engine`)**: Spawned as a child of `vless-tray`. Receives its `Profile` over `stdin` JSON-lines so VLESS UUIDs never appear in `ps` / `argv`, and shuts down automatically on `stdin` EOF if the UI process terminates.
2. **Minimal root helper (`vless-tray-helper`)**: Never touches network payloads. Authenticates every Unix socket connection via `getpeereid(2)` against the installing desktop user's UID (`owner-uid`), accepts only `StartTun`, `StartSystemProxy`, `UpdateServerRoute`, `Stop`, and `Status`, validates all IPs, CIDRs, interface names, and service names, and executes system tools (`/sbin/route`, `/sbin/ifconfig`, `/usr/sbin/networksetup`) directly via `argv` without a shell.
3. **Single-owner `utun` descriptor**: After sending the `utun` fd to `vless-engine` over `SCM_RIGHTS`, the helper closes its own copy immediately. If `vless-engine` exits or receives `kill -9`, the kernel destroys the `utun` interface and closes the helper session socket, causing `vless-tray-helper` to restore routes, DNS, and proxies from `/Library/Application Support/vless-tray/helper-state.json` and exit `0`.

---

## Supported Server Profiles & Modes

### 1. `REALITY` Profile (`security=reality`)

Targets a `reality-ktls` listener with `"type": "reality"` (default):

```text
vless://11111111-1111-4111-8111-111111111111@vpn.example.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=B2eE9Deuok5C6DjgTz5T7T94AaUQixm-CCg2bz-NiTY&sid=0123456789abcdef&type=tcp#reality
```

- Requires `encryption=none`, `type=tcp`, `flow=xtls-rprx-vision`, a valid DNS `sni`, a 32-byte base64url `pbk`, and `sid` of `0..=16` hex digits (right-padded with zeros to 8 bytes, matching Xray).
- TCP uses VLESS command `0x01`; UDP uses Mux `0x03` carrying XUDP (max datagram payload `7526` bytes).
- If the server rejects authentication (wrong `pbk`, `sid`, `sni`, or Mac clock outside `reality.maxTimeDiffMs`) and falls back to the cover site, the engine surfaces:
  > `The server did not accept this client. Check pbk, sid and sni, and that the Mac's clock is correct (within the server's maxTimeDiffMs).`

### 2. `kTLS` Profile (`security=tls`)

Targets a `reality-ktls` listener with `"type": "ktls"`:

```text
# Public CA certificate (verified against macOS System Keychain via Security.framework):
vless://2b1d4c3e-5f60-4781-92a3-b4c5d6e7f809@vpn.example.com:8443?encryption=none&security=tls&sni=vpn.example.com&alpn=http%2F1.1&type=tcp#ktls

# Self-signed or pinned certificate (verified via SHA-256 leaf certificate pin `pcs`):
vless://2b1d4c3e-5f60-4781-92a3-b4c5d6e7f809@vpn.example.com:8443?encryption=none&security=tls&sni=vpn.example.com&alpn=http%2F1.1&pcs=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef&type=tcp#ktls-pinned
```

- Requires `encryption=none`, `type=tcp`, and a DNS `sni`. `alpn` defaults to `http/1.1` when omitted.
- Leave `flow` empty: `reality-ktls` treats `xtls-rprx-vision` on a `ktls` port as an active probe and forwards it to `fallback` (importing `security=tls` with `flow=xtls-rprx-vision` emits an explicit warning).
- Unverified TLS (`allowInsecure`) does not exist: a self-signed server certificate requires `pcs=<64-hex-sha256-of-leaf-der>`.

### 3. Operating Modes

| Mode | Behavior |
|---|---|
| **`Off`** | Engine stopped; helper idle (`0` root processes running); system network settings untouched. |
| **`System Proxy`** | `vless-engine` binds a local HTTP/1.1 + SOCKS5 (with `UDP ASSOCIATE`) listener on `127.0.0.1:<port>`; `vless-tray-helper` configures HTTP, HTTPS, and SOCKS proxies plus `ExceptionsList` (`*.local`, RFC1918/link-local ranges, and user bypass entries) on all enabled macOS network services. |
| **`TUN`** | Pre-resolves the server hostname before route changes; creates a `utun` interface (`198.18.0.1/30` + `fd00:198:18::1/128`, MTU `1400`); installs split routes (`0.0.0.0/1`, `128.0.0.0/1`, `::/1`, `8000::/1`) into `utun` while routing server IPs and private/custom bypass CIDRs via the physical gateway/interface; binds outbound sockets with `IP_BOUND_IF` / `IPV6_BOUND_IF`; sniffs TLS SNI / HTTP `Host` for domain bypass entries; overrides DNS ephemerally in the `SystemConfiguration` dynamic store (`State:/Network/Service/.../DNS` and `Setup:/Network/Service/.../DNS` in `configd` RAM) and forwards port-53 queries over a single long-lived XUDP association to the configured resolver (default `1.1.1.1`). |

---

## Building, Testing & Running on macOS

### Prerequisites

- **macOS 13.0 (Ventura) or newer** (`aarch64-apple-darwin` or `x86_64-apple-darwin`).
- **Rust `1.100.0`** (`rustup` automatically selects `1.100.0` with `clippy` and `rustfmt` from [`rust-toolchain.toml`](rust-toolchain.toml)).

### 1. Build & Run Tests

```bash
# Build all workspace binaries in release mode (vless-tray, vless-engine, vless-tray-helper)
cargo build --release --bins

# Run the full unit, integration, and in-process E2E test suite across all 4 crates
cargo test --workspace

# Lint all workspace targets
cargo clippy --workspace --all-targets
```

> **Note on IPv6 loopback tests:** On macOS (with `::1` enabled), all workspace tests—including the 4 dual-stack IPv6 socket tests noted in [`STRIPPED.md` §6.4](STRIPPED.md#64-ipv6-socket-tests-designated-for-macos-execution-planmd-8)—run natively.

### 2. Package `VLESS Tray.app`

Assemble `target/dist/VLESS Tray.app` (containing `Contents/MacOS/{vless-tray,vless-engine}`, `Contents/Library/LaunchDaemons/{vless-tray-helper,io.vless-tray.helper.plist}`, and `Contents/Resources/{install-helper.sh,uninstall-helper.sh}`):

```bash
# Compile release binaries and assemble target/dist/VLESS Tray.app
./dist/package-app.sh --build

# Optional: ad-hoc sign inside-out for local macOS testing
./dist/package-app.sh --build --codesign -

# Optional: sign with Developer ID (Hardened Runtime + timestamp)
./dist/package-app.sh --build --codesign "Developer ID Application: Your Name (TEAMID)"
```

### 3. Install the Privileged Helper (`io.vless-tray.helper`)

`System Proxy` and `TUN` modes require installing the socket-activated `launchd`
helper once. You can install it either via the macOS administrator password prompt
(`osascript`) or from the terminal with `sudo`:

```bash
# Option A: Prompt via macOS GUI administrator dialog
"./target/dist/VLESS Tray.app/Contents/MacOS/vless-tray" install-helper

# Option B: Install directly from terminal via sudo (records $(id -u) in owner-uid)
sudo ./dist/install-helper.sh \
  --uid "$(id -u)" \
  --helper "./target/release/vless-tray-helper" \
  --plist "./dist/io.vless-tray.helper.plist"
```

Verify `launchd` registered the socket-activated service:

```bash
sudo launchctl print system/io.vless-tray.helper
ls -l /var/run/vless-tray.sock
```

### 4. Run `VLESS Tray` & Test Modes

```bash
# Launch the menu-bar app bundle (LSUIElement = true, appears in macOS menu bar)
open "./target/dist/VLESS Tray.app"

# Or run the menu-bar binary directly in the foreground for terminal output
"./target/dist/VLESS Tray.app/Contents/MacOS/vless-tray"

# Open the short-lived egui Settings window directly (import vless:// links, edit bypasses/DNS, tail logs)
"./target/dist/VLESS Tray.app/Contents/MacOS/vless-tray" --settings
```

To test `vless-engine` standalone on a local port without installing the root
helper (`StandaloneProxy` / CLI mode):

```bash
# Run standalone local HTTP + SOCKS5 mixed proxy on 127.0.0.1:2080
./target/release/vless-engine run \
  --link 'vless://<uuid>@vpn.example.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&pbk=<pbk>&sid=<sid>&type=tcp#test' \
  --listen 127.0.0.1:2080

# Verify TCP through SOCKS5 and HTTP CONNECT in another terminal
curl -v -x socks5h://127.0.0.1:2080 https://cloudflare.com/cdn-cgi/trace
curl -v -x http://127.0.0.1:2080 https://cloudflare.com/cdn-cgi/trace
```

### 5. Configuration & Runtime File Locations

| Path | Owner / Mode | Purpose |
|---|---|---|
| `~/Library/Application Support/vless-tray/` | `<user>`, `0600` | Profiles, active mode, bypass list, and DNS resolver JSON (written atomically via temp file + `fsync` + `rename`). |
| `/Library/Application Support/vless-tray/owner-uid` | `root:wheel`, `0600` | Authorized desktop user UID verified via `getpeereid(2)` on every helper connection. |
| `/Library/Application Support/vless-tray/helper-state.json` | `root:wheel`, `0600` | Pre-mutation rollback journal (present only while `TUN` or `System Proxy` is active; restored and deleted on teardown or boot recovery). |
| `/Library/PrivilegedHelperTools/vless-tray-helper` | `root:wheel`, `0755` | Installed root helper executable (development layout). |
| `/Library/LaunchDaemons/io.vless-tray.helper.plist` | `root:wheel`, `0644` | `launchd` socket-activation manifest listening on `/var/run/vless-tray.sock`. |

### 6. Uninstall the Privileged Helper

To stop `io.vless-tray.helper`, automatically recover any active `helper-state.json`
journal (`--recover-only`), and remove all root-owned helper files and sockets:

```bash
sudo ./dist/uninstall-helper.sh
```

To also remove your user-space profiles and settings:

```bash
rm -rf "$HOME/Library/Application Support/vless-tray"
```

---

## License & Acknowledgements

Licensed under the [MIT License](LICENSE).

- [`cfal/shoes`](https://github.com/cfal/shoes) (`7680938b`, MIT) by Alex Lau — upstream source of `engine/`, together with its pinned [`cfal/rustls`](https://github.com/cfal/rustls) (`f1a23c18`) and [`cfal/smoltcp`](https://github.com/cfal/smoltcp) (`7ef43e49`) forks. See [`NOTICE`](NOTICE) and [`STRIPPED.md`](STRIPPED.md).
- [`ChunkEr-gg/reality-ktls`](https://github.com/ChunkEr-gg/reality-ktls) — target VLESS (`REALITY` + `kTLS`) server implementation.

### Distribution builds

Set the workspace package version to `MAJOR.MINOR.PATCH` and tag that commit
`vMAJOR.MINOR.PATCH`. Release versions increase monotonically. Android's
version code is `major × 1000000 + minor × 1000 + patch` (minor and patch
each below 1000). Retrying a tag produces the same version. Protect release
tags and restrict the GitHub Actions `release` environment to authorized tags.

The environment needs the following signing material. Base64 values encode
the original binary files. Store private material as GitHub environment secrets.

| Platform | Secrets | Environment variables (GitHub vars) |
| --- | --- | --- |
| Android | ANDROID_KEYSTORE_B64, ANDROID_STORE_PASSWORD, ANDROID_KEY_ALIAS, ANDROID_KEY_PASSWORD | |
| iOS | IOS_P12_B64, IOS_P12_PASSWORD, IOS_APP_PROFILE_B64, IOS_TUNNEL_PROFILE_B64 | APPLE_TEAM_ID, IOS_BUNDLE_ID |
| macOS | MACOS_P12_B64, MACOS_P12_PASSWORD, NOTARY_KEY_B64 | MACOS_IDENTITY, NOTARY_KEY_ID, NOTARY_ISSUER |

Use an Android distribution or Play upload key, an Apple Distribution identity
and two App Store provisioning profiles with Packet Tunnel capability (the
extension ID ends in `.tunnel`), and a Developer ID Application identity plus
an App Store Connect notarization API key. The signed workflow stages the APK,
AAB, IPA and stapled macOS ZIPs in a draft GitHub Release after quality checks.
Download the companion `provenance.sigstore.json` from the same draft and
verify each file against the release tag and its full commit SHA:

```sh
gh attestation verify "$FILE" --bundle provenance.sigstore.json -R ChunkEr-gg/vless-client-rs \
  --source-ref "refs/tags/$TAG" --source-digest "$COMMIT" --deny-self-hosted-runners \
  --signer-workflow ChunkEr-gg/vless-client-rs/.github/workflows/release.yml
```

Android PR CI builds a validation AAB with the runner's disposable signing
key. The distribution key stays in the release environment.
