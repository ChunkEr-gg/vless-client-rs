# `dist/` — macOS Packaging, `launchd` Activation, and Privileged Helper Lifecycle

This directory contains the macOS `.app` bundle manifests, `launchd` property
lists, and installation/uninstallation tooling for **VLESS Tray** (`io.vless-tray.app`)
and its privileged root helper daemon (`io.vless-tray.helper`).

## Contents

| File | Purpose |
|---|---|
| `Info.plist` | macOS bundle manifest for `VLESS Tray.app` (`LSUIElement = true`, `LSMinimumSystemVersion = 13.0`). |
| `io.vless-tray.helper.plist` | Development `LaunchDaemon` manifest installed to `/Library/LaunchDaemons/io.vless-tray.helper.plist` (`ProgramArguments = ["/Library/PrivilegedHelperTools/vless-tray-helper"]`). |
| `io.vless-tray.helper.smappservice.plist` | Embedded `SMAppService` `LaunchDaemon` manifest packaged at `Contents/Library/LaunchDaemons/io.vless-tray.helper.plist` (`BundleProgram = "Contents/Library/LaunchDaemons/vless-tray-helper"`). |
| `install-helper.sh` | Idempotent root installer for development/unsigned builds; writes `owner-uid`, stages the helper and plist atomically, and bootstraps `system/io.vless-tray.helper`. |
| `uninstall-helper.sh` | Root uninstaller; boots out `system/io.vless-tray.helper`, runs `vless-tray-helper --recover-only` if `helper-state.json` exists, and removes all root artifacts. |
| `package-app.sh` | Assembles `target/dist/VLESS Tray.app` from compiled `vless-tray`, `vless-engine`, and `vless-tray-helper` binaries. |

---

## 1. `.app` Bundle Layout

Running `./dist/package-app.sh` (after `cargo build --release`, or directly via
`./dist/package-app.sh --build`) produces `target/dist/VLESS Tray.app`:

```text
VLESS Tray.app/
└─ Contents/
   ├─ Info.plist                                  (CFBundleIdentifier: io.vless-tray.app, LSUIElement: true)
   ├─ MacOS/
   │  ├─ vless-tray                               (Menu-bar agent + `--settings` short-lived egui window)
   │  └─ vless-engine                             (Unprivileged VLESS/REALITY/kTLS + userspace TUN engine)
   ├─ Library/
   │  └─ LaunchDaemons/
   │     ├─ vless-tray-helper                     (Privileged root helper binary)
   │     └─ io.vless-tray.helper.plist            (SMAppService manifest using BundleProgram)
   └─ Resources/
      ├─ install-helper.sh                        (Development root installer)
      ├─ uninstall-helper.sh                      (Root uninstaller with state recovery)
      └─ io.vless-tray.helper.dev.plist           (Development /Library/LaunchDaemons manifest)
```

### Process Separation

- **`vless-tray`** runs as the logged-in desktop user (`LSUIElement = true`, no Dock icon). Settings UI runs in a short-lived child process (`vless-tray --settings`) so GPU/windowing memory returns to macOS immediately when closed.
- **`vless-engine`** runs as an unprivileged child process of `vless-tray`, reading its profile over `stdin` (never exposing VLESS UUIDs in `ps`) and exiting automatically on `stdin` EOF.
- **`vless-tray-helper`** runs as `root` under `launchd` (`system/io.vless-tray.helper`). It **never parses network packets**; it only creates a `utun` interface (passing the sole fd to `vless-engine` via `SCM_RIGHTS`), updates routing/DNS/system-proxy state from validated IPC commands, and restores everything when the engine's Unix socket disconnects.

---

## 2. `launchd` Socket Activation & Security Model

Both `io.vless-tray.helper.plist` and `io.vless-tray.helper.smappservice.plist`
configure on-demand socket activation in `launchd`:

### Socket Activation (`launch_activate_socket`)

1. `launchd` creates and listens on `/var/run/vless-tray.sock` (`SockFamily = "Unix"`, `SockType = "stream"`) under the `Sockets` key named **`Listeners`**.
2. While `vless-tray` is disconnected or quit, **no root helper process is running**.
3. When `vless-engine` connects to `/var/run/vless-tray.sock`, `launchd` spawns `vless-tray-helper`.
4. On startup on macOS, `vless-tray-helper` calls Apple's `libSystem` C API:
   ```c
   int launch_activate_socket(const char *name, int **fds, size_t *cnt);
   ```
   passing `name = "Listeners"` (corresponding to `<key>Listeners</key>` under `<key>Sockets</key>`, equivalent to the `LAUNCH_ACTIVATE_SOCKET` contract). `launchd` transfers ownership of the bound listening file descriptor(s) into `fds`, which `vless-tray-helper` wraps in a non-blocking `UnixListener` (taking care to `free()` the `fds` buffer allocated by `libSystem`).

### Why `SockPathMode` Is `438` (`0o666`)

> **Important `launchd.plist(5)` Pitfall:** XML Property List `<integer>` elements are parsed strictly in **base-10 decimal** by CoreFoundation. Writing `<integer>0666</integer>` in an XML plist sets permissions to decimal `666` (`0o1232` = `--w--wx-wT`), breaking client connections. Decimal **`438`** equals octal **`0666`** (`rw-rw-rw-`).

Because the `launchd` daemon runs as `root:wheel` in the `system` domain while `vless-engine` runs as the unprivileged desktop user, socket filesystem permissions allow local `connect(2)` (`0666`), and **caller authorization is enforced inside `vless-tray-helper` on every accepted connection**:

1. `vless-tray-helper` reads `/Library/Application Support/vless-tray/owner-uid` (`root:wheel`, mode `0600` inside a `0700` directory).
2. On every accepted `UnixStream`, `vless-tray-helper` calls `getpeereid(fd, &mut euid, &mut egid)` before reading a single byte.
3. Any peer whose kernel-verified `euid` does not match the numeric UID in `owner-uid` is immediately rejected and closed.

### Lifecycle Keys

- **`RunAtLoad = true`**: Starts `vless-tray-helper` once at boot (or `launchctl bootstrap`). If `/Library/Application Support/vless-tray/helper-state.json` is left over from a power loss or panic, the helper restores routes/DNS/proxies and deletes the journal, then exits `0` if no client session is active.
- **`KeepAlive = { SuccessfulExit = false }`**:
  - When `vless-tray-helper` tears down cleanly and exits with code `0`, `launchd` **does not** restart it — nothing runs as `root` while idle, and `launchd` resumes watching `/var/run/vless-tray.sock`.
  - If `vless-tray-helper` ever exits non-zero or dies from a signal, `launchd` immediately respawns it so recovery runs automatically.
- **`ThrottleInterval = 1`**: Reduces `launchd`'s default 10-second respawn throttle to 1 second so immediate socket activation right after a 2-second idle boot recovery exit is never delayed.
- **`ProcessType = "Adaptive"` & `AbandonProcessGroup = false`**: Participates in macOS QoS boosting during IPC transactions without lingering background child processes.

---

## 3. Development Install vs. `SMAppService` Signing Flow

### A. Development / Unsigned Install (`install-helper.sh`)

During local development or unsigned testing, `SMAppService` cannot register daemons without a Developer ID signature and team provisioning. Instead, install via `/Library/PrivilegedHelperTools` and `/Library/LaunchDaemons`:

```bash
# Build workspace release binaries and assemble "target/dist/VLESS Tray.app"
./dist/package-app.sh --build

# Option 1: Trigger from the app CLI (prompts via macOS admin dialog using osascript)
"./target/dist/VLESS Tray.app/Contents/MacOS/vless-tray" install-helper

# Option 2: Run the root installer directly from terminal (resolves $SUDO_UID automatically)
sudo ./dist/install-helper.sh \
  --uid "$(id -u)" \
  --helper "./target/release/vless-tray-helper" \
  --plist "./dist/io.vless-tray.helper.plist"
```

What `install-helper.sh` does:
1. Validates that the target UID is a base-10 integer `> 0` (rejecting UID `0` unless `--allow-root-uid` is explicitly supplied).
2. Runs `launchctl bootout system/io.vless-tray.helper` (idempotent) and clears any stale `/var/run/vless-tray.sock`.
3. Creates `/Library/Application Support/vless-tray` (`root:wheel`, `0700`) and atomically writes `/Library/Application Support/vless-tray/owner-uid` (`root:wheel`, `0600`).
4. Stages to temporary files and atomically `mv`s `/Library/PrivilegedHelperTools/vless-tray-helper` (`root:wheel`, `0755`) and `/Library/LaunchDaemons/io.vless-tray.helper.plist` (`root:wheel`, `0644`) — creating fresh Mach-O inodes to avoid Apple Silicon `SIGKILL (Code Signature Invalid)` vnode cache issues.
5. Enables and bootstraps `system/io.vless-tray.helper` via `launchctl bootstrap system`.

### B. Signed Distribution via `SMAppService` (macOS 13+)

`VLESS Tray.app` is already structured to match `SMAppService.daemon(plistName: "io.vless-tray.helper.plist")`:

- `Contents/Library/LaunchDaemons/vless-tray-helper` contains the helper executable.
- `Contents/Library/LaunchDaemons/io.vless-tray.helper.plist` uses `BundleProgram = "Contents/Library/LaunchDaemons/vless-tray-helper"` and `AssociatedBundleIdentifiers = ["io.vless-tray.app"]`.

To sign and distribute with Developer ID:

```bash
# Package and sign nested binaries inside-out with Hardened Runtime + secure timestamp
./dist/package-app.sh --build --codesign "Developer ID Application: Your Name (TEAMID)"

# Verify deep signature & notarization readiness
codesign --verify --deep --strict --verbose=2 "target/dist/VLESS Tray.app"
```

When transitioning the app installer from `install-helper.sh` to `SMAppService`:
1. Place `VLESS Tray.app` in `/Applications/VLESS Tray.app`.
2. Register `SMAppService.daemon(plistName: "io.vless-tray.helper.plist").register()` (if `.status == .requiresApproval`, prompt user to approve **VLESS Tray** under **System Settings → General → Login Items → Allow in the Background**).
3. Ensure `/Library/Application Support/vless-tray/owner-uid` is provisioned with the installing user's UID (or verified via code-signing requirement audit token `audit_token_t` alongside `owner-uid`).

---

## 4. Cleanup & Uninstall Guarantees

Every failure and teardown path converges to zero leftover network state:

| Scenario | Cleanup Mechanism |
|---|---|
| Normal Disconnect / Quit | `vless-engine` sends `Stop` or closes its Unix socket; `vless-tray-helper` restores from `helper-state.json`, deletes the journal, and exits `0`. |
| `vless-engine` or `vless-tray` crash / `kill -9` | The kernel closes the engine's copy of the `utun` fd (destroying the `utun` interface and its routes immediately) **and** closes the helper Unix socket; `vless-tray-helper` observes EOF, removes server/bypass routes, restores DNS & proxies, deletes `helper-state.json`, and exits `0`. |
| `vless-tray-helper` crash / `kill -9` | `KeepAlive = { SuccessfulExit = false }` causes `launchd` to respawn `vless-tray-helper` immediately; on startup it detects `helper-state.json` and restores everything. |
| Hard power-off / kernel panic | TUN DNS uses ephemeral `SystemConfiguration` dynamic store keys (`State:/Network/Service/.../DNS` and `Setup:/Network/Service/.../DNS` in `configd` RAM) that never touch persistent disk preferences; at next boot `RunAtLoad = true` launches `vless-tray-helper` to restore any persistent proxy/route state from `helper-state.json` and delete it. |
| Uninstall (`sudo ./dist/uninstall-helper.sh`) | Boots out `system/io.vless-tray.helper`, executes `/Library/PrivilegedHelperTools/vless-tray-helper --recover-only` whenever `helper-state.json` exists, and deletes `/Library/LaunchDaemons/io.vless-tray.helper.plist`, `/Library/PrivilegedHelperTools/vless-tray-helper`, `/var/run/vless-tray.sock`, and `/Library/Application Support/vless-tray`. |

User-space profiles and preferences in `~/Library/Application Support/vless-tray/` are owned by the desktop user (`0600`) and left untouched by `uninstall-helper.sh` unless removed manually by the user.
