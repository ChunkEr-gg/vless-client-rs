# Android client

The ARM64 APK starts a local HTTP and SOCKS5 proxy on port 2080. Use **Import links** to add VLESS links or a base64 VLESS subscription. Select
a saved profile and tap **Start proxy**, then configure the consuming app to use
the displayed address. Search by name, endpoint or security type. Long-press
a profile while disconnected to remove it. **Connection tests** measures HTTPS
first-byte latency, download speed, URL status or exit country through the active proxy. **Stop proxy** releases the listener. The proxy
runs for the lifetime of the activity.

For a device-wide connection, select a profile and tap **Connect VPN**.
Approve Android's VPN permission dialog. The foreground service routes IPv4,
IPv6 and DNS packets from other applications to the Rust TUN engine and keeps
running after the Profiles screen closes. Tap **Disconnect VPN** in the app
or **Disconnect** in its notification to release the VPN.

To build on Linux or macOS, install Android SDK 36, NDK r27d and JDK 17.
From the repository root run the following with ANDROID_NDK_HOME set to the NDK
directory.

```sh
rustup target add aarch64-linux-android
./android/build-engine.sh
(cd android && ./gradlew :app:assembleDebug)
```

The installable debug APK is at `android/app/build/outputs/apk/debug/app-debug.apk`.
The APK embeds the optimized engine in the native library directory so Android
can execute it directly. The app passes the share link through a private pipe.

Profile lists are encrypted with an app-scoped Android Keystore AES-GCM key.
Opening the app migrates existing profiles and their selected index in one
preferences transaction. A key or data error leaves the saved records in place.

**VPN DNS** accepts a numeric unicast IPv4 or IPv6 server. Changes apply on the
next connection. Blank uses 1.1.1.1 for compatibility. An unreachable custom
server causes DNS queries to fail. The app does not switch to another resolver.
