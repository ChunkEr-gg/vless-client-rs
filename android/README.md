# Android client

The ARM64 APK starts a local HTTP and SOCKS5 proxy on port 2080. Use **Import links** to add VLESS links or a base64 VLESS subscription. Select
a saved profile and tap **Start proxy**, then configure the consuming app to use
the displayed address. Search by name, endpoint or security type. Long-press
a profile while disconnected to remove it. **Connection tests** measures HTTPS
first-byte latency, download speed, URL status or exit country through the active proxy. **Stop proxy** releases the listener. The proxy
runs for the lifetime of the activity. Device-wide VPN mode is pending.

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
