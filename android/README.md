# Android client

The ARM64 APK starts a local HTTP and SOCKS5 proxy on port 2080. Paste a VLESS
share link into the app, tap **Start proxy**, and configure the consuming app
to use the displayed address. **Stop proxy** releases the listener. The proxy
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
