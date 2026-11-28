package io.vless.client;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.net.LocalSocket;
import android.net.LocalSocketAddress;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

/** Owns the packet interface independently of the activity lifecycle. */
public final class TunnelService extends VpnService {
    static final String CHANGED = "io.vless.client.VPN_STATE";
    static volatile String state = "Off";
    static volatile String profileName = "";
    static final String DEFAULT_DNS = "1.1.1.1";
    // Serialize teardown with a new Service instance after Android destroys the old one.
    private static final java.util.concurrent.ExecutorService engines =
        java.util.concurrent.Executors.newSingleThreadExecutor(task -> new Thread(task, "vless-vpn"));
    private final android.os.Handler main = new android.os.Handler(android.os.Looper.getMainLooper());
    private Session active; // Main-thread owned, including every UI state transition.
    private int latestStartId;

    // Instrumentation observes the instance attached by Android without extending its lifetime.
    static volatile java.lang.ref.WeakReference<TunnelService> liveInstance = new java.lang.ref.WeakReference<>(null);

    @Override
    public void onCreate() {
        super.onCreate();
        liveInstance = new java.lang.ref.WeakReference<>(this);
    }

    static final class Session {
        volatile boolean cancelled;
        private Process child;

        synchronized Process start(ProcessBuilder command) throws IOException {
            if (cancelled) throw new IOException("VPN stopped");
            child = command.start();
            return child;
        }

        synchronized void cancel() {
            cancelled = true;
            if (child != null) child.destroyForcibly();
        }
    }

    static java.net.InetAddress dnsAddress(String value) {
        java.net.InetAddress ip = android.system.Os.inet_pton(
            value.contains(":") ? android.system.OsConstants.AF_INET6 : android.system.OsConstants.AF_INET, value);
        if (ip == null || ip.isAnyLocalAddress() || ip.isLoopbackAddress() || ip.isMulticastAddress()
                || ip.getHostAddress().equals("255.255.255.255"))
            throw new IllegalArgumentException("Invalid VPN DNS address");
        return ip;
    }

    private void publish(String value) {
        state = value;
        sendBroadcast(new Intent(CHANGED).setPackage(getPackageName()));
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        latestStartId = startId;
        if (intent == null || "stop".equals(intent.getAction())) {
            stopTunnel();
            return START_NOT_STICKY;
        }
        if (active != null)
            return START_NOT_STICKY;
        String link = intent.getStringExtra("link");
        String name = intent.getStringExtra("name");
        if (link == null || name == null) {
            stopSelf();
            return START_NOT_STICKY;
        }
        profileName = name;
        NotificationManager manager = getSystemService(NotificationManager.class);
        manager.createNotificationChannel(
            new NotificationChannel("vpn", "VPN connection", NotificationManager.IMPORTANCE_LOW));
        PendingIntent disconnect =
            PendingIntent.getService(this, 1, new Intent(this, TunnelService.class).setAction("stop"),
                PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        Intent openProfiles = new Intent(this, ProxyActivity.class)
                                  .addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_SINGLE_TOP);
        PendingIntent open = PendingIntent.getActivity(this, 0, openProfiles, PendingIntent.FLAG_IMMUTABLE);
        startForeground(1,
            new Notification.Builder(this, "vpn")
                .setSmallIcon(android.R.drawable.ic_lock_lock)
                .setContentTitle("VLESS VPN")
                .setContentText(profileName)
                .setContentIntent(open)
                .setOngoing(true)
                .addAction(android.R.drawable.ic_delete, "Disconnect", disconnect)
                .build());
        publish("Starting");
        Session session = new Session();
        active = session;
        engines.execute(() -> runTunnel(session, link, name));
        return START_NOT_STICKY;
    }

    private void runTunnel(Session session, String link, String name) {
        Process process = null;
        try {
            if (session.cancelled) return;
            Builder builder = new Builder()
                                  .setSession(name)
                                  .setMtu(1400)
                                  .addAddress("172.29.255.1", 30)
                                  .addAddress("fd73:726b::1", 126)
                                  .addRoute("0.0.0.0", 0)
                                  .addRoute("::", 0);
            android.content.SharedPreferences prefs = getSharedPreferences("routing", MODE_PRIVATE);
            String dns = prefs.getString("dns", "");
            java.net.InetAddress resolver = dnsAddress(dns.isEmpty() ? DEFAULT_DNS : dns);
            builder.addDnsServer(resolver);
            boolean inclusive = prefs.getBoolean("inclusive", false);
            if (!inclusive)
                builder.addDisallowedApplication(getPackageName());
            int installed = 0;
            for (String id : prefs.getStringSet(inclusive ? "included" : "excluded", java.util.Collections.emptySet())) {
                try {
                    if (inclusive)
                        builder.addAllowedApplication(id);
                    else
                        builder.addDisallowedApplication(id);
                    installed++;
                } catch (android.content.pm.PackageManager.NameNotFoundException ignored) {
                    // An app can be uninstalled between selection and connection.
                }
            }
            if (inclusive && installed == 0)
                throw new IOException("No selected VPN apps are installed");
            try (ParcelFileDescriptor tun = builder.establish()) {
                if (tun == null || session.cancelled)
                    throw new IOException("VPN permission was revoked");
                String socket = "vless-" + UUID.randomUUID();
                File binary = new File(getApplicationInfo().nativeLibraryDir, "libvless_engine.so");
                process = session.start(new ProcessBuilder(binary.getPath(), "android-vpn", socket, resolver.getHostAddress())
                                            .redirectErrorStream(true));
                try (LocalSocket control = connect(socket, process, session)) {
                    if (control.getPeerCredentials().getUid() != android.os.Process.myUid())
                        throw new IOException("Unexpected engine UID");
                    control.setFileDescriptorsForSend(new FileDescriptor[] {tun.getFileDescriptor()});
                    control.getOutputStream().write(new byte[] {0, 0, 0, 4, 'n', 'u', 'l', 'l'});
                    control.setFileDescriptorsForSend(null);
                    try (OutputStream input = process.getOutputStream()) {
                        input.write(link.getBytes(StandardCharsets.UTF_8));
                    }
                    try (BufferedReader output =
                             new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                        String line;
                        while ((line = output.readLine()) != null) {
                            if (line.contains("TUN stack started on fd"))
                                main.post(() -> {
                                    if (active == session && !session.cancelled) publish("Connected");
                                });
                        }
                    }
                }
            }
        } catch (Exception error) {
            // Failure is reported through the service state below.
        } finally {
            if (process != null) {
                process.destroyForcibly();
                try {
                    process.waitFor();
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                }
            }
            main.post(() -> {
                if (active != session) return;
                active = null;
                publish(session.cancelled ? "Off" : "Failed");
                stopSelfResult(latestStartId);
            });
        }
    }

    private LocalSocket connect(String name, Process process, Session session) throws Exception {
        for (int i = 0; i < 100 && !session.cancelled && process.isAlive(); i++) {
            LocalSocket socket = new LocalSocket();
            try {
                socket.connect(new LocalSocketAddress(name, LocalSocketAddress.Namespace.ABSTRACT));
                return socket;
            } catch (IOException error) {
                socket.close();
                Thread.sleep(50);
            }
        }
        throw new IOException("Engine did not open the VPN descriptor channel");
    }

    private void stopTunnel() {
        if (active == null) {
            stopSelf();
            return;
        }
        active.cancel();
        publish("Disconnecting");
    }

    @Override
    public void onRevoke() {
        main.post(this::stopTunnel);
    }

    @Override
    public void onDestroy() {
        if (liveInstance.get() == this) liveInstance.clear();
        if (active != null) {
            active.cancel();
            active = null;
            publish("Off");
        }
        stopForeground(STOP_FOREGROUND_REMOVE);
        super.onDestroy();
    }
}
