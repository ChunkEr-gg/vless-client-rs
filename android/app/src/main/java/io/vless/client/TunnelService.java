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
    private volatile Process child;
    private volatile boolean stopping;
    private Thread worker;

    private void publish(String value) {
        state = value;
        sendBroadcast(new Intent(CHANGED).setPackage(getPackageName()));
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent == null || "stop".equals(intent.getAction())) {
            stopTunnel();
            return START_NOT_STICKY;
        }
        if (worker != null)
            return START_NOT_STICKY;
        String link = intent.getStringExtra("link");
        profileName = intent.getStringExtra("name");
        if (link == null || profileName == null) {
            stopSelf();
            return START_NOT_STICKY;
        }
        NotificationManager manager = getSystemService(NotificationManager.class);
        manager.createNotificationChannel(
            new NotificationChannel("vpn", "VPN connection", NotificationManager.IMPORTANCE_LOW));
        PendingIntent disconnect =
            PendingIntent.getService(this, 1, new Intent(this, TunnelService.class).setAction("stop"),
                PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        startForeground(1,
            new Notification.Builder(this, "vpn")
                .setSmallIcon(android.R.drawable.ic_lock_lock)
                .setContentTitle("VLESS VPN")
                .setContentText(profileName)
                .setOngoing(true)
                .addAction(android.R.drawable.ic_delete, "Disconnect", disconnect)
                .build());
        publish("Starting");
        worker = new Thread(() -> runTunnel(link), "vless-vpn");
        worker.start();
        return START_NOT_STICKY;
    }

    private void runTunnel(String link) {
        Process process = null;
        try {
            Builder builder = new Builder()
                                  .setSession(profileName)
                                  .setMtu(1400)
                                  .addAddress("172.29.255.1", 30)
                                  .addAddress("fd73:726b::1", 126)
                                  .addRoute("0.0.0.0", 0)
                                  .addRoute("::", 0)
                                  .addDnsServer("1.1.1.1");
            // The engine runs under our UID. Exclude that UID to keep its server sockets on the underlying
            // network.
            builder.addDisallowedApplication(getPackageName());
            try (ParcelFileDescriptor tun = builder.establish()) {
                if (tun == null || stopping)
                    throw new IOException("VPN permission was revoked");
                String socket = "vless-" + UUID.randomUUID();
                File binary = new File(getApplicationInfo().nativeLibraryDir, "libvless_engine.so");
                process = new ProcessBuilder(binary.getPath(), "android-vpn", socket)
                              .redirectErrorStream(true)
                              .start();
                child = process;
                try (LocalSocket control = connect(socket, process)) {
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
                            if (!stopping && line.contains("TUN stack started on fd"))
                                publish("Connected");
                        }
                    }
                }
            }
        } catch (Exception error) {
            // Failure is reported through the service state below.
        } finally {
            if (process != null)
                process.destroyForcibly();
            child = null;
            publish(stopping ? "Off" : "Failed");
            stopSelf();
        }
    }

    private LocalSocket connect(String name, Process process) throws Exception {
        for (int i = 0; i < 100 && !stopping && process.isAlive(); i++) {
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
        stopping = true;
        Process running = child;
        if (running != null)
            running.destroy();
        if (worker == null)
            stopSelf();
    }
    @Override
    public void onRevoke() {
        stopTunnel();
    }
    @Override
    public void onDestroy() {
        stopTunnel();
        stopForeground(STOP_FOREGROUND_REMOVE);
        super.onDestroy();
    }
}
