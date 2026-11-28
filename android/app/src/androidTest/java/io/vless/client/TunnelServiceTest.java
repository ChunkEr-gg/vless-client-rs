package io.vless.client;

import android.app.Activity;
import android.app.Instrumentation;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.os.SystemClock;
import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import java.io.IOException;
import java.util.concurrent.TimeUnit;
import org.junit.Test;
import org.junit.runner.RunWith;
import static org.junit.Assert.*;

@RunWith(AndroidJUnit4.class)
public class TunnelServiceTest {
    private String shell(String command) throws IOException {
        Instrumentation inst = InstrumentationRegistry.getInstrumentation();
        try (java.io.InputStream in = new ParcelFileDescriptor.AutoCloseInputStream(
                     inst.getUiAutomation().executeShellCommand(command));
             java.util.Scanner scanner = new java.util.Scanner(in, "UTF-8").useDelimiter("\\A")) {
            return scanner.hasNext() ? scanner.next() : "";
        }
    }

    private void awaitVpn(String state, boolean interfacePresent) throws Exception {
        long until = SystemClock.elapsedRealtime() + 20000;
        String addresses;
        do {
            addresses = shell("ip -o addr show");
            if (TunnelService.state.equals(state) && addresses.contains("172.29.255.1/30") == interfacePresent)
                return;
            SystemClock.sleep(100);
        } while (SystemClock.elapsedRealtime() < until);
        fail("Expected " + state + ", actual " + TunnelService.state + ", interfaces " + addresses);
    }

    private void awaitServiceDestroyed(Context context) throws Exception {
        android.app.ActivityManager manager = context.getSystemService(android.app.ActivityManager.class);
        long until = SystemClock.elapsedRealtime() + 10000;
        do {
            // Android exposes this app's own services to the instrumentation UID.
            boolean running = manager.getRunningServices(Integer.MAX_VALUE).stream()
                .anyMatch(info -> TunnelService.class.getName().equals(info.service.getClassName()));
            if (!running && !shell("ps -A -w -o ARGS").contains("libvless_engine.so android-vpn "))
                return;
            SystemClock.sleep(100);
        } while (SystemClock.elapsedRealtime() < until);
        fail("VPN service or native engine remained after disconnect");
    }

    @Test public void destroyingConnectedServiceRemovesTunAndAllowsRestart() throws Exception {
        Instrumentation inst = InstrumentationRegistry.getInstrumentation();
        Context context = inst.getTargetContext();
        Activity activity = inst.startActivitySync(new Intent(context, ProxyActivity.class)
                                      .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
        Intent service = new Intent(context, TunnelService.class).putExtra("name", "Device fixture")
                             .putExtra("link", "vless://b831381d-6324-4d53-ad4f-8cda48b30811@10.0.2.2:19443"
                                               + "?security=tls&sni=fixture.test");
        SharedPreferences routing = context.getSharedPreferences("routing", Context.MODE_PRIVATE);
        String previous = routing.getString("dns", null);
        try {
            assertTrue(routing.edit().putString("dns", "10.20.0.53").commit());
            shell("appops set " + context.getPackageName() + " ACTIVATE_VPN allow");
            assertNull("VPN authorization", VpnService.prepare(context));
            for (int connection = 0; connection < 2; connection++) {
                context.startForegroundService(service);
                awaitVpn("Connected", true);
                assertTrue("Rust VPN child received private resolver",
                           java.util.Arrays.stream(shell("ps -A -w -o ARGS").split("\\n")).anyMatch(line ->
                               line.contains("libvless_engine.so android-vpn ") && line.trim().endsWith(" 10.20.0.53")));
                assertTrue("Android advertised private resolver",
                           shell("dumpsys connectivity").contains("10.20.0.53"));
                // Android binds the active VpnService. The disconnect action releases
                // the TUN, lets the system unbind and permits actual service destruction.
                assertNotNull(context.startService(new Intent(context, TunnelService.class).setAction("stop")));
                awaitVpn("Off", false);
                awaitServiceDestroyed(context);
            }
        } finally {
            if (!TunnelService.state.equals("Off"))
                context.startService(new Intent(context, TunnelService.class).setAction("stop"));
            routing.edit().putString("dns", previous).commit();
            shell("appops set " + context.getPackageName() + " ACTIVATE_VPN default");
            inst.runOnMainSync(activity::finish);
        }
    }

    @Test public void stopBeforeLaunchPreventsChildCreation() {
        TunnelService.Session session = new TunnelService.Session();
        session.cancel();
        assertThrows(IOException.class, () -> session.start(new ProcessBuilder("/system/bin/true")));
    }

    @Test public void stopAfterLaunchTerminatesChild() throws Exception {
        TunnelService.Session session = new TunnelService.Session();
        Process child = session.start(new ProcessBuilder("/system/bin/sleep", "60"));
        try {
            session.cancel();
            session.cancel();
            assertTrue(child.waitFor(5, TimeUnit.SECONDS));
        } finally {
            child.destroyForcibly();
        }
    }

    @Test public void dnsAcceptsNumericUnicastAddresses() {
        assertEquals("9.9.9.9", TunnelService.dnsAddress("9.9.9.9").getHostAddress());
        assertEquals(16, TunnelService.dnsAddress("2001:4860:4860::8888").getAddress().length);
        for (String invalid : new String[] {"resolver.example", "0.0.0.0", "127.0.0.1", "ff02::1"})
            assertThrows(IllegalArgumentException.class, () -> TunnelService.dnsAddress(invalid));
    }
}
