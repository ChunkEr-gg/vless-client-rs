package io.vless.client;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import java.io.IOException;
import java.util.concurrent.TimeUnit;
import org.junit.Test;
import org.junit.runner.RunWith;
import static org.junit.Assert.*;

@RunWith(AndroidJUnit4.class)
public class TunnelServiceTest {
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
