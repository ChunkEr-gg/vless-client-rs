package io.vless.client;

import android.app.AppComponentFactory;
import android.app.Service;
import android.content.Intent;
import java.lang.ref.WeakReference;

/** Lets instrumentation exercise callbacks on the VPN instance attached by Android. */
public final class DebugComponentFactory extends AppComponentFactory {
    static volatile WeakReference<TunnelService> vpn = new WeakReference<>(null);

    @Override
    public Service instantiateService(ClassLoader loader, String name, Intent intent)
            throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        Service service = super.instantiateService(loader, name, intent);
        if (service instanceof TunnelService)
            vpn = new WeakReference<>((TunnelService) service);
        return service;
    }
}
