package io.vless.client;

import android.app.Activity;
import android.os.Bundle;
import android.text.InputType;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

public final class ProxyActivity extends Activity {
    private Process engine;
    private Button connect;
    private EditText profile;
    private TextView status;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        int pad = Math.round(20 * getResources().getDisplayMetrics().density);
        layout.setPadding(pad, pad, pad, pad);
        layout.setOnApplyWindowInsetsListener((view, insets) -> {
            view.setPadding(pad, pad + insets.getSystemWindowInsetTop(), pad,
                    pad + insets.getSystemWindowInsetBottom());
            return insets;
        });
        profile = new EditText(this);
        profile.setHint("VLESS share link");
        profile.setSingleLine(true);
        profile.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        connect = new Button(this);
        connect.setText("Start proxy");
        connect.setOnClickListener(v -> {
            if (engine == null) startProxy(); else stopProxy();
        });
        status = new TextView(this);
        status.setText("Disconnected");
        layout.addView(profile);
        layout.addView(connect);
        layout.addView(status);
        setContentView(layout);
    }

    private void startProxy() {
        String link = profile.getText().toString().trim();
        if (!link.startsWith("vless://") || link.length() > 65536 || link.contains("\n")) {
            profile.setError("Enter one VLESS share link");
            return;
        }
        File binary = new File(getApplicationInfo().nativeLibraryDir, "libvless_engine.so");
        try {
            Process child = new ProcessBuilder(binary.getPath(), "run", "--link", "-",
                    "--listen", "127.0.0.1:2080").redirectErrorStream(true).start();
            engine = child;
            connect.setText("Stop proxy");
            status.setText("Starting proxy…");
            new Thread(() -> supervise(child, link), "vless-proxy").start();
        } catch (Exception e) {
            status.setText("Could not launch the engine");
        }
    }

    private void supervise(Process child, String link) {
        try {
            try (OutputStream input = child.getOutputStream()) {
                input.write(link.getBytes(StandardCharsets.UTF_8));
            }
            try (BufferedReader log = new BufferedReader(new InputStreamReader(child.getInputStream()))) {
                String line;
                while ((line = log.readLine()) != null) {
                    if (line.contains("vless-engine listening on ")) {
                        runOnUiThread(() -> {
                            if (engine == child) status.setText("HTTP and SOCKS5 proxy at 127.0.0.1:2080");
                        });
                    }
                }
            }
            child.waitFor();
        } catch (Exception e) {
            child.destroyForcibly();
        } finally {
            runOnUiThread(() -> {
                if (engine == child) {
                    engine = null;
                    connect.setText("Start proxy");
                    status.setText("Proxy stopped. Check the profile and local port.");
                }
            });
        }
    }

    private void stopProxy() {
        if (engine != null) {
            engine.destroy();
            engine = null;
        }
        connect.setText("Start proxy");
        status.setText("Disconnected");
    }

    @Override protected void onDestroy() {
        stopProxy();
        super.onDestroy();
    }
}
