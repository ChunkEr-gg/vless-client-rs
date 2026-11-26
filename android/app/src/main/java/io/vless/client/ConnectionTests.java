package io.vless.client;

import android.app.Activity;
import android.app.AlertDialog;
import android.view.View;
import android.widget.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import javax.net.ssl.HttpsURLConnection;

final class ConnectionTests {
    private static final String TRACE = "https://www.cloudflare.com/cdn-cgi/trace";
    private static final String DOWNLOAD = "https://speed.cloudflare.com/__down?bytes=5000000";
    private static final String[] TABS = {"Ping", "Speed", "URL", "Country"};
    private static final String[] HELP = {"Time to the first HTTPS response byte from Cloudflare.",
        "Download 5 MB from Cloudflare through this profile.", "Check the HTTP status of an HTTPS URL.",
        "Look up the proxy’s exit country with Cloudflare."};

    static void show(Activity activity, String profile) {
        LinearLayout panel = new LinearLayout(activity);
        panel.setOrientation(LinearLayout.VERTICAL);
        int pad = Math.round(20 * activity.getResources().getDisplayMetrics().density);
        panel.setPadding(pad, pad, pad, pad);
        TextView name = new TextView(activity);
        name.setText(profile);
        panel.addView(name);
        RadioGroup tabs = new RadioGroup(activity);
        tabs.setOrientation(LinearLayout.HORIZONTAL);
        for (int i = 0; i < TABS.length; i++) {
            RadioButton tab = new RadioButton(activity);
            tab.setId(View.generateViewId());
            tab.setText(TABS[i]);
            tab.setGravity(android.view.Gravity.CENTER);
            tab.setButtonDrawable(null);
            tab.setPadding(0, pad / 2, 0, pad / 2);
            tabs.addView(tab, new RadioGroup.LayoutParams(0, -2, 1));
        }
        panel.addView(tabs);
        TextView help = new TextView(activity), result = new TextView(activity);
        EditText url = new EditText(activity);
        url.setSingleLine(true);
        url.setText("https://example.com/");
        panel.addView(help);
        panel.addView(url);
        panel.addView(result);
        tabs.setOnCheckedChangeListener((group, id) -> {
            int i = group.indexOfChild(group.findViewById(id));
            for (int j = 0; j < TABS.length; j++)
                group.getChildAt(j).setBackgroundColor(i == j ? 0xffdedede : 0x00000000);
            help.setText(HELP[i]);
            result.setText("");
            url.setVisibility(i == 2 ? View.VISIBLE : View.GONE);
        });
        tabs.check(tabs.getChildAt(0).getId());
        AlertDialog dialog = new AlertDialog.Builder(activity)
                                 .setTitle("Connection tests")
                                 .setView(panel)
                                 .setPositiveButton("Run test", null)
                                 .setNegativeButton("Close", null)
                                 .create();
        dialog.show();
        android.graphics.drawable.GradientDrawable sheet = new android.graphics.drawable.GradientDrawable();
        sheet.setColor(0xffffffff);
        sheet.setCornerRadius(pad);
        dialog.getWindow().setBackgroundDrawable(sheet);
        dialog.getWindow().setDimAmount(0.38f);
        for (int action : new int[]{AlertDialog.BUTTON_POSITIVE, AlertDialog.BUTTON_NEGATIVE}) {
            Button control = dialog.getButton(action);
            boolean primary = action == AlertDialog.BUTTON_POSITIVE;
            android.graphics.drawable.GradientDrawable shape = new android.graphics.drawable.GradientDrawable();
            shape.setColor(primary ? 0xff121212 : 0xffffffff);
            shape.setStroke(1, primary ? 0xff121212 : 0xffcccccc);
            shape.setCornerRadius(pad / 2f);
            control.setBackground(shape);
            control.setTextColor(primary ? 0xffffffff : 0xff121212);
            control.setAllCaps(false);
        }
        java.util.concurrent.atomic.AtomicReference<HttpsURLConnection> active =
            new java.util.concurrent.atomic.AtomicReference<>();
        java.util.concurrent.atomic.AtomicBoolean closed = new java.util.concurrent.atomic.AtomicBoolean();
        dialog.setOnDismissListener(d -> {
            closed.set(true);
            HttpsURLConnection connection = active.getAndSet(null);
            if (connection != null)
                connection.disconnect();
        });
        Button run = dialog.getButton(AlertDialog.BUTTON_POSITIVE);
        run.setOnClickListener(v -> {
            int i = tabs.indexOfChild(tabs.findViewById(tabs.getCheckedRadioButtonId()));
            String target = i == 1 ? DOWNLOAD : i == 2 ? url.getText().toString().trim() : TRACE;
            for (int j = 0; j < TABS.length; j++) tabs.getChildAt(j).setEnabled(false);
            url.setEnabled(false);
            run.setEnabled(false);
            result.setText("Running…");
            new Thread(() -> {
                String message;
                try {
                    URL endpoint = new URL(target);
                    if (!endpoint.getProtocol().equals("https"))
                        throw new IOException("Enter an HTTPS URL.");
                    Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(ProxyActivity.LISTENER_HOST, ProxyActivity.LISTENER_PORT));
                    HttpsURLConnection connection = (HttpsURLConnection) endpoint.openConnection(proxy);
                    active.set(connection);
                    if (closed.get())
                        return;
                    connection.setConnectTimeout(10000);
                    connection.setReadTimeout(15000);
                    connection.setInstanceFollowRedirects(false);
                    connection.setUseCaches(false);
                    if (i == 2)
                        connection.setRequestMethod("HEAD");
                    long start = System.nanoTime();
                    int status = connection.getResponseCode();
                    if (i == 2)
                        message = "HTTP " + status;
                    else if (status != 200)
                        throw new IOException("HTTP " + status);
                    else
                        try (InputStream body = connection.getInputStream()) {
                            if (i == 0) {
                                if (body.read() == -1)
                                    throw new EOFException();
                                message = (System.nanoTime() - start) / 1000000 + " ms to first byte";
                            } else if (i == 1) {
                                byte[] buf = new byte[32768];
                                int bytes = 0, count;
                                while (bytes <= 5000000 && (count = body.read(buf)) != -1) bytes += count;
                                if (bytes != 5000000)
                                    throw new IOException("Incomplete speed sample");
                                message = String.format(Locale.ROOT, "%.1f Mbps download",
                                    bytes * 8000.0 / (System.nanoTime() - start));
                            } else {
                                BufferedReader reader =
                                    new BufferedReader(new InputStreamReader(body, StandardCharsets.UTF_8));
                                String country = null, line;
                                while ((line = reader.readLine()) != null)
                                    if (line.matches("loc=[A-Z]{2}")) {
                                        country = line.substring(4);
                                        break;
                                    }
                                if (country == null)
                                    throw new IOException("Country unavailable");
                                message = "Exit country · " + country;
                            }
                        }
                } catch (Exception error) {
                    message = "Test failed: " + error.getLocalizedMessage();
                } finally {
                    HttpsURLConnection connection = active.getAndSet(null);
                    if (connection != null)
                        connection.disconnect();
                }
                String output = message;
                activity.runOnUiThread(() -> {
                    if (!dialog.isShowing())
                        return;
                    result.setText(output);
                    run.setEnabled(true);
                    url.setEnabled(true);
                    for (int j = 0; j < TABS.length; j++) tabs.getChildAt(j).setEnabled(true);
                });
            }, "vless-diagnostic").start();
        });
    }
}
