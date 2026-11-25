package io.vless.client;

import android.app.Activity;
import android.app.AlertDialog;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.text.Editable;
import android.text.InputType;
import android.text.TextWatcher;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;
import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public final class ProxyActivity extends Activity {
    private Process engine;
    private Button connect;
    private JSONArray profiles;
    private int selected;
    private LinearLayout rows;
    private EditText search;
    private TextView name, details, address;
    private Button tests, add, vpn, bypass;
    private static final int VPN_CONSENT = 24;
    private final android.content.BroadcastReceiver vpnChanges = new android.content.BroadcastReceiver() {
        @Override
        public void onReceive(android.content.Context context, android.content.Intent intent) {
            render();
        }
    };
    private boolean vpnActive() {
        return "Starting".equals(TunnelService.state) || "Connected".equals(TunnelService.state);
    }
    private void toggleVpn() {
        if (vpnActive()) {
            startService(new android.content.Intent(this, TunnelService.class).setAction("stop"));
            return;
        }
        android.content.Intent consent = android.net.VpnService.prepare(this);
        if (consent == null)
            launchVpn();
        else
            startActivityForResult(consent, VPN_CONSENT);
    }
    private void launchVpn() {
        JSONObject item = current();
        if (item != null && engine == null)
            startForegroundService(new android.content.Intent(this, TunnelService.class)
                                       .putExtra("link", item.optString("link"))
                                       .putExtra("name", item.optString("name")));
    }
    @Override
    protected void onActivityResult(int request, int result, android.content.Intent data) {
        super.onActivityResult(request, result, data);
        if (request == VPN_CONSENT && result == RESULT_OK)
            launchVpn();
    }
    @Override
    protected void onStart() {
        super.onStart();
        android.content.IntentFilter filter = new android.content.IntentFilter(TunnelService.CHANGED);
        if (android.os.Build.VERSION.SDK_INT >= 33)
            registerReceiver(vpnChanges, filter, RECEIVER_NOT_EXPORTED);
        else
            registerReceiver(vpnChanges, filter);
        render();
    }
    @Override
    protected void onStop() {
        unregisterReceiver(vpnChanges);
        super.onStop();
    }
    private boolean listening;
    private static final int INK = 0xff121212, PAPER = Color.WHITE, MUTED = 0xff595959;
    private static final int CANVAS = 0xffeaeaea, EMBER = 0xffff3616;
    private TextView status;

    @Override
    public void onCreate(Bundle state) {
        super.onCreate(state);
        try {
            profiles = new JSONArray(getPreferences(MODE_PRIVATE).getString("profiles", "[]"));
        } catch (JSONException err) {
            throw new IllegalStateException("Invalid saved profiles", err);
        }
        selected = getPreferences(MODE_PRIVATE).getInt("selected", 0);
        ScrollView scroll = new ScrollView(this);
        scroll.setBackgroundColor(CANVAS);
        LinearLayout layout = column(18);
        scroll.addView(layout);
        scroll.setOnApplyWindowInsetsListener((view, insets) -> {
            view.setPadding(0, insets.getSystemWindowInsetTop(), 0, insets.getSystemWindowInsetBottom());
            return insets;
        });
        LinearLayout heading = new LinearLayout(this);
        heading.setGravity(android.view.Gravity.CENTER_VERTICAL);
        heading.addView(label("Profiles", 30, INK, true), new LinearLayout.LayoutParams(0, -2, 1));
        add = button("+  Import links", INK, PAPER);
        add.setOnClickListener(v -> importDialog());
        heading.addView(add);
        layout.addView(heading);
        search = new EditText(this);
        search.setSingleLine(true);
        search.setHint("Search profiles");
        search.setTextColor(INK);
        search.setHintTextColor(MUTED);
        search.setPadding(dp(14), 0, dp(14), 0);
        search.setBackground(surface(PAPER, 10));
        block(layout, search, 46);
        rows = column(0);
        block(layout, rows, -2);
        LinearLayout card = column(22);
        card.setBackground(new GradientDrawable() {
            private final android.graphics.Paint dots =
                new android.graphics.Paint(android.graphics.Paint.ANTI_ALIAS_FLAG);
            {
                setColor(INK);
                setCornerRadius(dp(20));
                dots.setColor(0xff2a2a2a);
            }
            @Override
            public void draw(android.graphics.Canvas canvas) {
                super.draw(canvas);
                for (int y = dp(12); y < getBounds().height() - dp(10); y += dp(14))
                    for (int x = dp(12); x < getBounds().width() - dp(10); x += dp(14))
                        canvas.drawCircle(x, y, dp(1), dots);
            }
        });
        block(layout, card, -2);
        status = label("●  Proxy offline", 14, 0xffbbbbbb, true);
        card.addView(status);
        name = label("", 28, PAPER, true);
        block(card, name, -2);
        details = label("", 16, 0xffbbbbbb, false);
        card.addView(details);
        address = label("", 14, PAPER, false);
        block(card, address, -2);
        tests = button("Connection tests", 0xff333333, PAPER);
        tests.setOnClickListener(v -> ConnectionTests.show(this, current().optString("name")));
        block(card, tests, 44);
        connect = button("Start proxy", EMBER, INK);
        connect.setOnClickListener(v -> {
            if (engine == null)
                startProxy();
            else
                stopProxy();
        });
        block(card, connect, 48);
        vpn = button("Connect VPN", 0xff333333, PAPER);
        vpn.setOnClickListener(view -> toggleVpn());
        block(card, vpn, 48);
        bypass = button("Per-app routing", 0xff333333, PAPER);
        bypass.setOnClickListener(view -> {
            String[] modes = {"Bypass selected apps", "Route only selected apps"};
            boolean inclusive = getSharedPreferences("routing", MODE_PRIVATE).getBoolean("inclusive", false);
            new AlertDialog.Builder(this).setTitle("Per-app routing")
                .setSingleChoiceItems(modes, inclusive ? 1 : 0, (dialog, index) -> {
                    dialog.dismiss();
                    showRoutingApps(index == 1, modes[index]);
                }).setNegativeButton("Cancel", null).show();
        });
        block(card, bypass, 44);
        search.addTextChangedListener(new TextWatcher() {
            public void afterTextChanged(Editable e) {
                renderRows();
            }
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {}
            public void onTextChanged(CharSequence s, int start, int before, int count) {}
        });
        render();
        setContentView(scroll);
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
    private GradientDrawable surface(int color, int radius) {
        GradientDrawable bg = new GradientDrawable();
        bg.setColor(color);
        bg.setCornerRadius(dp(radius));
        return bg;
    }
    private LinearLayout column(int padding) {
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(dp(padding), dp(padding), dp(padding), dp(padding));
        return box;
    }
    private void block(LinearLayout parent, View view, int height) {
        LinearLayout.LayoutParams params =
            new LinearLayout.LayoutParams(-1, height < 0 ? height : dp(height));
        params.topMargin = dp(14);
        parent.addView(view, params);
    }
    private TextView label(String text, int size, int color, boolean bold) {
        TextView view = new TextView(this);
        view.setText(text);
        view.setTextSize(size);
        view.setTextColor(color);
        if (bold)
            view.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        return view;
    }
    private Button button(String text, int bg, int fg) {
        Button b = new Button(this);
        b.setText(text);
        b.setAllCaps(false);
        b.setTextColor(fg);
        b.setPadding(dp(14), 0, dp(14), 0);
        b.setBackground(surface(bg, 8));
        return b;
    }
    private JSONObject current() {
        return profiles.optJSONObject(selected);
    }
    private void renderRows() {
        rows.removeAllViews();
        String filter = search.getText().toString().toLowerCase(Locale.ROOT);
        for (int i = 0; i < profiles.length(); i++) {
            JSONObject p = profiles.optJSONObject(i);
            String title = p.optString("name"), endpoint = p.optString("endpoint"),
                   security = p.optString("security");
            if (!(title + " " + endpoint + " " + security).toLowerCase(Locale.ROOT).contains(filter))
                continue;
            LinearLayout row = column(12);
            row.addView(label(title, 17, INK, true));
            row.addView(label(endpoint + "   ·   " + security, 14, MUTED, false));
            row.setBackground(surface(i == selected ? 0xffdedede : CANVAS, 12));
            final int index = i;
            row.setOnClickListener(v -> {
                if (engine != null || vpnActive())
                    return;
                selected = index;
                getPreferences(MODE_PRIVATE).edit().putInt("selected", index).apply();
                render();
            });
            row.setOnLongClickListener(v -> {
                if (engine != null || vpnActive())
                    return false;
                new AlertDialog.Builder(this)
                    .setTitle("Remove profile?")
                    .setMessage(title)
                    .setNegativeButton("Cancel", null)
                    .setPositiveButton("Remove",
                        (dialog, which) -> {
                            profiles.remove(index);
                            if (selected > index || selected >= profiles.length())
                                selected = Math.max(0, selected - 1);
                            getPreferences(MODE_PRIVATE)
                                .edit()
                                .putString("profiles", profiles.toString())
                                .putInt("selected", selected)
                                .apply();
                            render();
                        })
                    .show();
                return true;
            });
            rows.addView(row);
        }
    }
    private void render() {
        renderRows();
        JSONObject p = current();
        name.setText(p == null ? "No profile selected" : p.optString("name"));
        details.setText(p == null ? "" : p.optString("security"));
        address.setText(p == null ? ""
                                  : "Server\n" + p.optString("endpoint")
                    + (listening ? "\n\nSOCKS5 address\n127.0.0.1:2080" : ""));
        status.setText(listening ? "●  Proxy listening"
                : engine != null ? "●  Starting"
                                 : "●  Proxy offline");
        status.setTextColor(listening ? EMBER : 0xffbbbbbb);
        tests.setVisibility(listening ? View.VISIBLE : View.GONE);
        connect.setText(engine == null ? "Start proxy" : "Stop proxy");
        boolean active = vpnActive();
        if (active) {
            name.setText(TunnelService.profileName);
            status.setText("●  VPN " + TunnelService.state.toLowerCase(Locale.ROOT));
            status.setTextColor(EMBER);
        } else if ("Failed".equals(TunnelService.state) && engine == null) {
            status.setText("VPN disconnected. Check the profile or retry.");
        }
        connect.setEnabled(p != null && !active);
        add.setEnabled(engine == null && !active);
        bypass.setEnabled(!active);
        vpn.setEnabled(engine == null && (p != null || active));
        vpn.setText(active ? "Disconnect VPN" : "Connect VPN");
    }
    private void showRoutingApps(boolean inclusive, String title) {
        android.content.pm.PackageManager manager = getPackageManager();
        android.content.Intent launcher = new android.content.Intent(android.content.Intent.ACTION_MAIN)
                           .addCategory(android.content.Intent.CATEGORY_LAUNCHER);
        java.util.List<android.content.pm.ResolveInfo> apps = manager.queryIntentActivities(launcher, 0);
        apps.sort(new android.content.pm.ResolveInfo.DisplayNameComparator(manager));
        java.util.ArrayList<String> packages = new java.util.ArrayList<String>();
        java.util.ArrayList<String> labels = new java.util.ArrayList<String>();
        for (android.content.pm.ResolveInfo app : apps) {
            String id = app.activityInfo.packageName;
            if (!id.equals(getPackageName()) && !packages.contains(id)) {
                packages.add(id);
                labels.add(app.loadLabel(manager) + "\n" + id);
            }
        }
        android.content.SharedPreferences prefs = getSharedPreferences("routing", MODE_PRIVATE);
        String key = inclusive ? "included" : "excluded";
        java.util.Set<String> selectedApps = new java.util.HashSet<>(prefs.getStringSet(key, java.util.Collections.emptySet()));
        boolean[] checked = new boolean[packages.size()];
        for (int i = 0; i < checked.length; i++)
            checked[i] = selectedApps.contains(packages.get(i));
        new AlertDialog.Builder(this)
            .setTitle(title)
            .setMultiChoiceItems(labels.toArray(new String[0]), checked, (dialog, index, enabled) -> {
                if (enabled)
                    selectedApps.add(packages.get(index));
                else
                    selectedApps.remove(packages.get(index));
            })
            .setPositiveButton("Save", (dialog, which) -> {
                if (inclusive && java.util.Collections.disjoint(selectedApps, packages)) {
                    Toast.makeText(this, "Select at least one app to route through the VPN", Toast.LENGTH_LONG).show();
                    return;
                }
                prefs.edit().putStringSet(key, selectedApps).putBoolean("inclusive", inclusive).apply();
            })
            .setNegativeButton("Cancel", null)
            .show();
    }

    private void importDialog() {
        EditText field = new EditText(this);
        field.setHint("VLESS links or subscription");
        field.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_MULTI_LINE
            | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        AlertDialog dialog = new AlertDialog.Builder(this)
                                 .setTitle("Import links")
                                 .setView(field)
                                 .setNegativeButton("Cancel", null)
                                 .setPositiveButton("Import", null)
                                 .create();
        dialog.show();
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> {
            String text = field.getText().toString().trim();
            if (text.isEmpty() || text.length() > 1048576) {
                field.setError("Enter up to 1 MiB of VLESS links");
                return;
            }
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setEnabled(false);
            new Thread(() -> {
                try {
                    Process parser = new ProcessBuilder(
                        new File(getApplicationInfo().nativeLibraryDir, "libvless_engine.so").getPath(),
                        "import-profiles")
                                         .start();
                    try (OutputStream in = parser.getOutputStream()) {
                        in.write(text.getBytes(StandardCharsets.UTF_8));
                    }
                    StringBuilder output = new StringBuilder();
                    try (BufferedReader r = new BufferedReader(
                             new InputStreamReader(parser.getInputStream(), StandardCharsets.UTF_8))) {
                        String line;
                        while ((line = r.readLine()) != null) output.append(line);
                    }
                    if (parser.waitFor() != 0)
                        throw new IllegalArgumentException();
                    JSONArray imported = new JSONArray(output.toString());
                    runOnUiThread(() -> {
                        if (!dialog.isShowing())
                            return;
                        java.util.LinkedHashMap<String, JSONObject> merged = new java.util.LinkedHashMap<>();
                        for (int i = 0; i < profiles.length(); i++) {
                            JSONObject entry = profiles.optJSONObject(i);
                            merged.putIfAbsent(entry.optString("link"), entry);
                        }
                        for (int i = 0; i < imported.length(); i++) {
                            JSONObject entry = imported.optJSONObject(i);
                            merged.put(entry.optString("link"), entry);
                        }
                        if (merged.size() > 128) {
                            field.setError("Save up to 128 profiles");
                            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setEnabled(true);
                            return;
                        }
                        if (imported.length() == 0) {
                            field.setError("No profiles found");
                            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setEnabled(true);
                            return;
                        }
                        JSONObject first = imported.optJSONObject(0);
                        profiles = new JSONArray(merged.values());
                        selected = new java.util.ArrayList<>(merged.keySet()).indexOf(first.optString("link"));
                        for (int i = 0; i < imported.length(); i++) {
                            JSONArray warnings = imported.optJSONObject(i).optJSONArray("warnings");
                            if (warnings != null && warnings.length() > 0) {
                                Toast.makeText(this, warnings.optString(0), Toast.LENGTH_LONG).show();
                                break;
                            }
                        }
                        getPreferences(MODE_PRIVATE)
                            .edit()
                            .putString("profiles", profiles.toString())
                            .putInt("selected", selected)
                            .apply();
                        render();
                        dialog.dismiss();
                    });
                } catch (Exception e) {
                    runOnUiThread(() -> {
                        field.setError("Invalid VLESS link or subscription");
                        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setEnabled(true);
                    });
                }
            }, "vless-import").start();
        });
    }
    private void startProxy() {
        if (current() == null)
            return;
        String link = current().optString("link");
        File binary = new File(getApplicationInfo().nativeLibraryDir, "libvless_engine.so");
        try {
            Process child =
                new ProcessBuilder(binary.getPath(), "run", "--link", "-", "--listen", "127.0.0.1:2080")
                    .redirectErrorStream(true)
                    .start();
            engine = child;
            render();
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
                            if (engine == child) {
                                listening = true;
                                render();
                            }
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
                    listening = false;
                    render();
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
        listening = false;
        render();
    }

    @Override
    protected void onDestroy() {
        stopProxy();
        super.onDestroy();
    }
}
