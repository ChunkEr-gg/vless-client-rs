package io.vless.client;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
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
import java.util.concurrent.atomic.AtomicReference;
import org.json.JSONArray;
import org.json.JSONObject;

public final class ProxyActivity extends Activity {
    private Process engine;
    private Button connect;
    private JSONArray profiles;
    private ProfileStore store;
    private int selected;
    private LinearLayout rows;
    private EditText search;
    private TextView name, details, address;
    private LinearLayout listenerRow;
    static final String LISTENER_HOST = "127.0.0.1";
    static final int LISTENER_PORT = 2080;
    private static final String LISTENER_ADDRESS = LISTENER_HOST + ":" + LISTENER_PORT;
    private Button tests, add, vpn, bypass;
    private static final int PICK_PROFILE_FILE = 25;
    private EditText importField;
    private static final int VPN_CONSENT = 24;
    private final android.content.BroadcastReceiver vpnChanges = new android.content.BroadcastReceiver() {
        @Override
        public void onReceive(android.content.Context context, android.content.Intent intent) {
            render();
        }
    };
    private boolean vpnActive() {
        return "Starting".equals(TunnelService.state) || "Connected".equals(TunnelService.state)
            || "Disconnecting".equals(TunnelService.state);
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
        if (request == PICK_PROFILE_FILE && result == RESULT_OK && data != null && data.getData() != null)
            readProfileFile(data.getData());
    }

    private void readProfileFile(android.net.Uri uri) {
        if (!"content".equals(uri.getScheme()))
            return;
        EditText target = importField;
        new Thread(() -> {
            try (java.io.InputStream stream = getContentResolver().openInputStream(uri)) {
                if (stream == null)
                    throw new java.io.IOException();
                java.io.ByteArrayOutputStream bytes = new java.io.ByteArrayOutputStream();
                byte[] chunk = new byte[8192];
                int count;
                while ((count = stream.read(chunk)) != -1) {
                    if (bytes.size() + count > 1048576)
                        throw new java.io.IOException();
                    bytes.write(chunk, 0, count);
                }
                String text = StandardCharsets.UTF_8.newDecoder()
                                  .decode(java.nio.ByteBuffer.wrap(bytes.toByteArray())).toString();
                runOnUiThread(() -> {
                    if (isDestroyed() || isFinishing() || engine != null || vpnActive() || target != importField)
                        return;
                    if (target == null)
                        importDialog(text);
                    else if (target.isEnabled())
                        target.setText(text);
                });
            } catch (java.io.IOException | SecurityException error) {
                runOnUiThread(() -> Toast.makeText(this, "Choose a readable UTF-8 file up to 1 MiB",
                                                   Toast.LENGTH_LONG).show());
            }
        }, "vless-read-profile-file").start();
    }

    @Override
    protected void onStart() {
        super.onStart();
        if (profiles == null) return;
        android.content.IntentFilter filter = new android.content.IntentFilter(TunnelService.CHANGED);
        if (android.os.Build.VERSION.SDK_INT >= 33)
            registerReceiver(vpnChanges, filter, RECEIVER_NOT_EXPORTED);
        else
            registerReceiver(vpnChanges, filter);
        render();
    }
    @Override
    protected void onStop() {
        if (profiles != null) unregisterReceiver(vpnChanges);
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
            loadProfiles(new ProfileStore(this, getPreferences(MODE_PRIVATE), "profiles.db"));
        } catch (Exception err) {
            Toast.makeText(this, "Saved profiles could not be opened. Unlock the device and retry.", Toast.LENGTH_LONG).show();
            finish();
            return;
        }
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
        add.setOnClickListener(v -> importDialog(""));
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
        listenerRow = new LinearLayout(this);
        listenerRow.setGravity(android.view.Gravity.CENTER_VERTICAL);
        TextView listener = label("SOCKS5 address\n" + LISTENER_ADDRESS, 14, PAPER, false);
        listenerRow.addView(listener, new LinearLayout.LayoutParams(0, -2, 1));
        android.widget.ImageButton copy = new android.widget.ImageButton(this);
        copy.setImageResource(R.drawable.ic_copy);
        copy.setContentDescription("Copy proxy address");
        copy.setColorFilter(PAPER);
        copy.setBackground(surface(0xff333333, 8));
        copy.setOnClickListener(view -> {
            android.content.ClipboardManager clipboard = getSystemService(android.content.ClipboardManager.class);
            clipboard.setPrimaryClip(android.content.ClipData.newPlainText("SOCKS5 address", LISTENER_ADDRESS));
            if (android.os.Build.VERSION.SDK_INT < 33)
                Toast.makeText(this, "Address copied", Toast.LENGTH_SHORT).show();
        });
        listenerRow.addView(copy, new LinearLayout.LayoutParams(dp(48), dp(48)));
        block(card, listenerRow, -2);
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
        Button dns = button("VPN DNS", 0xff333333, PAPER);
        dns.setOnClickListener(view -> showDns());
        block(card, dns, 44);
        search.addTextChangedListener(new TextWatcher() {
            public void afterTextChanged(Editable e) {
                renderRows();
            }
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {}
            public void onTextChanged(CharSequence s, int start, int before, int count) {}
        });
        render();
        setContentView(scroll);
        if (state == null)
            reviewImport(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        if (profiles == null) return;
        reviewImport(intent);
    }

    private void reviewImport(Intent intent) {
        String text;
        if (Intent.ACTION_VIEW.equals(intent.getAction()) && "vless".equals(intent.getScheme())) {
            text = intent.getDataString();
        } else if (Intent.ACTION_SEND.equals(intent.getAction()) && "text/plain".equals(intent.getType())) {
            CharSequence shared = intent.getCharSequenceExtra(Intent.EXTRA_TEXT);
            text = shared == null ? null : shared.toString();
        } else {
            return;
        }
        if (text == null || text.isEmpty() || text.length() > 1048576) {
            Toast.makeText(this, "Share up to 1 MiB of VLESS links", Toast.LENGTH_LONG).show();
            return;
        }
        if (engine != null || vpnActive()) {
            Toast.makeText(this, "Disconnect before importing profiles", Toast.LENGTH_LONG).show();
            return;
        }
        importDialog(text);
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
        String filter = search.getText().toString().trim().toLowerCase(Locale.ROOT);
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
                selectProfile(index);
            });
            row.setOnLongClickListener(v -> {
                if (engine != null || vpnActive())
                    return false;
                java.util.List<String> actions = new java.util.ArrayList<>();
                actions.add("Share profile");
                if (filter.isEmpty() && index > 0)
                    actions.add("Move up");
                if (filter.isEmpty() && index + 1 < profiles.length())
                    actions.add("Move down");
                actions.add("Remove profile");
                new AlertDialog.Builder(this)
                    .setTitle(title)
                    .setItems(actions.toArray(new String[0]), (dialog, action) -> {
                        String choice = actions.get(action);
                        if (choice.equals("Share profile")) {
                            android.content.Intent share = new android.content.Intent(android.content.Intent.ACTION_SEND)
                                .setType("text/plain").putExtra(android.content.Intent.EXTRA_TEXT, p.optString("link"));
                            startActivity(android.content.Intent.createChooser(share, "Share profile"));
                        } else if (choice.equals("Move up") || choice.equals("Move down")) {
                            moveProfile(index, choice.equals("Move up") ? index - 1 : index + 1);
                        } else {
                            confirmRemoval(index, title);
                        }
                    }).setNegativeButton("Cancel", null).show();
                return true;
            });
            rows.addView(row);
        }
        if (!filter.isEmpty() && rows.getChildCount() == 0) {
            TextView empty = label("No matching profiles", 14, MUTED, false);
            empty.setGravity(android.view.Gravity.CENTER);
            rows.addView(empty);
        }
    }
    private void moveProfile(int from, int to) {
        java.util.List<JSONObject> ordered = new java.util.ArrayList<>();
        for (int i = 0; i < profiles.length(); i++)
            ordered.add(profiles.optJSONObject(i));
        JSONObject active = current();
        java.util.Collections.swap(ordered, from, to);
        saveProfiles(new JSONArray(ordered), ordered.indexOf(active));
    }

    void loadProfiles(ProfileStore source) throws java.security.GeneralSecurityException, java.io.IOException, org.json.JSONException {
        ProfileStore.Snapshot saved = source.load();
        store = source;
        profiles = saved.rows;
        selected = saved.selected;
    }

    boolean selectProfile(int index) {
        return saveProfiles(profiles, index);
    }

    boolean removeProfile(int index) {
        JSONArray remaining = new JSONArray();
        for (int i = 0; i < profiles.length(); i++)
            if (i != index) remaining.put(profiles.opt(i));
        int next = selected > index || selected >= remaining.length() ? Math.max(0, selected - 1) : selected;
        return saveProfiles(remaining, next);
    }

    private boolean saveProfiles(JSONArray next, int nextSelected) {
        try {
            store.save(next, nextSelected);
        } catch (Exception error) {
            Toast.makeText(this, "Could not save profiles", Toast.LENGTH_LONG).show();
            return false;
        }
        profiles = next;
        selected = nextSelected;
        render();
        return true;
    }

    private void confirmRemoval(int index, String title) {
        new AlertDialog.Builder(this)
            .setTitle("Remove profile?")
            .setMessage(title)
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Remove", (dialog, which) -> removeProfile(index))
            .show();
    }

    private void render() {
        renderRows();
        JSONObject p = current();
        name.setText(p == null ? "No profile selected" : p.optString("name"));
        details.setText(p == null ? "" : p.optString("security"));
        address.setText(p == null ? ""
                                  : "Server\n" + p.optString("endpoint"));
        listenerRow.setVisibility(listening ? View.VISIBLE : View.GONE);
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
        boolean disconnecting = "Disconnecting".equals(TunnelService.state);
        vpn.setEnabled(!disconnecting && engine == null && (p != null || active));
        vpn.setText(disconnecting ? "Disconnecting…" : active ? "Disconnect VPN" : "Connect VPN");
    }
    private void showDns() {
        android.content.SharedPreferences prefs = getSharedPreferences("routing", MODE_PRIVATE);
        EditText field = new EditText(this);
        field.setSingleLine(true);
        field.setHint(TunnelService.DEFAULT_DNS);
        field.setText(prefs.getString("dns", ""));
        AlertDialog dialog = new AlertDialog.Builder(this).setTitle("VPN DNS server")
            .setMessage("Enter an IP address. A blank value uses " + TunnelService.DEFAULT_DNS + " on the next connection.")
            .setView(field).setPositiveButton("Save", null).setNegativeButton("Cancel", null).create();
        dialog.show();
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(view -> {
            String value = field.getText().toString().trim();
            try {
                if (!value.isEmpty()) TunnelService.dnsAddress(value);
                prefs.edit().putString("dns", value).apply();
                dialog.dismiss();
            } catch (IllegalArgumentException invalid) {
                field.setError("Enter a unicast IPv4 or IPv6 address");
            }
        });
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

    private void importDialog(String initialText) {
        EditText field = new EditText(this);
        field.setHint("VLESS link or HTTPS subscription URL");
        field.setText(initialText);
        importField = field;
        field.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_MULTI_LINE
            | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        AlertDialog dialog = new AlertDialog.Builder(this)
                                 .setTitle("Import links")
                                 .setView(field)
                                 .setNegativeButton("Cancel", null)
                                 .setNeutralButton("Choose file…", null)
                                 .setPositiveButton("Import", null)
                                 .create();
        AtomicReference<Thread> worker = new AtomicReference<>();
        dialog.setOnDismissListener(ignored -> {
            Thread active = worker.getAndSet(null);
            if (active != null)
                active.interrupt();
            if (importField == field)
                importField = null;
        });
        dialog.show();
        dialog.getButton(AlertDialog.BUTTON_NEUTRAL).setOnClickListener(v ->
            startActivityForResult(new Intent(Intent.ACTION_OPEN_DOCUMENT)
                                       .addCategory(Intent.CATEGORY_OPENABLE).setType("*/*"), PICK_PROFILE_FILE));
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> {
            String text = field.getText().toString().trim();
            byte[] input = text.getBytes(StandardCharsets.UTF_8);
            if (input.length == 0 || input.length > SubscriptionDownload.MAX_BYTES) {
                field.setError("Enter up to 1 MiB of VLESS links");
                return;
            }
            Button importButton = dialog.getButton(AlertDialog.BUTTON_POSITIVE);
            Button chooseFile = dialog.getButton(AlertDialog.BUTTON_NEUTRAL);
            field.setError(null);
            field.setEnabled(false);
            importButton.setEnabled(false);
            chooseFile.setEnabled(false);
            boolean subscription = text.regionMatches(true, 0, "https://", 0, 8);
            if (subscription)
                importButton.setText("Downloading…");
            Thread task = new Thread(() -> {
                Process parser = null;
                String error = "Invalid VLESS link or subscription";
                try {
                    byte[] content = input;
                    if (subscription) {
                        error = "Could not download the subscription";
                        content = SubscriptionDownload.read(text);
                        error = "Invalid VLESS link or subscription";
                    }
                    if (Thread.currentThread().isInterrupted())
                        return;
                    parser = new ProcessBuilder(
                        new File(getApplicationInfo().nativeLibraryDir, "libvless_engine.so").getPath(),
                        "import-profiles")
                                         .start();
                    try (OutputStream in = parser.getOutputStream()) {
                        in.write(content);
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
                        if (!dialog.isShowing() || isFinishing() || isDestroyed())
                            return;
                        if (engine != null || vpnActive()) {
                            field.setError("Disconnect before importing profiles");
                            return;
                        }
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
                            return;
                        }
                        if (imported.length() == 0) {
                            field.setError("No profiles found");
                            return;
                        }
                        JSONObject first = imported.optJSONObject(0);
                        int nextSelected = new java.util.ArrayList<>(merged.keySet()).indexOf(first.optString("link"));
                        for (int i = 0; i < imported.length(); i++) {
                            JSONArray warnings = imported.optJSONObject(i).optJSONArray("warnings");
                            if (warnings != null && warnings.length() > 0) {
                                Toast.makeText(this, warnings.optString(0), Toast.LENGTH_LONG).show();
                                break;
                            }
                        }
                        if (saveProfiles(new JSONArray(merged.values()), nextSelected))
                            dialog.dismiss();
                    });
                } catch (Exception e) {
                    String message = e instanceof SubscriptionDownload.TooLarge
                        ? "Import up to 1 MiB of VLESS links" : error;
                    runOnUiThread(() -> {
                        if (dialog.isShowing() && !isFinishing() && !isDestroyed())
                            field.setError(message);
                    });
                } finally {
                    if (parser != null)
                        parser.destroy();
                    worker.compareAndSet(Thread.currentThread(), null);
                    runOnUiThread(() -> {
                        if (!dialog.isShowing() || isFinishing() || isDestroyed())
                            return;
                        field.setEnabled(true);
                        importButton.setText("Import");
                        importButton.setEnabled(true);
                        chooseFile.setEnabled(true);
                    });
                }
            }, "vless-import");
            worker.set(task);
            task.start();
        });
    }
    private void startProxy() {
        if (current() == null)
            return;
        String link = current().optString("link");
        File binary = new File(getApplicationInfo().nativeLibraryDir, "libvless_engine.so");
        try {
            Process child =
                new ProcessBuilder(binary.getPath(), "run", "--link", "-", "--listen", LISTENER_ADDRESS)
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
        if (profiles != null) stopProxy();
        super.onDestroy();
    }
}
