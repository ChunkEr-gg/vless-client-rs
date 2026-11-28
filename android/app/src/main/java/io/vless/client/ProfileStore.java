package io.vless.client;

import android.content.Context;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import org.json.JSONArray;
import org.json.JSONException;

final class ProfileStore {
    private static final String ALIAS = "vless.client.profiles.v1";
    private static final String SEALED = "profiles.aesgcm.v1";
    private static final int IV_BYTES = 12;
    private final SharedPreferences prefs;

    private final Context context;
    private final String database;

    ProfileStore(Context context, SharedPreferences prefs, String database) {
        this.context = context;
        this.database = database;
        this.prefs = prefs;
    }

    private SecretKey key(boolean create) throws GeneralSecurityException, IOException {
        KeyStore store = KeyStore.getInstance("AndroidKeyStore");
        store.load(null);
        SecretKey existing = (SecretKey) store.getKey(ALIAS, null);
        if (existing != null)
            return existing;
        if (!create)
            throw new GeneralSecurityException("Missing profile key");
        KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        generator.init(new KeyGenParameterSpec.Builder(ALIAS,
            KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256).build());
        return generator.generateKey();
    }

    static final class Snapshot {
        final JSONArray rows;
        final int selected;

        Snapshot(JSONArray rows, int selected) {
            this.rows = rows;
            this.selected = selected;
        }
    }

    private SQLiteDatabase open() {
        SQLiteDatabase db = context.openOrCreateDatabase(database, Context.MODE_PRIVATE, null);
        try {
            db.execSQL("CREATE TABLE IF NOT EXISTS profile_state (id INTEGER PRIMARY KEY CHECK(id = 1), "
                       + "envelope BLOB NOT NULL, selected INTEGER NOT NULL)");
            return db;
        } catch (RuntimeException ex) {
            db.close();
            throw ex;
        }
    }

    private JSONArray decrypt(byte[] bytes) throws GeneralSecurityException, IOException, JSONException {
        if (bytes.length < IV_BYTES + 16)
            throw new IOException("Incomplete encrypted profiles");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key(false), new GCMParameterSpec(128, bytes, 0, IV_BYTES));
        return new JSONArray(new String(cipher.doFinal(bytes, IV_BYTES, bytes.length - IV_BYTES),
                                        StandardCharsets.UTF_8));
    }

    Snapshot load() throws GeneralSecurityException, IOException, JSONException {
        Snapshot result;
        try (SQLiteDatabase db = open()) {
            db.beginTransaction();
            try (Cursor cursor = db.rawQuery("SELECT envelope, selected FROM profile_state WHERE id = 1", null)) {
                if (cursor.moveToFirst()) {
                    result = new Snapshot(decrypt(cursor.getBlob(0)), cursor.getInt(1));
                } else {
                    int selected = prefs.getInt("selected", 0);
                    String sealed = prefs.getString(SEALED, null);
                    byte[] bytes;
                    if (sealed != null) {
                        bytes = Base64.decode(sealed, Base64.NO_WRAP);
                        result = new Snapshot(decrypt(bytes), selected);
                    } else {
                        result = new Snapshot(new JSONArray(prefs.getString("profiles", "[]")), selected);
                        bytes = encrypt(result.rows, true);
                    }
                    db.execSQL("INSERT INTO profile_state VALUES (1, ?, ?)", new Object[] {bytes, selected});
                }
                db.setTransactionSuccessful();
            } finally {
                db.endTransaction();
            }
        }
        // A crash before this point leaves the legacy copy available for migration.
        if ((prefs.contains("profiles") || prefs.contains(SEALED) || prefs.contains("selected"))
                && !prefs.edit().remove("profiles").remove(SEALED).remove("selected").commit())
            throw new IOException("Could not remove migrated profile preferences");
        return result;
    }

    private byte[] encrypt(JSONArray rows, boolean create) throws GeneralSecurityException, IOException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key(create));
        byte[] iv = cipher.getIV();
        if (iv.length != IV_BYTES)
            throw new GeneralSecurityException("Unexpected profile IV size");
        byte[] ciphertext = cipher.doFinal(rows.toString().getBytes(StandardCharsets.UTF_8));
        return ByteBuffer.allocate(iv.length + ciphertext.length).put(iv).put(ciphertext).array();
    }

    void save(JSONArray rows, int selected) throws GeneralSecurityException, IOException {
        // load() authenticates or migrates the single row before editing becomes available.
        android.content.ContentValues values = new android.content.ContentValues();
        values.put("envelope", encrypt(rows, false));
        values.put("selected", selected);
        try (SQLiteDatabase db = open()) {
            if (db.update("profile_state", values, "id = 1", null) != 1)
                throw new IOException("Missing profile state");
        }
    }
}
