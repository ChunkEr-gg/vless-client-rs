package io.vless.client;

import android.content.SharedPreferences;
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

    ProfileStore(SharedPreferences prefs) {
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

    JSONArray load() throws GeneralSecurityException, IOException, JSONException {
        String sealed = prefs.getString(SEALED, null);
        if (sealed != null) {
            byte[] bytes = Base64.decode(sealed, Base64.NO_WRAP);
            if (bytes.length < IV_BYTES + 16)
                throw new IOException("Incomplete encrypted profiles");
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key(false), new GCMParameterSpec(128, bytes, 0, IV_BYTES));
            return new JSONArray(new String(cipher.doFinal(bytes, IV_BYTES, bytes.length - IV_BYTES),
                                            StandardCharsets.UTF_8));
        }
        String legacy = prefs.getString("profiles", null);
        if (legacy == null)
            return new JSONArray();
        JSONArray rows = new JSONArray(legacy);
        save(rows, prefs.getInt("selected", 0));
        return rows;
    }

    void save(JSONArray rows, int selected) throws GeneralSecurityException, IOException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key(!prefs.contains(SEALED)));
        byte[] iv = cipher.getIV();
        if (iv.length != IV_BYTES)
            throw new GeneralSecurityException("Unexpected profile IV size");
        byte[] ciphertext = cipher.doFinal(rows.toString().getBytes(StandardCharsets.UTF_8));
        byte[] envelope = ByteBuffer.allocate(iv.length + ciphertext.length).put(iv).put(ciphertext).array();
        // SharedPreferences atomically replaces one file, including the legacy key removal.
        if (!prefs.edit().putString(SEALED, Base64.encodeToString(envelope, Base64.NO_WRAP))
                .putInt("selected", selected).remove("profiles").commit())
            throw new IOException("Could not commit encrypted profiles");
    }
}
