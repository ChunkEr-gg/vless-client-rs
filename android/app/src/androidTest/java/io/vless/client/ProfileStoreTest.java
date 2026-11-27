package io.vless.client;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import java.security.GeneralSecurityException;
import java.util.UUID;
import org.json.JSONArray;
import org.json.JSONException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import static org.junit.Assert.*;

@RunWith(AndroidJUnit4.class)
public class ProfileStoreTest {
    private Context context;
    private SharedPreferences prefs;
    private String file;
    private static final String ROWS = "[{\"name\":\"first\"},{\"link\":\"vless://fixture\",\"pin\":\"test-pin\"}]";
    private static final String SEALED = "profiles.aesgcm.v1";

    @Before public void setUp() {
        context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        file = "test-" + UUID.randomUUID();
        prefs = context.getSharedPreferences(file, Context.MODE_PRIVATE);
    }

    @After public void tearDown() {
        context.deleteSharedPreferences(file);
    }

    @Test public void migratesOnceAndPreservesSelection() throws Exception {
        assertTrue(prefs.edit().putString("profiles", ROWS).putInt("selected", 1).commit());
        ProfileStore store = new ProfileStore(prefs);
        JSONArray migrated = store.load();
        assertEquals(2, migrated.length());
        assertEquals("test-pin", migrated.getJSONObject(1).getString("pin"));
        String sealed = prefs.getString(SEALED, null);
        assertNotNull(sealed);
        assertFalse(prefs.contains("profiles"));
        assertEquals(1, prefs.getInt("selected", -1));
        assertEquals("vless://fixture", new ProfileStore(prefs).load().getJSONObject(1).getString("link"));
        assertEquals(sealed, prefs.getString(SEALED, null));
        store.save(store.load(), 0);
        assertNotEquals(sealed, prefs.getString(SEALED, null));
        assertEquals(0, prefs.getInt("selected", -1));
    }

    @Test public void authenticationFailurePreservesCiphertext() throws Exception {
        ProfileStore store = new ProfileStore(prefs);
        store.save(new JSONArray(ROWS), 1);
        byte[] bytes = Base64.decode(prefs.getString(SEALED, ""), Base64.NO_WRAP);
        bytes[bytes.length - 1] ^= 1;
        String corrupt = Base64.encodeToString(bytes, Base64.NO_WRAP);
        assertTrue(prefs.edit().putString(SEALED, corrupt).commit());
        assertThrows(GeneralSecurityException.class, () -> store.load());
        assertEquals(corrupt, prefs.getString(SEALED, null));
    }

    @Test public void malformedLegacyDataIsPreserved() {
        assertTrue(prefs.edit().putString("profiles", "{").commit());
        assertThrows(JSONException.class, () -> new ProfileStore(prefs).load());
        assertEquals("{", prefs.getString("profiles", null));
        assertFalse(prefs.contains(SEALED));
    }
}
