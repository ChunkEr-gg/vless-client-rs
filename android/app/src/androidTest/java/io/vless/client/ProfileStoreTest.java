package io.vless.client;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteException;
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
        context.deleteDatabase(file);
    }

    private ProfileStore store() {
        return new ProfileStore(context, prefs, file);
    }

    private SQLiteDatabase database() {
        return context.openOrCreateDatabase(file, Context.MODE_PRIVATE, null);
    }

    private byte[] envelope() {
        try (SQLiteDatabase db = database();
             Cursor cursor = db.rawQuery("SELECT envelope FROM profile_state WHERE id = 1", null)) {
            assertTrue(cursor.moveToFirst());
            return cursor.getBlob(0);
        }
    }

    @Test public void migratesOnceAndPreservesSelection() throws Exception {
        assertTrue(prefs.edit().putString("profiles", ROWS).putInt("selected", 1).commit());
        ProfileStore.Snapshot migrated = store().load();
        assertEquals(2, migrated.rows.length());
        assertEquals("test-pin", migrated.rows.getJSONObject(1).getString("pin"));
        assertFalse(prefs.contains("profiles"));
        assertFalse(prefs.contains("selected"));
        assertEquals(1, migrated.selected);
        byte[] sealed = envelope();
        assertEquals("vless://fixture", store().load().rows.getJSONObject(1).getString("link"));
        assertArrayEquals(sealed, envelope());
        store().save(migrated.rows, 0);
        assertEquals(0, store().load().selected);
        assertFalse(java.util.Arrays.equals(sealed, envelope()));
    }

    @Test public void migratesExistingEncryptedPreferences() throws Exception {
        store().load();
        store().save(new JSONArray(ROWS), 1);
        byte[] sealed = envelope();
        assertTrue(context.deleteDatabase(file));
        assertTrue(prefs.edit().putString(SEALED, Base64.encodeToString(sealed, Base64.NO_WRAP))
                       .putInt("selected", 1).commit());
        ProfileStore.Snapshot restored = store().load();
        assertEquals(new JSONArray(ROWS).toString(), restored.rows.toString());
        assertEquals(1, restored.selected);
        assertArrayEquals(sealed, envelope());
        assertFalse(prefs.contains(SEALED));
    }

    @Test public void authenticationFailurePreservesCiphertext() throws Exception {
        store().load();
        store().save(new JSONArray(ROWS), 1);
        byte[] bytes = envelope();
        bytes[bytes.length - 1] ^= 1;
        try (SQLiteDatabase db = database()) {
            db.execSQL("UPDATE profile_state SET envelope = ?", new Object[] {bytes});
        }
        assertThrows(GeneralSecurityException.class, () -> store().load());
        assertArrayEquals(bytes, envelope());
    }

    @Test public void malformedLegacyDataIsPreserved() {
        assertTrue(prefs.edit().putString("profiles", "{").commit());
        assertThrows(JSONException.class, () -> store().load());
        assertEquals("{", prefs.getString("profiles", null));
        assertFalse(prefs.contains(SEALED));
    }

    @Test public void failedDeletionThenSelectionKeepsBothProfiles() throws Exception {
        ProfileStore store = store();
        store.load();
        JSONArray original = new JSONArray(ROWS);
        store.save(original, 0);
        try (SQLiteDatabase db = database()) {
            db.execSQL("CREATE TRIGGER fail_save BEFORE UPDATE ON profile_state BEGIN "
                       + "SELECT RAISE(ABORT, 'injected write failure'); END");
            JSONArray deletion = new JSONArray().put(original.get(1));
            assertThrows(SQLiteException.class, () -> store.save(deletion, 0));
            db.execSQL("DROP TRIGGER fail_save");
        }
        assertEquals(2, store().load().rows.length());
        store.save(original, 1);
        ProfileStore.Snapshot restored = store().load();
        assertEquals(original.toString(), restored.rows.toString());
        assertEquals(1, restored.selected);
    }
}
