package com.gocashfree.cashfreedev.data_source;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;

import androidx.annotation.Nullable;

import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class EncryptedSharedPreferences {
    private static final String FILENAME = "SdkPrefs";

    private SharedPreferences sharedPreferences;

    private EncryptedSharedPreferences(Context context) {
        sharedPreferences = context.getSharedPreferences(FILENAME, Context.MODE_PRIVATE);
    }

    public static EncryptedSharedPreferences getPreferences(Context context) {
        return new EncryptedSharedPreferences(context);
    }

    @SuppressWarnings("ConstantConditions")
    public Map<String, Object> getAll() {
        Map<String, ?> map = sharedPreferences.getAll();
        HashMap<String, Object> output = new HashMap<>();
        for (String key : map.keySet()) {
            output.put(decrypt(key), decrypt((String) map.get(key)));
        }
        return output;
    }

    @Nullable
    public String getString(String key, @Nullable String defValue) {
        String value = sharedPreferences.getString(encrypt(key), null);
        if (value == null)
            return defValue;
        return decrypt(value);
    }

    @Nullable
    public Set<String> getStringSet(String key, @Nullable Set<String> defValues) {
        Set<String> value = sharedPreferences.getStringSet(encrypt(key), null);
        if (value == null)
            return defValues;
        return decrypt(value);
    }


    public int getInt(String key, int defValue) {
        String value = sharedPreferences.getString(encrypt(key), null);
        if (value == null)
            return defValue;
        return Integer.parseInt(decrypt(value));
    }


    public long getLong(String key, long defValue) {
        String value = sharedPreferences.getString(encrypt(key), null);
        if (value == null)
            return defValue;
        return Long.parseLong(decrypt(value));
    }


    public float getFloat(String key, float defValue) {
        String value = sharedPreferences.getString(encrypt(key), null);
        if (value == null)
            return defValue;
        return Float.parseFloat(decrypt(value));
    }


    public boolean getBoolean(String key, boolean defValue) {
        String value = sharedPreferences.getString(encrypt(key), null);
        if (value == null)
            return defValue;
        return Boolean.parseBoolean(decrypt(value));
    }


    public boolean contains(String key) {
        return sharedPreferences.contains(encrypt(key));
    }


    public Editor edit() {
        return new Editor();
    }

    private String encrypt(String value) {
        return Base64.encodeToString(value.getBytes(Charset.defaultCharset()), Base64.NO_WRAP);
    }

    private String decrypt(String value) {
        return new String(Base64.decode(value.getBytes(Charset.defaultCharset()), Base64.NO_WRAP));
    }

    private Set<String> encrypt(Set<String> value) {
        Set<String> output = new HashSet<>();
        for (String entry : value) {
            output.add(encrypt(entry));
        }
        return output;
    }

    private Set<String> decrypt(Set<String> value) {
        Set<String> output = new HashSet<>();
        for (String entry : value) {
            output.add(decrypt(entry));
        }
        return output;
    }

    public class Editor {
        private SharedPreferences.Editor editor;

        @SuppressLint("CommitPrefEdits")
        private Editor() {
            editor = sharedPreferences.edit();
        }

        public SharedPreferences.Editor putString(String key, @Nullable String value) {
            return editor.putString(encrypt(key), (value == null) ? null : encrypt(value));
        }


        public SharedPreferences.Editor putStringSet(String key, @Nullable Set<String> values) {
            return editor.putStringSet(encrypt(key), (values == null) ? null : encrypt(values));
        }


        public SharedPreferences.Editor putInt(String key, int value) {
            return editor.putString(encrypt(key), encrypt(String.valueOf(value)));
        }


        public SharedPreferences.Editor putLong(String key, long value) {
            return editor.putString(encrypt(key), encrypt(String.valueOf(value)));
        }


        public SharedPreferences.Editor putFloat(String key, float value) {
            return editor.putString(encrypt(key), encrypt(String.valueOf(value)));
        }


        public SharedPreferences.Editor putBoolean(String key, boolean value) {
            return editor.putString(encrypt(key), encrypt(String.valueOf(value)));
        }


        public SharedPreferences.Editor remove(String key) {
            return editor.remove(encrypt(key));
        }


        public SharedPreferences.Editor clear() {
            return editor.clear();
        }


        public boolean commit() {
            return editor.commit();
        }


        public void apply() {
            editor.apply();
        }
    }
}
