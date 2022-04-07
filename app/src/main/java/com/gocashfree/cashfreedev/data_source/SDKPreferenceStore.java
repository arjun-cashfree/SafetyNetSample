package com.gocashfree.cashfreedev.data_source;

import android.content.Context;
import android.util.Log;


import java.util.HashMap;
import java.util.Map;

public class SDKPreferenceStore implements SDKPreferencesDataSource {
    private static SDKPreferenceStore instance;
    private final String TAG = "CustomStorage";
    private HashMap<String, String> sdkPrefs = new HashMap<>();

    private SDKPreferenceStore() {
    }

    synchronized public static SDKPreferenceStore getInstance() {
        if (instance == null) {
            // if instance is null, initialize
            instance = new SDKPreferenceStore();
        }
        return instance;
    }

    @Override
    public void storeValue(String key, String value) {
        sdkPrefs.put(key, value);
    }

    @Override
    public String getValue(String key, String defValue) {
        String val = sdkPrefs.get(key);
        if (val == null) {
            return defValue;
        }
        return val;
    }

    @Override
    public void removeValue(String key) {
        sdkPrefs.remove(key);
    }

    @Override
    public HashMap<String, String> getprefs() {
        return sdkPrefs;
    }

    @Override
    public void archive(Context context) {
        Log.e(TAG, "deserialize");
        EncryptedSharedPreferences.Editor editor = EncryptedSharedPreferences.getPreferences(context).edit();
        editor.clear();
        for (Map.Entry<String, String> entry : sdkPrefs.entrySet()) {
            editor.putString(entry.getKey(), entry.getValue());
        }
        editor.commit();
    }


    @Override
    public void restore(Context context) {
        Log.e(TAG, "serialize");
        EncryptedSharedPreferences sharedPreferences = EncryptedSharedPreferences.getPreferences(context);
        HashMap<String, String> map = new HashMap<>();
        for (HashMap.Entry<String, Object> entry : sharedPreferences.getAll().entrySet()) {
            map.put(entry.getKey(), String.valueOf(entry.getValue()));
        }
        map.putAll(sdkPrefs);
        sdkPrefs.putAll(map);
    }

    @Override
    public void storeMap(String key, HashMap<String, String> inputMap) {
        sdkPrefs.putAll(inputMap);
    }

    @Override
    public HashMap<String, String> getAll() {
        return sdkPrefs;
    }


    public void clearAllValues(Context context) {
        EncryptedSharedPreferences sharedPreferences = EncryptedSharedPreferences.getPreferences(context);
        EncryptedSharedPreferences.Editor editor = sharedPreferences.edit();
        sdkPrefs.clear();
        editor.clear();
        editor.commit();
    }
}
