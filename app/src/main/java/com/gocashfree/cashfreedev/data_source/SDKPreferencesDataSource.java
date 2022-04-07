package com.gocashfree.cashfreedev.data_source;

import android.content.Context;

import java.util.HashMap;

public interface SDKPreferencesDataSource {
    void storeValue(String key, String value);

    String getValue(String key, String defValue);

    void removeValue(String key);

    HashMap<String, String> getprefs();

    void archive(Context context);

    void restore(Context context);

    void storeMap(String key, HashMap<String, String> inputMap);

    HashMap<String, String> getAll();
}
