package com.gocashfree.cashfreedev.rest;

import android.util.Log;


import java.util.HashMap;
import java.util.Map;

class BaseApi {
    private static final String TAG = "BaseApi";
    private static final String PROD_BASE_URL = "https://www.cashfree.com/";
    private static final String TEST_BASE_URL = "https://test.cashfree.com/";
    private static final String BEARER = "Bearer ";
    private static final String AUTHORIZATION = "Authorization";
    static final String BILLPAY = "billpay/";

    private CFExecutorService instance;

    CFExecutorService geCFExecutor() {
        if (instance == null) {
            instance = CFExecutorService.getInstance();
        }
        return instance;
    }

    Map<String, String> getHeaders(String token) {
        String bearer = BEARER.concat(token);
        Map<String, String> headers = new HashMap<>();
        headers.put(AUTHORIZATION, bearer);
        Log.d(TAG, String.format("%s :%s", AUTHORIZATION, bearer));
        return headers;
    }

    String getBaseUrl(String stage) {
        if ("TEST".equals(stage)) {
            return TEST_BASE_URL;
        }//For now keeping prod url as default
        return PROD_BASE_URL;
    }
}
