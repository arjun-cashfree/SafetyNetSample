package com.gocashfree.cashfreedev.rest;

import android.util.Log;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class CFExecutorService {

    private static String TAG = CFExecutorService.class.getSimpleName();

    private static CFExecutorService INSTANCE;
    private ExecutorService executor;
    private CFRestImpl cfRestImpl;

    public static CFExecutorService getInstance() {
        if (INSTANCE == null) {
            INSTANCE = new CFExecutorService();
            INSTANCE.initialize();
        }
        return INSTANCE;
    }

    private void initialize() {
        executor = Executors.newSingleThreadExecutor();
        cfRestImpl = new CFRestImpl();
    }

    public void executeCertPinnedPostRequest(final String api,
                                   final String body,
                                   final String xCorrID,
                                   final APISuccessListener apiSuccessListener,
                                   final APIErrorListener errorListener) {

        if (executor != null && cfRestImpl != null) {
            executor.execute(new Runnable() {
                @Override
                public void run() {
                    if (xCorrID == null) {
                        cfRestImpl.makePOSTRequest(api, body, apiSuccessListener, errorListener);
                    } else {
                        cfRestImpl.makePOSTRequest(api, body, xCorrID, apiSuccessListener, errorListener);
                    }
                }
            });
        } else {
            Log.d(TAG, "Error initializing  CFExecutorService or CFRestImpl");
        }
    }

}
