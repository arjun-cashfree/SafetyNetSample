package com.gocashfree.cashfreedev.rest;

import androidx.annotation.NonNull;

public interface CFRestInterface {

    void makeCertPinnedPOSTRequest(String url,
                      String body,
                      String pubKey,
                      APISuccessListener apiSuccessListener,
                      APIErrorListener errorListener);

    void makePOSTRequest(@NonNull String api,
                                String bodyParams,
                                final APISuccessListener apiSuccessListener,
                                final APIErrorListener errorListener);

    void makePOSTRequest(@NonNull String api,
                                String bodyParams,
                                String xCorrID,
                                final APISuccessListener apiSuccessListener,
                                final APIErrorListener errorListener);

}
