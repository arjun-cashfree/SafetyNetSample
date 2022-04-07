package com.gocashfree.cashfreedev;

import android.app.Activity;
import android.content.Context;
import android.util.Log;

import androidx.annotation.NonNull;

import com.gocashfree.cashfreedev.rest.APIErrorListener;
import com.gocashfree.cashfreedev.rest.APISuccessListener;
import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.GoogleApiAvailability;
import com.google.android.gms.common.api.ApiException;
import com.google.android.gms.safetynet.SafetyNet;
import com.google.android.gms.safetynet.SafetyNetApi;
import com.google.android.gms.tasks.OnFailureListener;
import com.google.android.gms.tasks.OnSuccessListener;

public class GoogleSafetyNetAPI {

    public void generateSafetyNetToken(Context context, String API_KEY, String nonce, APISuccessListener successListener, APIErrorListener errorListener) {
        if (GoogleApiAvailability.getInstance()
                .isGooglePlayServicesAvailable(context, 13000000) ==
                ConnectionResult.SUCCESS) {
            SafetyNet.getClient(context).attest(nonce.getBytes(), API_KEY)
                    .addOnSuccessListener((Activity) context,
                            new OnSuccessListener<SafetyNetApi.AttestationResponse>() {
                                @Override
                                public void onSuccess(SafetyNetApi.AttestationResponse response) {
                                    successListener.onSuccess(response.getJwsResult(), "");
                                }
                            })
                    .addOnFailureListener((Activity) context, new OnFailureListener() {
                        @Override
                        public void onFailure(@NonNull Exception e) {
                            if (e.getMessage() != null) {
                                // An error occurred while communicating with the service.
                                if (e instanceof ApiException) {
                                    ApiException apiException = (ApiException) e;
                                    errorListener.onError(e.getMessage());
                                } else {
                                    // A different, unknown type of error occurred.
                                    errorListener.onError(e.getMessage());
                                    Log.d(GoogleSafetyNetAPI.class.getName(), "Error: " + e.getMessage());
                                }
                            } else {
                                errorListener.onError("unknown type of error occurred");
                                Log.d(GoogleSafetyNetAPI.class.getName(), "Error: unknown type of error occurred");
                            }
                        }
                    });

        }
    }
}
