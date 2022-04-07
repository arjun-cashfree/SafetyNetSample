package com.gocashfree.cashfreedev.rest;

import android.net.http.X509TrustManagerExtensions;
import android.os.Handler;
import android.os.Looper;
import android.util.Base64;
import android.util.Log;


import androidx.annotation.NonNull;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

public class CFRestImpl implements CFRestInterface {

    public static final String APPLICATION_JSON = "application/json";
    private static final String HEADER_CONTENT_TYPE = "Content-Type";
    private static final String HEADER_X_CORRELATION_ID = "X-CORRELATION-ID";
    private static final String DEFAULT_PARAMS_ENCODING = "UTF-8";

    private static final int CF_DEFAULT_READ_TIMEOUT = 10000; // milliseconds
    private static final int CF_DEFAULT_CONNECTION_TIMEOUT = 10000; // milliseconds

    private static String TAG = CFRestImpl.class.getSimpleName();


    @Override
    public void makeCertPinnedPOSTRequest(String api, String body, String pubKey, APISuccessListener apiSuccessListener, APIErrorListener errorListener) {

        Log.d(TAG, "API: " + api);

        HttpsURLConnection httpConnection = null;
        BufferedReader reader = null;
        Handler handler = new Handler(Looper.getMainLooper());
        RetryStrategy retryStrategy = new RetryStrategy();
        while (retryStrategy.shouldRetry()) {
            try {
                URL url = new URL(api);
                httpConnection = (HttpsURLConnection) url.openConnection();
                httpConnection.setRequestMethod("POST");
                httpConnection.setRequestProperty(HEADER_CONTENT_TYPE, APPLICATION_JSON);
                httpConnection.setDoOutput(true);
                httpConnection.setDoInput(true);
                httpConnection.setConnectTimeout(CF_DEFAULT_CONNECTION_TIMEOUT);
                httpConnection.setReadTimeout(CF_DEFAULT_READ_TIMEOUT);


                TrustManagerFactory trustManagerFactory =
                        TrustManagerFactory.getInstance(
                                TrustManagerFactory.getDefaultAlgorithm());
                trustManagerFactory.init((KeyStore) null);
                // Find first X509TrustManager in the TrustManagerFactory
                X509TrustManager x509TrustManager = null;
                for (TrustManager trustManager : trustManagerFactory.getTrustManagers()) {
                    if (trustManager instanceof X509TrustManager) {
                        x509TrustManager = (X509TrustManager) trustManager;
                        break;
                    }
                }
                X509TrustManagerExtensions trustManagerExt =
                        new X509TrustManagerExtensions(x509TrustManager);
                Set<String> validPins = Collections.singleton(pubKey);
                validatePinning(trustManagerExt, httpConnection, validPins);
                // add params to request.
                OutputStreamWriter wr = new OutputStreamWriter(httpConnection.getOutputStream());
                wr.write(body);
                wr.flush();
                wr.close();

                int responseCode = httpConnection.getResponseCode();

                InputStream stream = httpConnection.getInputStream();
                final StringBuilder buffer = new StringBuilder();
                reader = new BufferedReader(new InputStreamReader(stream, "UTF-8"), 8);
                String line;
                while ((line = reader.readLine()) != null) {
                    buffer.append(line);
                }

                Log.d(TAG, "API Response: " + buffer);

                if (responseCode == HttpURLConnection.HTTP_OK) {
                    if (apiSuccessListener != null) {
                        handler.post(new Runnable() {
                            @Override
                            public void run() {
                                apiSuccessListener.onSuccess(buffer.toString(), "");
                            }
                        });
                    }
                } else if (errorListener != null) {
                    handler.post(new Runnable() {
                        @Override
                        public void run() {
                            errorListener.onError(buffer.toString());
                        }
                    });
                }

                // If the  api call received successful response from server,
                // break the while loop. Else it will automatically retry API call.
                break;
            } catch (final Exception e) {
                try {
                    e.printStackTrace();
                    retryStrategy.errorOccurred();
                } catch (Exception ex) {
                    Log.d(TAG, "" + ex.getMessage());
                    e.printStackTrace();
                    if (errorListener != null) {
                        handler.post(new Runnable() {
                            @Override
                            public void run() {
                                errorListener.onError(e.toString());
                            }
                        });
                    } else {
                        errorListener.onError("Something went wrong");
                    }
                }
            } finally {
                Log.d(TAG, "closing httpConnection: ");
                if (httpConnection != null) {
                    httpConnection.disconnect();
                }
                if (reader != null) {
                    try {
                        reader.close();
                    } catch (IOException e) {

                    }
                }
            }
        }

    }

    /**
     * Converts <code>params</code> into an application/x-www-form-urlencoded encoded string.
     */
    private String encodeParameters(Map<String, String> params, String paramsEncoding) {
        Log.d(TAG, "Body");
        StringBuilder encodedParams = new StringBuilder();
        try {
            for (Map.Entry<String, String> entry : params.entrySet()) {
                if (entry.getKey() == null || entry.getValue() == null) {
                    throw new IllegalArgumentException(
                            String.format(
                                    "All keys and values must be non-null.",
                                    entry.getKey(), entry.getValue()));
                }
                Log.d(TAG, String.format("%s : %s", entry.getKey(), entry.getValue()));
                encodedParams.append(URLEncoder.encode(entry.getKey(), paramsEncoding));
                encodedParams.append('=');
                encodedParams.append(URLEncoder.encode(entry.getValue(), paramsEncoding));
                encodedParams.append('&');
            }
            return encodedParams.toString();
        } catch (UnsupportedEncodingException uee) {
            throw new RuntimeException("Encoding not supported: " + paramsEncoding, uee);
        }
    }

    static class RetryStrategy {

        public static final int DEFAULT_RETRIES = 5;
        public static final long DEFAULT_WAIT_TIME_IN_MILLI = 2000;

        private int numberOfRetries;
        private int numberOfTriesLeft;
        private long timeToWait;

        public RetryStrategy() {
            this(DEFAULT_RETRIES, DEFAULT_WAIT_TIME_IN_MILLI);
        }

        public RetryStrategy(int numberOfRetries,
                             long timeToWait) {
            this.numberOfRetries = numberOfRetries;
            numberOfTriesLeft = numberOfRetries;
            this.timeToWait = timeToWait;
        }

        /**
         * @return true if there are tries left
         */
        public boolean shouldRetry() {
            return numberOfTriesLeft > 0;
        }

        public void errorOccurred() throws Exception {
            numberOfTriesLeft--;
            if (!shouldRetry()) {
                throw new Exception("Retry Failed: Total " + numberOfRetries
                        + " attempts made at interval " + getTimeToWait()
                        + "ms");
            }
            Log.d(TAG, "Exception occurred, retrying API call.");
            waitUntilNextTry();
        }

        public long getTimeToWait() {
            return timeToWait;
        }

        private void waitUntilNextTry() {
            try {
                Thread.sleep(getTimeToWait());
            } catch (InterruptedException ignored) {
            }
        }
    }

    private void validatePinning(
            X509TrustManagerExtensions trustManagerExt,
            HttpsURLConnection conn, Set<String> validPins)
            throws SSLException {
        String certChainMsg = "";
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            List<X509Certificate> trustedChain =
                    trustedChain(trustManagerExt, conn);
            for (X509Certificate cert : trustedChain) {
                byte[] publicKey = cert.getPublicKey().getEncoded();
                md.update(publicKey, 0, publicKey.length);
                String pin = Base64.encodeToString(md.digest(),
                        Base64.NO_WRAP);
                certChainMsg += "    sha256/" + pin + " : " +
                        cert.getSubjectDN().toString() + "\n";
                if (validPins.contains(pin)) {
                    return;
                }
            }
        } catch (NoSuchAlgorithmException e) {
            throw new SSLException(e);
        }
        throw new SSLPeerUnverifiedException("Certificate pinning " +
                "failure\n  Peer certificate chain:\n" + certChainMsg);
    }

    private List<X509Certificate> trustedChain(
            X509TrustManagerExtensions trustManagerExt,
            HttpsURLConnection conn) throws SSLException {
        Certificate[] serverCerts = conn.getServerCertificates();
        X509Certificate[] untrustedCerts = Arrays.copyOf(serverCerts,
                serverCerts.length, X509Certificate[].class);
        String host = conn.getURL().getHost();
        try {
            return trustManagerExt.checkServerTrusted(untrustedCerts,
                    "RSA", host);
        } catch (CertificateException e) {
            throw new SSLException(e);
        }
    }


    @Override
    public void makePOSTRequest(@NonNull String api,
                                String bodyParams,
                                final APISuccessListener apiSuccessListener,
                                final APIErrorListener errorListener) {
        Log.d(TAG, "API: " + api);

        HttpsURLConnection httpConnection = null;
        BufferedReader reader = null;
        Handler handler = new Handler(Looper.getMainLooper());
        RetryStrategy retryStrategy = new RetryStrategy();
        while (retryStrategy.shouldRetry()) {
            try {
                URL url = new URL(api);
                httpConnection = (HttpsURLConnection) url.openConnection();
                httpConnection.setRequestMethod("POST");
                httpConnection.setRequestProperty(HEADER_CONTENT_TYPE, APPLICATION_JSON);
                httpConnection.setDoOutput(true);
                httpConnection.setDoInput(true);
                httpConnection.setConnectTimeout(CF_DEFAULT_CONNECTION_TIMEOUT);
                httpConnection.setReadTimeout(CF_DEFAULT_READ_TIMEOUT);

                // add params to request.
                OutputStreamWriter wr = new OutputStreamWriter(httpConnection.getOutputStream());
                wr.write(bodyParams);
                wr.flush();
                wr.close();

                int responseCode = httpConnection.getResponseCode();

                InputStream stream = httpConnection.getInputStream();
                final StringBuilder buffer = new StringBuilder();
                reader = new BufferedReader(new InputStreamReader(stream, "UTF-8"), 8);
                String line;
                while ((line = reader.readLine()) != null) {
                    buffer.append(line);
                }

                Log.d(TAG, "API Response: " + buffer);

                if (responseCode == HttpURLConnection.HTTP_OK) {
                    if (apiSuccessListener != null) {
                        HttpsURLConnection finalHttpConnection = httpConnection;
                        handler.post(new Runnable() {
                            @Override
                            public void run() {
                                apiSuccessListener.onSuccess(buffer.toString(), finalHttpConnection.getHeaderFields().get("X-CORRELATION-ID").get(0));
                            }
                        });
                    }
                } else if (errorListener != null) {
                    handler.post(new Runnable() {
                        @Override
                        public void run() {
                            errorListener.onError(buffer.toString());
                        }
                    });
                }

                // If the  api call received successful response from server,
                // break the while loop. Else it will automatically retry API call.
                break;
            } catch (final Exception e) {
                try {
                    e.printStackTrace();
                    retryStrategy.errorOccurred();
                } catch (Exception ex) {
                    Log.d(TAG, "" + ex.getMessage());
                    e.printStackTrace();
                    if (errorListener != null) {
                        handler.post(new Runnable() {
                            @Override
                            public void run() {
                                errorListener.onError(e.toString());
                            }
                        });
                    } else {
                        errorListener.onError("Something went wrong");
                    }
                }
            } finally {
                Log.d(TAG, "closing httpConnection: ");
                if (httpConnection != null) {
                    httpConnection.disconnect();
                }
                if (reader != null) {
                    try {
                        reader.close();
                    } catch (IOException e) {

                    }
                }
            }
        }

    }

    @Override
    public void makePOSTRequest(@NonNull String api,
                                String bodyParams,
                                String xCorrID,
                                final APISuccessListener apiSuccessListener,
                                final APIErrorListener errorListener) {
        Log.d(TAG, "API: " + api);

        HttpsURLConnection httpConnection = null;
        BufferedReader reader = null;
        Handler handler = new Handler(Looper.getMainLooper());
        RetryStrategy retryStrategy = new RetryStrategy();
        while (retryStrategy.shouldRetry()) {
            try {
                URL url = new URL(api);
                httpConnection = (HttpsURLConnection) url.openConnection();
                httpConnection.setRequestMethod("PUT");
                httpConnection.setRequestProperty(HEADER_CONTENT_TYPE, APPLICATION_JSON);
                httpConnection.setRequestProperty(HEADER_X_CORRELATION_ID, xCorrID);
                httpConnection.setDoOutput(true);
                httpConnection.setDoInput(true);
                httpConnection.setConnectTimeout(CF_DEFAULT_CONNECTION_TIMEOUT);
                httpConnection.setReadTimeout(CF_DEFAULT_READ_TIMEOUT);


                // add params to request.
                OutputStreamWriter wr = new OutputStreamWriter(httpConnection.getOutputStream());
                wr.write(bodyParams);
                wr.flush();
                wr.close();

                int responseCode = httpConnection.getResponseCode();
                InputStream stream;
                if (responseCode == HttpsURLConnection.HTTP_BAD_REQUEST) {
                    stream = httpConnection.getErrorStream();
                } else {
                    stream = httpConnection.getInputStream();
                }
                final StringBuilder buffer = new StringBuilder();
                reader = new BufferedReader(new InputStreamReader(stream, "UTF-8"), 8);
                String line;
                while ((line = reader.readLine()) != null) {
                    buffer.append(line);
                }

                Log.d(TAG, "API Response: " + buffer);

                if (responseCode == HttpURLConnection.HTTP_OK) {
                    if (apiSuccessListener != null) {
                        HttpsURLConnection finalHttpConnection = httpConnection;
                        handler.post(new Runnable() {
                            @Override
                            public void run() {
                                apiSuccessListener.onSuccess(String.format("Request : %s \n Response: %s", bodyParams, buffer.toString()), finalHttpConnection.getHeaderFields().get("X-CORRELATION-ID").get(0));
                            }
                        });
                    }
                } else if (errorListener != null) {
                    handler.post(new Runnable() {
                        @Override
                        public void run() {
                            errorListener.onError(String.format("Request : %s \n Response: %s", bodyParams, buffer.toString()));
                        }
                    });
                }

                // If the  api call received successful response from server,
                // break the while loop. Else it will automatically retry API call.
                break;
            } catch (final Exception e) {
                try {
                    e.printStackTrace();
                    retryStrategy.errorOccurred();
                } catch (Exception ex) {
                    Log.d(TAG, "" + ex.getMessage());
                    e.printStackTrace();
                    if (errorListener != null) {
                        handler.post(new Runnable() {
                            @Override
                            public void run() {
                                errorListener.onError(String.format("Request : %s \n Response: %s", bodyParams, e.toString()));
                            }
                        });
                    } else {
                        errorListener.onError("Something went wrong");
                    }
                }
            } finally {
                Log.d(TAG, "closing httpConnection: ");
                if (httpConnection != null) {
                    httpConnection.disconnect();
                }
                if (reader != null) {
                    try {
                        reader.close();
                    } catch (IOException e) {

                    }
                }
            }
        }

    }
}
