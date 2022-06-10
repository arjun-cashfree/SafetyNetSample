package com.gocashfree.cashfreedev;

import static com.gocashfree.cashfreedev.EncryptionUtils.visaPublicKey;

import android.annotation.SuppressLint;
import android.content.Context;
import android.os.AsyncTask;
import android.os.Build;
import android.os.Bundle;
import android.os.Process;
import android.provider.Settings;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.webkit.ValueCallback;
import android.webkit.WebResourceRequest;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AppCompatActivity;

import com.gocashfree.cashfreedev.rest.APIErrorListener;
import com.gocashfree.cashfreedev.rest.APISuccessListener;
import com.gocashfree.cashfreedev.rest.DeviceEnrollmentAPI;
import com.gocashfree.cashfreedev.rest.DeviceValidationAPI;
import com.google.android.gms.safetynet.SafetyNetApi;
import com.nimbusds.jose.JOSEException;
import com.visa.app.vbaagent.core.OnVBAAgentEventListener;
import com.visa.app.vbaagent.core.VBAAgent;
import com.visa.app.vbaagent.core.VBAAgentConfig;
import com.visa.app.vbaagent.core.VBAEnvironment;

import org.jose4j.lang.JoseException;
import org.json.JSONException;
import org.json.JSONObject;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;
import org.xmlpull.v1.XmlPullParserFactory;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.List;
import java.util.UUID;
import java.util.zip.DataFormatException;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.GZIPInputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

public class MainActivity extends AppCompatActivity {
    Button button;
    EditText paresTxt;
    EditText tokenTxt;
    private Button signParesBtn;
    private Button idTokenBtn;

    String authCode;
    String xCorrID;
    String vDeviceId;
    String signedAuthCode;
    String signedDeviceID;
    String encryptedAuthCode;

    WebView webView;
    private String termURL = "";
    private boolean listenForTermURL = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        button = findViewById(R.id.button);
        signParesBtn = findViewById(R.id.signedParesBtn);
        idTokenBtn = findViewById(R.id.idTokenBtn);
        paresTxt = findViewById(R.id.paresTxt);
        tokenTxt = findViewById(R.id.idTokenTxt);
        webView = findViewById(R.id.webview);
        webView.getSettings().setJavaScriptEnabled(true);
//        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.ECLAIR_MR1) {
//            webView.getSettings().setDomStorageEnabled(true);
//        }
        webView.setWebViewClient(new WebViewClient() {
            @Override
            public void onPageFinished(WebView view, String url) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
                    webView.evaluateJavascript("window.VSCPaymentControllerBridge.onUrlChange(window.location.href);')", new ValueCallback<String>() {
                        @Override
                        public void onReceiveValue(String s) {
                            // Checkout page starts verifying the payment
                            Log.d("TAG", s);
                        }
                    });
                }
            };

            @Override
            public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                    Log.d("------", request.getUrl().toString());
                }
                return super.shouldOverrideUrlLoading(view, request);
            }

            @Override
            public boolean shouldOverrideUrlLoading(WebView view, String url) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                    Log.d("------1", url);
                }
                return super.shouldOverrideUrlLoading(view, url);
            }

            @Override
            public void doUpdateVisitedHistory(WebView view, String url, boolean isReload) {
                super.doUpdateVisitedHistory(view, url, isReload);
                Log.d("-----", url);
                if(listenForTermURL && url.startsWith(termURL)) {
                    Log.e("termURL with PaRes", url);
                    String base64EncodedPares = url.split("\\?")[1].split("&")[1];
                    try {

                        JSONObject pares = new JSONObject();
                        pares.put("cavv", "");
                        pares.put("eciflag", "05");
                        pares.put("xid", "");
                        pares.put("paresstatus", "Y");
                        pares.put("signatureverification", "Y");

                        String urlDecodedStr = URLDecoder.decode((base64EncodedPares));
                        System.out.println("urlDecodedStr ::\n" + (urlDecodedStr));
                        byte[] base64DecodedStr = new byte[0];
                        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.FROYO) {
                            base64DecodedStr = Base64.decode(urlDecodedStr, Base64.DEFAULT);
                        }
                        String paresStr = decompressToString(base64DecodedStr);
                        System.out.println(paresStr);
                        JSONObject jsonObject = parseXML(paresStr);
                        System.out.println(jsonObject.toString());
                        String signedPares = EncryptionUtils.generateJWS(paresTxt.getText().toString());
                        System.out.println("signedPares\t:" + signedPares);
                        String encryptedPares = EncryptionUtils.generateJWE(signedPares, visaPublicKey);
                        System.out.println("encryptedPares\t:" + encryptedPares);
                        System.out.println("visaPublicKey\t:" + visaPublicKey);
                        new DeviceValidationAPI().validateDevice(signedDeviceID, vDeviceId, encryptedAuthCode, encryptedPares, xCorrID, new APISuccessListener() {
                            @Override
                            public void onSuccess(String response, String headers) {
                                setClipboard(MainActivity.this, response + "\nSignedPares:\t" + signedPares);
                                Log.d(DeviceValidationAPI.class.getName() + " response:", response);
                            }
                        }, new APIErrorListener() {
                            @Override
                            public void onError(String error) {
                                Log.d(DeviceValidationAPI.class.getName() + " error:", error);
                                setClipboard(MainActivity.this, error);
                            }
                        });
//                        setClipboard(MainActivity.this, EncryptionUtils.generateJWS(paresTxt.getText().toString()));
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }
        });
        webView.addJavascriptInterface(new JSInterface(), "VSCPaymentControllerBridge");
        webView.loadUrl("https://payments.cashfree.com/order/#diHTNQptPt9AvwIjBKRH");
        button.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                button.setEnabled(false);
                String nonce = Calendar.getInstance().getTimeInMillis() + "nonce";
                Log.d(MainActivity.class.getName() + "\t nonce", nonce);
                new GoogleSafetyNetAPI().generateSafetyNetToken(MainActivity.this, "AIzaSyAOIJhdoCME7oMIerSgIYb5p7FmnCf7_5c", nonce, new APISuccessListener() {
                    @RequiresApi(api = Build.VERSION_CODES.HONEYCOMB)
                    @Override
                    public void onSuccess(String response, String headers) {
//                        Log.d(MainActivity.class.getName()+"\t safetynet response", response);
                        AsyncTask.execute(new Runnable() {
                            public void run() {
                                Process.setThreadPriority(Process.THREAD_PRIORITY_BACKGROUND);

                                try {
                                    new DeviceEnrollmentAPI().enrollDevice(EncryptionUtils.generateJWE(
                                            EncryptionUtils.generateJWS(
                                                    Settings.Secure.getString(getApplicationContext().getContentResolver(), Settings.Secure.ANDROID_ID),
                                                    String.format("%d", Calendar.getInstance().getTimeInMillis()),
                                                    response)
                                    ), new APISuccessListener() {
                                        @Override
                                        public void onSuccess(String response1, String headers) {
//                                        Log.d("DeviceEnrollmentAPI :", response1);
                                            try {
                                                xCorrID = headers;
                                                JSONObject jsonObject = new JSONObject(response1);
                                                String payload = EncryptionUtils.decrypt(jsonObject.getString("data"));
                                                JSONObject plObj = new JSONObject(payload);
                                                authCode = plObj.getString("authCode");
                                                vDeviceId = plObj.getString("vDeviceId");
                                                signedAuthCode = EncryptionUtils.generateJWS(authCode);
                                                signedDeviceID = EncryptionUtils.generateJWS(vDeviceId);
                                                EncryptionUtils.setVisaDevicePublicKey(plObj.getJSONObject("publicKey").getString("publicKey"));
                                                encryptedAuthCode = EncryptionUtils.generateJWE(signedAuthCode, plObj.getJSONObject("publicKey").getString("publicKey"));

                                                JSONObject result = new JSONObject();
                                                result.put("encryptedAuthCode", encryptedAuthCode);
                                                result.put("authCode", authCode);
                                                result.put("signedDeviceID", signedDeviceID);
                                                result.put("deviceID", vDeviceId);
                                                result.put("X-CORRELATION-ID", xCorrID);
                                                System.out.println(result.toString());
                                                setClipboard(MainActivity.this, result.toString());
                                                button.setEnabled(true);
                                                signParesBtn.setEnabled(true);

                                                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
                                                    webView.evaluateJavascript("window.startVSCEnrollment('1635927013','"+signedDeviceID+"','"+encryptedAuthCode+"','"+xCorrID+"')", new ValueCallback<String>() {
                                                        @Override
                                                        public void onReceiveValue(String s) {
                                                            // Checkout page starts verifying the payment
                                                            Log.d("TAG", s);
                                                        }
                                                    });
                                                }
                                            } catch (JSONException | NoSuchAlgorithmException | GenericSecurityException e) {
                                                e.printStackTrace();
                                                button.setEnabled(true);
                                                signParesBtn.setEnabled(false);
                                            } catch (IOException e) {
                                                e.printStackTrace();
                                                signParesBtn.setEnabled(false);
                                            } catch (JoseException e) {
                                                e.printStackTrace();
                                                signParesBtn.setEnabled(false);
                                            } catch (InvalidKeySpecException e) {
                                                e.printStackTrace();
                                                signParesBtn.setEnabled(false);
                                            }
                                        }
                                    }, new APIErrorListener() {
                                        @Override
                                        public void onError(String error) {
                                            Log.e("DeviceEnrollmentAPI :", error);
                                            button.setEnabled(true);
                                            signParesBtn.setEnabled(false);
                                        }
                                    });
                                } catch (NoSuchAlgorithmException | JoseException | IOException | InvalidKeySpecException e) {
                                    e.printStackTrace();
                                    button.setEnabled(true);
                                    signParesBtn.setEnabled(false);
                                }
                            }
                        });

                    }
                }, new APIErrorListener() {
                    @Override
                    public void onError(String error) {
                        Log.e(MainActivity.class.getName() + "\t safetynet error", error);
                        button.setEnabled(true);
                        signParesBtn.setEnabled(false);
                    }
                });
            }
        });
        signParesBtn.setOnClickListener(new View.OnClickListener() {
            @SuppressLint("NewApi")
            @Override
            public void onClick(View view) {
                if (paresTxt.getText().toString().isEmpty()) {
                    Toast.makeText(MainActivity.this, "Pares is empty", Toast.LENGTH_SHORT).show();
                } else {
                    try {

                        JSONObject pares = new JSONObject();
                        pares.put("cavv", "");
                        pares.put("eciflag", "05");
                        pares.put("xid", "");
                        pares.put("paresstatus", "Y");
                        pares.put("signatureverification", "Y");

                        String urlDecodedStr = URLDecoder.decode((paresTxt.getText().toString()));
                        System.out.println("urlDecodedStr ::\n" + (urlDecodedStr));
                        byte[] base64DecodedStr = Base64.decode(urlDecodedStr, Base64.DEFAULT);
                        String paresStr = decompressToString(base64DecodedStr);
                        System.out.println(paresStr);
                        JSONObject jsonObject = parseXML(paresStr);
                        System.out.println(jsonObject.toString());
                        /*
                        String signedPares = EncryptionUtils.generateJWS(paresTxt.getText().toString());
                        System.out.println("signedPares\t:" + signedPares);
                        String encryptedPares = EncryptionUtils.generateJWE(signedPares, visaPublicKey);
                        System.out.println("encryptedPares\t:" + encryptedPares);
                        System.out.println("visaPublicKey\t:" + visaPublicKey);
                        new DeviceValidationAPI().validateDevice(signedDeviceID, vDeviceId, encryptedAuthCode, encryptedPares, xCorrID, new APISuccessListener() {
                            @Override
                            public void onSuccess(String response, String headers) {
                                setClipboard(MainActivity.this, response + "\nSignedPares:\t" + signedPares);
                                Log.d(DeviceValidationAPI.class.getName() + " response:", response);

                            }
                        }, new APIErrorListener() {
                            @Override
                            public void onError(String error) {
                                Log.d(DeviceValidationAPI.class.getName() + " error:", error);
                                setClipboard(MainActivity.this, error);
                            }
                        });*/
//                        setClipboard(MainActivity.this, EncryptionUtils.generateJWS(paresTxt.getText().toString()));
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }
        });
        idTokenBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {

                try {
                    String idToken = EncryptionUtils.digestJWS(EncryptionUtils.decryptJWE(tokenTxt.getText().toString(), EncryptionUtils.privateKey));

                    long timeInMillis = Calendar.getInstance().getTimeInMillis();
                    String nonce = timeInMillis + "";
                    new GoogleSafetyNetAPI().generateSafetyNetToken(MainActivity.this, "AIzaSyAOIJhdoCME7oMIerSgIYb5p7FmnCf7_5c", nonce, new APISuccessListener() {
                        @Override
                        public void onSuccess(String response, String headers) {
                            try {
                                String jws = EncryptionUtils.generateJWSFromDPrivateKey(idToken, nonce, response);
                                String jwe = EncryptionUtils.generateJWE(jws, visaPublicKey);
                                setClipboard(MainActivity.this, "Encrypted ID Token: " + jwe);
                            } catch (JSONException | NoSuchAlgorithmException | JoseException | IOException | InvalidKeySpecException e) {
                                e.printStackTrace();
                            }
                        }
                    }, new APIErrorListener() {
                        @Override
                        public void onError(String error) {
                            System.out.println("Error ::" + error);
                        }
                    });
                } catch (ParseException | JOSEException e) {
                    e.printStackTrace();
                }
            }
        });
    }

    public static void setClipboard(Context context, String text) {
        if (android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.HONEYCOMB) {
            android.text.ClipboardManager clipboard = (android.text.ClipboardManager) context.getSystemService(Context.CLIPBOARD_SERVICE);
            clipboard.setText(text);
        } else {
            android.content.ClipboardManager clipboard = (android.content.ClipboardManager) context.getSystemService(Context.CLIPBOARD_SERVICE);
            android.content.ClipData clip = android.content.ClipData.newPlainText("Copied Text", text);
            clipboard.setPrimaryClip(clip);
        }
    }

    public static JSONObject parseXML(String paresStr) {
        JSONObject pares = new JSONObject();
        try {
            XmlPullParserFactory factory = XmlPullParserFactory.newInstance();
            factory.setNamespaceAware(true);
            XmlPullParser  parser = factory.newPullParser();

            parser.setInput(new StringReader(paresStr));

            int eventType = parser.getEventType();
            String text ="";
            while (eventType != XmlPullParser.END_DOCUMENT) {
                String tagname = parser.getName();
                switch (eventType) {
                    case XmlPullParser.TEXT:
                        text = parser.getText();
                        break;
                    case XmlPullParser.END_TAG:
                        if (tagname.equalsIgnoreCase("cavv")) {
                            pares.put("cavv", text);
                        }  else if (tagname.equalsIgnoreCase("eci")) {
                            pares.put("eciflag", text);
                        }  else if (tagname.equalsIgnoreCase("xid")) {
                        pares.put("xid", text);
                    }
                        break;

                    default:
                        break;
                }
                eventType = parser.next();
            }
            pares.put("paresstatus", "Y");
            pares.put("signatureverification", "Y");
        } catch (XmlPullParserException | IOException | JSONException e) {e.printStackTrace();}
        return pares;
    }

    public static byte[] decompress(byte[] bytesToDecompress) {
        byte[] returnValues = null;

        Inflater inflater = new Inflater();

        int numberOfBytesToDecompress = bytesToDecompress.length;

        inflater.setInput
                (
                        bytesToDecompress,
                        0,
                        numberOfBytesToDecompress
                );

        int bufferSizeInBytes = numberOfBytesToDecompress;

        int numberOfBytesDecompressedSoFar = 0;
        List<Byte> bytesDecompressedSoFar = new ArrayList<Byte>();

        try {
            while (inflater.needsInput() == false) {
                byte[] bytesDecompressedBuffer = new byte[bufferSizeInBytes];

                int numberOfBytesDecompressedThisTime = inflater.inflate
                        (
                                bytesDecompressedBuffer
                        );

                numberOfBytesDecompressedSoFar += numberOfBytesDecompressedThisTime;

                for (int b = 0; b < numberOfBytesDecompressedThisTime; b++) {
                    bytesDecompressedSoFar.add(bytesDecompressedBuffer[b]);
                }
            }

            returnValues = new byte[bytesDecompressedSoFar.size()];
            for (int b = 0; b < returnValues.length; b++) {
                returnValues[b] = (byte) (bytesDecompressedSoFar.get(b));
            }

        } catch (DataFormatException dfe) {
            dfe.printStackTrace();
        }

        inflater.end();

        return returnValues;
    }

    public static String decompressToString(byte[] bytesToDecompress) {
        byte[] bytesDecompressed = decompress
                (
                        bytesToDecompress
                );

        String returnValue = null;

        try {
            returnValue = new String
                    (
                            bytesDecompressed,
                            0,
                            bytesDecompressed.length,
                            "UTF-8"
                    );
        } catch (UnsupportedEncodingException uee) {
            uee.printStackTrace();
        }

        return returnValue;
    }

    public void onVBAButtonClicker(View view) {
        if (android.os.Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {

            final String sessionID = UUID.randomUUID().toString();
            String service = "VSC";
            String merchantId = "com.gocashfree.cashfreedev";
// Initialize agent
            VBAAgentConfig config = new VBAAgentConfig(sessionID, service, merchantId,
                    VBAEnvironment.PRODUCTION_INDIA);
            VBAAgent agent = new VBAAgent(MainActivity.this, config);
// Begin profiling
            agent.profile(new OnVBAAgentEventListener() {
                @Override
                public void onSuccess() {
                        Log.d("VBAAgent", "onSuccess");
                AsyncTask.execute(new Runnable() {
                    public void run() {
                        android.os.Process.setThreadPriority(android.os.Process.THREAD_PRIORITY_BACKGROUND);

                        try {
                            new DeviceEnrollmentAPI().enrollDevice(EncryptionUtils.generateJWE(
                                    EncryptionUtils.generateJWSVBA(
                                            Settings.Secure.getString(getApplicationContext().getContentResolver(), Settings.Secure.ANDROID_ID),
                                            sessionID)
                            ), new com.gocashfree.cashfreedev.rest.APISuccessListener() {
                                @Override
                                public void onSuccess(String response1, String headers) {
                                        Log.d("DeviceEnrollmentAPI :", response1);
                                        Log.d("DeviceEnrllHeaders :", headers);
                                    try {
                                        xCorrID = headers;
                                        JSONObject jsonObject = new JSONObject(response1);
                                        String payload = EncryptionUtils.decrypt(jsonObject.getString("data"));
                                        JSONObject plObj = new JSONObject(payload);
                                        authCode = plObj.getString("authCode");
                                        vDeviceId = plObj.getString("vDeviceId");
                                        signedAuthCode = EncryptionUtils.generateJWS(authCode);
                                        signedDeviceID = EncryptionUtils.generateJWS(vDeviceId);
                                        EncryptionUtils.setVisaDevicePublicKey(plObj.getJSONObject("publicKey").getString("publicKey"));
                                        encryptedAuthCode = EncryptionUtils.generateJWE(signedAuthCode, plObj.getJSONObject("publicKey").getString("publicKey"));

                                        JSONObject result = new JSONObject();
                                        result.put("encryptedAuthCode", encryptedAuthCode);
                                        result.put("authCode", authCode);
                                        result.put("signedDeviceID", signedDeviceID);
                                        result.put("deviceID", vDeviceId);
                                        result.put("X-CORRELATION-ID", xCorrID);
                                        System.out.println(result.toString());
                                        setClipboard(MainActivity.this, result.toString());
                                        button.setEnabled(true);
                                        signParesBtn.setEnabled(true);
                                    } catch (JSONException | NoSuchAlgorithmException | GenericSecurityException e) {
                                        e.printStackTrace();
                                        button.setEnabled(true);
                                        signParesBtn.setEnabled(false);
                                    } catch (IOException e) {
                                        e.printStackTrace();
                                        signParesBtn.setEnabled(false);
                                    } catch (JoseException e) {
                                        e.printStackTrace();
                                        signParesBtn.setEnabled(false);
                                    } catch (InvalidKeySpecException e) {
                                        e.printStackTrace();
                                        signParesBtn.setEnabled(false);
                                    }
                                }
                            }, new com.gocashfree.cashfreedev.rest.APIErrorListener() {
                                @Override
                                public void onError(String error) {
                                    Log.e("DeviceEnrollmentAPI :", error);
                                    button.setEnabled(true);
                                    signParesBtn.setEnabled(false);
                                }
                            });
                        } catch (NoSuchAlgorithmException | JoseException | IOException | InvalidKeySpecException e) {
                            e.printStackTrace();
                            button.setEnabled(true);
                            signParesBtn.setEnabled(false);
                        }
                    }
                });
                }

                @Override
                public void onError(Exception e, int errorCode) {
                    Log.d("VBAAgent", "onError");
                    e.printStackTrace();
// Continue with API flow, and log VBA error with session ID
                }
            });
        }
    }

    public class JSInterface {
        @android.webkit.JavascriptInterface
        public void getEnrollmentInfo (String cardAliasArrayString) {

        }
        @android.webkit.JavascriptInterface
        public void initVSCPayment1(final String cardAlias) {
            Log.d("CardAlias", cardAlias);

            if (android.os.Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {

                final String sessionID = UUID.randomUUID().toString();
                String service = "VSC";
                String merchantId = "com.gocashfree.cashfreedev";
// Initialize agent
                VBAAgentConfig config = new VBAAgentConfig(sessionID, service, merchantId,
                        VBAEnvironment.PRODUCTION_INDIA);
                VBAAgent agent = new VBAAgent(MainActivity.this, config);
// Begin profiling
                agent.profile(new OnVBAAgentEventListener() {
                    @Override
                    public void onSuccess() {
                        Log.d("VBAAgent", "onSuccess");
                        AsyncTask.execute(new Runnable() {
                            public void run() {
                                android.os.Process.setThreadPriority(android.os.Process.THREAD_PRIORITY_BACKGROUND);

                                try {
                                    new DeviceEnrollmentAPI().enrollDevice(cardAlias,
                                            EncryptionUtils.generateJWE(
                                                    EncryptionUtils.generateJWSVBA(
                                                            Settings.Secure.getString(getApplicationContext().getContentResolver(), Settings.Secure.ANDROID_ID),
                                                            sessionID)
                                            ), new com.gocashfree.cashfreedev.rest.APISuccessListener() {
                                                @Override
                                                public void onSuccess(String response1, String headers) {
                                                    Log.d("DeviceEnrollmentAPI :", response1);
                                                    Log.d("DeviceEnrllHeaders :", headers);
                                                    try {
                                                        xCorrID = headers;
                                                        JSONObject jsonObject = new JSONObject(response1);
                                                        String payload = EncryptionUtils.decrypt(jsonObject.getString("data"));
                                                        JSONObject plObj = new JSONObject(payload);
                                                        authCode = plObj.getString("authCode");
                                                        vDeviceId = plObj.getString("vDeviceId");
                                                        signedAuthCode = EncryptionUtils.generateJWS(authCode);
                                                        signedDeviceID = EncryptionUtils.generateJWS(vDeviceId);
                                                        EncryptionUtils.setVisaDevicePublicKey(plObj.getJSONObject("publicKey").getString("publicKey"));
                                                        encryptedAuthCode = EncryptionUtils.generateJWE(signedAuthCode, plObj.getJSONObject("publicKey").getString("publicKey"));

                                                        JSONObject result = new JSONObject();
                                                        result.put("encryptedAuthCode", encryptedAuthCode);
                                                        result.put("authCode", authCode);
                                                        result.put("signedDeviceID", signedDeviceID);
                                                        result.put("deviceID", vDeviceId);
                                                        result.put("X-CORRELATION-ID", xCorrID);
                                                        System.out.println(result.toString());
                                                        setClipboard(MainActivity.this, result.toString());
                                                        button.setEnabled(true);
                                                        signParesBtn.setEnabled(true);
                                                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
                                                            webView.evaluateJavascript("window.startVSCRepeatPayment("+cardAlias+","+signedDeviceID+","+encryptedAuthCode+","+xCorrID+")", new ValueCallback<String>() {
                                                                @Override
                                                                public void onReceiveValue(String s) {
                                                                    // Checkout page starts verifying the payment
                                                                    Log.d("TAG", s);
                                                                }
                                                            });
                                                        }
                                                    } catch (JSONException | NoSuchAlgorithmException | GenericSecurityException e) {
                                                        e.printStackTrace();
                                                        button.setEnabled(true);
                                                        signParesBtn.setEnabled(false);
                                                    } catch (IOException e) {
                                                        e.printStackTrace();
                                                        signParesBtn.setEnabled(false);
                                                    } catch (JoseException e) {
                                                        e.printStackTrace();
                                                        signParesBtn.setEnabled(false);
                                                    } catch (InvalidKeySpecException e) {
                                                        e.printStackTrace();
                                                        signParesBtn.setEnabled(false);
                                                    }
                                                }
                                            }, new com.gocashfree.cashfreedev.rest.APIErrorListener() {
                                                @Override
                                                public void onError(String error) {
                                                    Log.e("DeviceEnrollmentAPI :", error);
                                                    button.setEnabled(true);
                                                    signParesBtn.setEnabled(false);
                                                }
                                            });
                                } catch (NoSuchAlgorithmException | JoseException | IOException | InvalidKeySpecException e) {
                                    e.printStackTrace();
                                    button.setEnabled(true);
                                    signParesBtn.setEnabled(false);
                                }
                            }
                        });
                    }

                    @Override
                    public void onError(Exception e, int errorCode) {
                        Log.d("VBAAgent", "onError");
                        e.printStackTrace();
// Continue with API flow, and log VBA error with session ID
                    }
                });
            }
        }

        @android.webkit.JavascriptInterface
        public void initVSCPayment(final String cardAlias)  {
            button.setEnabled(false);
            String nonce = Calendar.getInstance().getTimeInMillis() + "nonce";
            Log.d(MainActivity.class.getName() + "\t nonce", nonce);
            new GoogleSafetyNetAPI().generateSafetyNetToken(MainActivity.this, "AIzaSyAOIJhdoCME7oMIerSgIYb5p7FmnCf7_5c", nonce, new APISuccessListener() {
                @RequiresApi(api = Build.VERSION_CODES.HONEYCOMB)
                @Override
                public void onSuccess(String response, String headers) {
//                        Log.d(MainActivity.class.getName()+"\t safetynet response", response);
                    AsyncTask.execute(new Runnable() {
                        public void run() {
                            Process.setThreadPriority(Process.THREAD_PRIORITY_BACKGROUND);

                            try {
                                new DeviceEnrollmentAPI().enrollDevice(cardAlias,
                                        EncryptionUtils.generateJWE(
                                        EncryptionUtils.generateJWS(
                                                Settings.Secure.getString(getApplicationContext().getContentResolver(), Settings.Secure.ANDROID_ID),
                                                String.format("%d", Calendar.getInstance().getTimeInMillis()),
                                                response)
                                ), new APISuccessListener() {
                                    @Override
                                    public void onSuccess(String response1, String headers) {
//                                        Log.d("DeviceEnrollmentAPI :", response1);
                                        try {
                                            xCorrID = headers;
                                            JSONObject jsonObject = new JSONObject(response1);
                                            String payload = EncryptionUtils.decrypt(jsonObject.getString("data"));
                                            JSONObject plObj = new JSONObject(payload);
                                            authCode = plObj.getString("authCode");
                                            vDeviceId = plObj.getString("vDeviceId");
                                            signedAuthCode = EncryptionUtils.generateJWS(authCode);
                                            signedDeviceID = EncryptionUtils.generateJWS(vDeviceId);
                                            EncryptionUtils.setVisaDevicePublicKey(plObj.getJSONObject("publicKey").getString("publicKey"));
                                            encryptedAuthCode = EncryptionUtils.generateJWE(signedAuthCode, plObj.getJSONObject("publicKey").getString("publicKey"));

                                            JSONObject result = new JSONObject();
                                            result.put("encryptedAuthCode", encryptedAuthCode);
                                            result.put("authCode", authCode);
                                            result.put("signedDeviceID", signedDeviceID);
                                            result.put("deviceID", vDeviceId);
                                            result.put("X-CORRELATION-ID", xCorrID);
                                            System.out.println(result.toString());
                                            setClipboard(MainActivity.this, result.toString());
                                            button.setEnabled(true);
                                            signParesBtn.setEnabled(true);
                                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
                                                webView.evaluateJavascript("window.startVSCEnrollment('"+cardAlias+"','"+signedDeviceID+"','"+encryptedAuthCode+"','"+xCorrID+"')", new ValueCallback<String>() {
                                                    @Override
                                                    public void onReceiveValue(String s) {
                                                        // Checkout page starts verifying the payment
                                                        Log.d("TAG", s);
                                                    }
                                                });
                                            }
                                        } catch (JSONException | NoSuchAlgorithmException | GenericSecurityException e) {
                                            e.printStackTrace();
                                            button.setEnabled(true);
                                            signParesBtn.setEnabled(false);
                                        } catch (IOException e) {
                                            e.printStackTrace();
                                            signParesBtn.setEnabled(false);
                                        } catch (JoseException e) {
                                            e.printStackTrace();
                                            signParesBtn.setEnabled(false);
                                        } catch (InvalidKeySpecException e) {
                                            e.printStackTrace();
                                            signParesBtn.setEnabled(false);
                                        }
                                    }
                                }, new APIErrorListener() {
                                    @Override
                                    public void onError(String error) {
                                        Log.e("DeviceEnrollmentAPI :", error);
                                        button.setEnabled(true);
                                        signParesBtn.setEnabled(false);
                                    }
                                });
                            } catch (NoSuchAlgorithmException | JoseException | IOException | InvalidKeySpecException e) {
                                e.printStackTrace();
                                button.setEnabled(true);
                                signParesBtn.setEnabled(false);
                            }
                        }
                    });

                }
            }, new APIErrorListener() {
                @Override
                public void onError(String error) {
                    Log.e(MainActivity.class.getName() + "\t safetynet error", error);
                    button.setEnabled(true);
                    signParesBtn.setEnabled(false);
                }
            });
        }

        @android.webkit.JavascriptInterface
        public void initVSCEnrollment(final String cardAlias) {
            Log.d("CardAlias", cardAlias);

        }
        @android.webkit.JavascriptInterface
        public void setVISAStaticKeys(String visaStaticKeysArrayString) {

        }
        @android.webkit.JavascriptInterface
        public void setIDToken(String cardAlias, String idTokenStr) {
            Log.d("setIDToken", cardAlias);

            try {
                String idToken = EncryptionUtils.digestJWS(EncryptionUtils.decryptJWE(idTokenStr, EncryptionUtils.privateKey));

                long timeInMillis = Calendar.getInstance().getTimeInMillis();
                String nonce = timeInMillis + "";
                new GoogleSafetyNetAPI().generateSafetyNetToken(MainActivity.this, "AIzaSyAOIJhdoCME7oMIerSgIYb5p7FmnCf7_5c", nonce, new APISuccessListener() {
                    @Override
                    public void onSuccess(String response, String headers) {
                        try {
                            String jws = EncryptionUtils.generateJWSFromDPrivateKey(idToken, nonce, response);
                            String jwe = EncryptionUtils.generateJWE(jws, visaPublicKey);
                            setClipboard(MainActivity.this, "Encrypted ID Token: " + jwe);
                        } catch (JSONException | NoSuchAlgorithmException | JoseException | IOException | InvalidKeySpecException e) {
                            e.printStackTrace();
                        }
                    }
                }, new APIErrorListener() {
                    @Override
                    public void onError(String error) {
                        System.out.println("Error ::" + error);
                    }
                });
            } catch (ParseException | JOSEException e) {
                e.printStackTrace();
            }
        }

        @android.webkit.JavascriptInterface
        public void setACSEndURL(String url) {
            Log.d("setACSEndURL", url);
            termURL = url;
            listenForTermURL = true;
        }
        @android.webkit.JavascriptInterface
        public void initDisenrollment(String disenrollmentCardAlias) {

        }
        @android.webkit.JavascriptInterface
        public void setVISAMerchantAppID(String appID) {

        }
        @android.webkit.JavascriptInterface
        public void onUrlChange(String url) {
            Log.d("hydrated", "onUrlChange" + url);
        }
    }
}
