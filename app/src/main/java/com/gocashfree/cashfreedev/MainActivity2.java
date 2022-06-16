package com.gocashfree.cashfreedev;

import static com.gocashfree.cashfreedev.EncryptionUtils.sharedPreferences;
import static com.gocashfree.cashfreedev.EncryptionUtils.visaPublicKey;
import static com.gocashfree.cashfreedev.MainActivity.decompressToString;
import static com.gocashfree.cashfreedev.MainActivity.parseXML;
import static com.gocashfree.cashfreedev.MainActivity.setClipboard;

import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AppCompatActivity;

import android.annotation.SuppressLint;
import android.os.AsyncTask;
import android.os.Build;
import android.os.Bundle;
import android.os.Process;
import android.provider.Settings;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.webkit.ValueCallback;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import com.gocashfree.cashfreedev.data_source.EncryptedSharedPreferences;
import com.gocashfree.cashfreedev.rest.APIErrorListener;
import com.gocashfree.cashfreedev.rest.APISuccessListener;
import com.gocashfree.cashfreedev.rest.DeviceEnrollmentAPI;
import com.gocashfree.cashfreedev.rest.DeviceValidationAPI;
import com.nimbusds.jose.JOSEException;
import com.visa.app.vbaagent.core.OnVBAAgentEventListener;
import com.visa.app.vbaagent.core.VBAAgent;
import com.visa.app.vbaagent.core.VBAAgentConfig;
import com.visa.app.vbaagent.core.VBAEnvironment;

import org.jose4j.lang.JoseException;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.util.Calendar;
import java.util.UUID;

public class MainActivity2 extends AppCompatActivity {
    EditText urlTxt;
    Button browseBtn;
    WebView webView;

    String authCode;
    String xCorrID;
    String vDeviceId;
    String signedAuthCode;
    String signedDeviceID;
    String encryptedAuthCode;
    static String cardAlias;
    private Button clearBtn;
    private EncryptedSharedPreferences encryptedSharedPref;

    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main2);
        urlTxt = findViewById(R.id.checkoutURL);
        browseBtn = findViewById(R.id.browseBtn);
        clearBtn = findViewById(R.id.clearBtn);
        webView = findViewById(R.id.webview);
        webView.setWebContentsDebuggingEnabled(true);
        webView.getSettings().setJavaScriptEnabled(true);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.ECLAIR_MR1) {
            webView.getSettings().setDomStorageEnabled(true);
        }
        encryptedSharedPref = EncryptedSharedPreferences.getPreferences(MainActivity2.this);
        webView.addJavascriptInterface(new MainActivity2.JSInterface(), "VSCPaymentControllerBridge");
        webView.loadUrl("https://12be-119-82-99-242.ngrok.io/billpay/resources/vsctest");
        browseBtn.setOnClickListener(new View.OnClickListener() {
            @SuppressLint("NewApi")
            @Override
            public void onClick(View view) {
                if (!urlTxt.getText().toString().isEmpty())
                    webView.loadUrl(urlTxt.getText().toString());
                else
                    Toast.makeText(MainActivity2.this, "url empty", Toast.LENGTH_SHORT).show();
            }
        });
        clearBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                urlTxt.setText("");
            }
        });
    }

    public class JSInterface {
        @android.webkit.JavascriptInterface
        public String getEnrollmentInfo (String cardAliasArrayString) {
            Log.d("getEnrollmentInfo", cardAlias);
            try {
                JSONArray jsonArray = new JSONArray(cardAliasArrayString);
                JSONObject resultObj = new JSONObject();
                for (int i = 0; i < jsonArray.length(); i++) {
                    if (sharedPreferences.contains(jsonArray.getString(i))) {
                        resultObj.put(jsonArray.getString(i), true);
                    } else {
                        resultObj.put(jsonArray.getString(i), true);
                    }
                }
                System.out.println(resultObj.toString());
                return resultObj.toString();
            } catch (JSONException e) {
                e.printStackTrace();
            }
            return null;
        }

        @android.webkit.JavascriptInterface
        public void initVSCPayment(final String cardAlias)  {
            Log.d("initVSCPayment", cardAlias);
            String idToken = sharedPreferences.getString(cardAlias, "");
            long timeInMillis = Calendar.getInstance().getTimeInMillis();
            String nonce = timeInMillis + "";
            new GoogleSafetyNetAPI().generateSafetyNetToken(MainActivity2.this, "AIzaSyAOIJhdoCME7oMIerSgIYb5p7FmnCf7_5c", nonce, new APISuccessListener() {
                @Override
                public void onSuccess(String response, String headers) {
                    try {
                        String jws = EncryptionUtils.generateJWSFromDPrivateKey(idToken, nonce, response);
                        String jwe = EncryptionUtils.generateJWE(jws, visaPublicKey);
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
                            webView.evaluateJavascript(String.format("window.startVSCRepeatPayment('%s','%s','%s')", cardAlias, signedDeviceID, jwe), new ValueCallback<String>() {
                                @Override
                                public void onReceiveValue(String s) {
                                    // Checkout page starts verifying the payment
                                    Log.d("TAG", s);
                                }
                            });
                        }
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
        }

        @android.webkit.JavascriptInterface
        public void initVSCEnrollment(final String cardAlias) {
            Log.d("CardAlias", cardAlias);
            MainActivity2.cardAlias = cardAlias;
            String nonce = Calendar.getInstance().getTimeInMillis() + "nonce";
            Log.d(MainActivity.class.getName() + "\t nonce", nonce);
            new GoogleSafetyNetAPI().generateSafetyNetToken(MainActivity2.this, "AIzaSyAOIJhdoCME7oMIerSgIYb5p7FmnCf7_5c", nonce, new APISuccessListener() {
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
                                                } catch (IOException e) {
                                                    e.printStackTrace();
                                                } catch (JoseException e) {
                                                    e.printStackTrace();
                                                } catch (InvalidKeySpecException e) {
                                                    e.printStackTrace();
                                                }
                                            }
                                        }, new APIErrorListener() {
                                            @Override
                                            public void onError(String error) {
                                                Log.e("DeviceEnrollmentAPI :", error);
                                            }
                                        });
                            } catch (NoSuchAlgorithmException | JoseException | IOException | InvalidKeySpecException e) {
                                e.printStackTrace();
                            }
                        }
                    });

                }
            }, new APIErrorListener() {
                @Override
                public void onError(String error) {
                    Log.e(MainActivity.class.getName() + "\t safetynet error", error);
                }
            });

        }
        @android.webkit.JavascriptInterface
        public void setVISAStaticKeys(String visaStaticKeysArrayString) {

        }
        @RequiresApi(api = Build.VERSION_CODES.GINGERBREAD)
        @android.webkit.JavascriptInterface
        public void setIDToken(String idTokenStr) {
            cardAlias = MainActivity2.cardAlias;
            Log.d("setIDToken", cardAlias);
            Toast.makeText(MainActivity2.this, "setIDToken called", Toast.LENGTH_SHORT).show();

            try {
                String idToken = EncryptionUtils.digestJWS(EncryptionUtils.decryptJWE(idTokenStr, EncryptionUtils.privateKey));
                sharedPreferences.edit().putString("cardAlias", idToken).apply();

            } catch (ParseException | JOSEException e) {
                e.printStackTrace();
            }
        }

        @SuppressLint("NewApi")
        @android.webkit.JavascriptInterface
        public void setPares(String paRes) {
            Log.d("setPares", paRes);
            Toast.makeText(MainActivity2.this, "setPares called", Toast.LENGTH_SHORT).show();

            if (paRes.isEmpty()) {
                Toast.makeText(MainActivity2.this, "Pares is empty", Toast.LENGTH_SHORT).show();
            } else {
                try {
                    byte[] base64DecodedStr = Base64.decode(paRes, Base64.DEFAULT);
                    String paresStr = decompressToString(base64DecodedStr);

                    System.out.println("ParesString: " + paresStr);
                    JSONObject jsonObject = parseXML(paresStr);
                    System.out.println("PaRes JSON: " +jsonObject.toString());

                    JSONObject paresJSONCorrectOrder = new JSONObject();
                    paresJSONCorrectOrder.put("cavv", jsonObject.getString("cavv"));
                    paresJSONCorrectOrder.put("eciflag", jsonObject.getString("eciflag"));
                    paresJSONCorrectOrder.put("xid", jsonObject.getString("xid"));
                    paresJSONCorrectOrder.put("paresstatus", "Y");
                    paresJSONCorrectOrder.put("signatureverification", "Y");
                    System.out.println("Correct PaRes JSON: " +jsonObject.toString());



                    String base64EncodedPaResJSON = Base64.encodeToString(paresJSONCorrectOrder.toString().getBytes(), Base64.NO_WRAP);
                        String signedPares = EncryptionUtils.generateJWS(base64EncodedPaResJSON);
                        System.out.println("signedPares\t:" + signedPares);
                        String encryptedPares = EncryptionUtils.generateJWE(signedPares, visaPublicKey);
                        System.out.println("encryptedPares\t:" + encryptedPares);
                        System.out.println("visaPublicKey\t:" + visaPublicKey);
                        new DeviceValidationAPI().validateDevice(MainActivity2.cardAlias, signedDeviceID, vDeviceId, encryptedAuthCode, encryptedPares, xCorrID, new APISuccessListener() {
                            @Override
                            public void onSuccess(String response, String headers) {
                                setClipboard(MainActivity2.this, response + "\nSignedPares:\t" + signedPares);
                                Log.d(DeviceValidationAPI.class.getName() + " response:", response);
                                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {

                                    Log.d("Build version", "Build version is above kitkat");
                                    webView.evaluateJavascript("window.initVSCAuthorize()", new ValueCallback<String>() {
                                        @Override
                                        public void onReceiveValue(String s) {
                                            // Checkout page starts verifying the payment
                                            Log.d("TAG", s);
                                        }
                                    });
                                }
                            }
                        }, new APIErrorListener() {
                            @Override
                            public void onError(String error) {
                                Log.d(DeviceValidationAPI.class.getName() + " error:", error);
                                setClipboard(MainActivity2.this, error);
                            }
                        });
//                        setClipboard(MainActivity.this, EncryptionUtils.generateJWS(paresTxt.getText().toString()));
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
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
