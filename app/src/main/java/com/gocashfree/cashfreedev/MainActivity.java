package com.gocashfree.cashfreedev;

import static com.gocashfree.cashfreedev.EncryptionUtils.visaPublicKey;

import android.content.Context;
import android.os.AsyncTask;
import android.os.Bundle;
import android.provider.Settings;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.gocashfree.cashfreedev.rest.APIErrorListener;
import com.gocashfree.cashfreedev.rest.APISuccessListener;
import com.gocashfree.cashfreedev.rest.DeviceEnrollmentAPI;
import com.gocashfree.cashfreedev.rest.DeviceValidationAPI;
import com.google.android.gms.safetynet.SafetyNetApi;
import com.nimbusds.jose.JOSEException;

import org.jose4j.lang.JoseException;
import org.json.JSONException;
import org.json.JSONObject;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;
import org.xmlpull.v1.XmlPullParserFactory;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Calendar;
import java.util.zip.DeflaterOutputStream;
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
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        button = findViewById(R.id.button);
        signParesBtn = findViewById(R.id.signedParesBtn);
        idTokenBtn = findViewById(R.id.idTokenBtn);
        paresTxt = findViewById(R.id.paresTxt);
        tokenTxt = findViewById(R.id.idTokenTxt);
        button.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                button.setEnabled(false);
                String nonce = Calendar.getInstance().getTimeInMillis() + "nonce";
                Log.d(MainActivity.class.getName()+"\t nonce", nonce);
                new GoogleSafetyNetAPI().generateSafetyNetToken(MainActivity.this, "AIzaSyAOIJhdoCME7oMIerSgIYb5p7FmnCf7_5c", nonce, new APISuccessListener() {
                    @Override
                    public void onSuccess(String response, String headers) {
//                        Log.d(MainActivity.class.getName()+"\t safetynet response", response);
                        AsyncTask.execute(new Runnable() {
                            public void run() {
                                android.os.Process.setThreadPriority(android.os.Process.THREAD_PRIORITY_BACKGROUND);

                                try {
                                    new DeviceEnrollmentAPI().enrollDevice(EncryptionUtils.generateJWE(
                                            EncryptionUtils.generateJWS(
                                                    Settings.Secure.getString(getApplicationContext().getContentResolver(), Settings.Secure.ANDROID_ID),
                                                    String.format("%d", Calendar.getInstance().getTimeInMillis()),
                                                    response)
                                    ), new com.gocashfree.cashfreedev.rest.APISuccessListener() {
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
                                } catch (NoSuchAlgorithmException|JoseException|IOException|InvalidKeySpecException e) {
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
                        Log.e(MainActivity.class.getName()+"\t safetynet error", error);
                        button.setEnabled(true);
                        signParesBtn.setEnabled(false);
                    }
                });
            }
        });
        signParesBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                if (paresTxt.getText().toString().isEmpty()) {
                    Toast.makeText(MainActivity.this, "Pares is empty", Toast.LENGTH_SHORT).show();
                } else {
                    try {

//                        JSONObject pares = new JSONObject();
//                        pares.put("cavv","");
//                        pares.put("eciflag","05");
//                        pares.put("xid","");
//                        pares.put("paresstatus","Y");
//                        pares.put("signatureverification","Y");
//
//                        String urlDecodedStr = URLDecoder.decode(decompressStr(paresTxt.getText().toString()));
//                        System.out.println("urlDecodedStr ::\n"+(urlDecodedStr));
//                        byte[] base64DecodedStr = Base64.decode(urlDecodedStr, Base64.DEFAULT);
//                        String paresStr = new String(base64DecodedStr, StandardCharsets.UTF_8);
//                        System.out.println(decompressStr(paresStr));
//                        parseXml(paresStr);
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
                                setClipboard(MainActivity.this, "Encrypted ID Token: "+ jwe);
                            } catch (JSONException | NoSuchAlgorithmException | JoseException |IOException | InvalidKeySpecException e) {
                                e.printStackTrace();
                            }
                        }
                    }, new APIErrorListener() {
                        @Override
                        public void onError(String error) {
                            System.out.println("Error ::"+ error);
                        }
                    });
                } catch (ParseException | JOSEException e) {
                    e.printStackTrace();
                }
            }
        });
    }

    private void setClipboard(Context context, String text) {
        if(android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.HONEYCOMB) {
            android.text.ClipboardManager clipboard = (android.text.ClipboardManager) context.getSystemService(Context.CLIPBOARD_SERVICE);
            clipboard.setText(text);
        } else {
            android.content.ClipboardManager clipboard = (android.content.ClipboardManager) context.getSystemService(Context.CLIPBOARD_SERVICE);
            android.content.ClipData clip = android.content.ClipData.newPlainText("Copied Text", text);
            clipboard.setPrimaryClip(clip);
        }
    }
    public void parseXml(String xml) throws XmlPullParserException {
        try {

            XmlPullParserFactory factory = XmlPullParserFactory.newInstance();
            factory.setNamespaceAware(true);
            XmlPullParser xpp = factory.newPullParser();

            xpp.setInput( new StringReader( xml ) ); // pass input whatever xml you have
            int eventType = xpp.getEventType();
            while (eventType != XmlPullParser.END_DOCUMENT) {
                if(eventType == XmlPullParser.START_DOCUMENT) {
                    Log.d("XML Parser","Start document");
                } else if(eventType == XmlPullParser.START_TAG) {
                    Log.d("XML Parser","Start tag "+xpp.getName());
                } else if(eventType == XmlPullParser.END_TAG) {
                    Log.d("XML Parser","End tag "+xpp.getName());
                } else if(eventType == XmlPullParser.TEXT) {
                    Log.d("XML Parser","Text "+xpp.getText()); // here you get the text from xml
                }
                eventType = xpp.next();
            }
            Log.d("XML Parser","End document");

        } catch (XmlPullParserException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

 public String decompressStr (String str) throws IOException {
     ByteArrayOutputStream baos = new ByteArrayOutputStream();
     DeflaterOutputStream dos = new DeflaterOutputStream(baos);
     dos.write(str.getBytes());
     dos.flush();
     dos.close();

     // at this moment baos.toByteArray() holds the compressed data of "Hello World!"

     // will decompress compressed "Hello World!"
     ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
     InflaterInputStream iis = new InflaterInputStream(bais);

     String result = "";
     byte[] buf = new byte[5];
     int rlen = -1;
     while ((rlen = iis.read(buf)) != -1) {
         result += new String(Arrays.copyOf(buf, rlen));
     }

     // now result will contain "Hello World!"

     System.out.println("Decompress result: " + result);
     return  result;
 }
}

class test {
    public static void main(String[] args) {
        System.out.println(new String(Base64.decode("eNrNWdmSo0iy%2FZW2nkdZD5skYEyVZsG%2Bix2hNzaxiB0kEF9%2FkVRZnV1dDzPzcG1kmanAifBwx%2F348SAPdtYnCWMl0a1PPg5qMgxBmvyWx99%2BJ5Utgjhg1xdXpDm2deUMyO8fBx2YyfCa8BqtknvSD3lTfyD%2FhP%2BJHqDPy1VZH2VBPX4cgqijRO1jiyEwuc74fnmokl5kPhAU%2FvwQWxI%2FQG%2FxAfpzvX57jobVwDmPP47OBKs25xq2%2BwiqYQ5hcgorxI0W9tsBes44xMGYfKAwisA4TP4G7%2F61%2FqCr6pf80D7Vgaq5rboReDXoq%2BCwPok%2BqaPHB7bbH6AfV4dkbps6WWesC36MD9CftrVB%2FQF%2F%2BRAwvCp4Sg%2F26eMw5tXfbMK2B%2BglPwxjMN6GD%2F8AfR8douB%2B%2FwAAUBR8Xf%2FSfolc5ywFn5%2FV19eUQxLlH%2FBuNWr9fq0CZdr0%2BZhVT1P%2FKjhAT1OgV%2Bg%2BDlae1utmffLbXJX18O33bBzbf0HQNE3%2FnLB%2FNn0KPYMDwSS0ToiHPP3H7%2B9VSSzWl%2BY%2FWkYHdVPnUVDmSzCuCaImY9bEv%2F2w7VdqbPOpCYFMlv5jVfVHhGzrP54SGEN2q07o10q%2FePbv7PKzsf0Q%2FDFkwTPboZ8UfRzM5JI8MyL5zTHFb7%2F%2F4xMFTJ4mw%2FjfbPe51VcNn%2FrcoLwlH05S5a0fco9uvJweJXWMLE6gKnmkiG%2Bf694zD9AP%2B74b%2F47UlyfynthdaDdq94O%2BM28ThFRs4KKiFnSq0Q8J5tw2j6vgtYuK3cyMarRJ3%2BNxwMkRUaWqUDXmebEXh67YTRVuaA90FLuhTsrW6k9LMlTtlbLNzs4uupGLFjbfNdUZxtvxTsNwRBbxJRayETc8ZGYq%2BxxxErCufM1E4nUPW%2FzWYHBc6JLM9qxGu2d9c6d3yqzb4RRuXeO2orhyuxkjKukc6mfLmbEHoPVBN09pjZonQOiwMA2sj05UxpQ7xmfPbm8LttdtIwF4HMKn%2Fk2MIF5mL%2Fs8T%2FCdb2zFFgZQlclugNnOnJksbCoh2eS2ZTB127cA1TyO2AcoVMUnoekZDGW3S6GmCe1tNrnHTyH49u1LxnyPiJw83hE47WCSCcbgPaKTfswva%2BquFUkVRXZhaBrgVgomkQKp6KwPc7Km3Ez3LlFYqHxPd8gAUgPXwcQYviQ3ZzG7RxowWIUywBTZrKKCKw8Qh6UylXZddWZsoFCp5lKgsSnuLDkwOysLGN%2BywZbKcxuhbGp5O%2Fh8km7%2ByWxDdJeFNGWv12jgaaXIckuEkkXgcXDgkTfVEicR%2BIxrGAw7l15w0jKRd5kQRcZ1TXG2KCnCNCTwdrXIapRKbU%2BMLU6qzc4qA9bK7c%2Ba2zxl80%2By6WKzugrgtw%2FTxNsnd%2FQrrlVNY2LT154iA0bN97IsqrglEMyH%2F5PflrOd2QWY3%2F1W6WvJWI4miayUhStbsDbQv%2Fuv0ox2jVC3iE9SqZrEJBhvvxjqLBnwus4Cy1nQSh9zH6tfduDFt6dfa7wosQAalV677Jrz5ARTaxw4AI40MAjwvE%2Bn8jpmAZJyuzZSKEvscHYYGrxFW1qKrVwwNgzcH6MAmXj8HLGdX3MLQ7DXaqP5jWGnbMhyBXObCFTO0QZhjMeV653rnjMZzDl7Hj7swYUoWmnZ2Fd7OHNlS1Cei8dHfYPPUI5DFUc0Nf0IbsUo0jdxytxY99X0iAc8oj607eDnSlj6Z%2Bd4JT3jFCjGMaePgIdOWLjwuFyUZ7XEMMFxB3XhDcuOZqgdrUlm7jm5l7ap0RobW8JceAprHIfiiHANOc3KR88mKAixU6sG%2Fbr5WGf%2B44JkGm%2FkU71WFdE%2FQQ7WXAgf7c5t6F5i7KoN9jwfb8kjoRTTK9CBIs6ckzSzzgvx3SSJlnlIFLIN1Xpa08AAVLMVKbtYceM0E%2FPMSRO2gSFAFBAnwIDLM86CpbI8A7yUsi%2FTo3WVnKSPdQvqs5yScLxDthshL6iSStOeSlmOMqI1luZZ5aJJSX1RnnyKMhxBBTIvVhkcC2CvPMgyrKV7yE%2B3uCoX39MypdLuoUWWPkqOobUrzidxkoyv63me936sv%2FuYNin1C3%2B35xplxViEgelovPxIKWbFDANuVOrWqaFSwAalSqs8TQ88MByOWusEl8VNLJjTMSfuMRZjf9GHUX1gA%2Fv9DByWYYD8xUcGFGB53TMJVmFAp9J5KnXgmuXSD52mt3uE6Dy89XKFv%2FoVovD97Ky%2BevDNx6RBpV54jZnU8KgVIiDfOwt%2BvLu3eUUoOAZnMT%2FeFeNcgONrP4Og1rRlKaDS1PaXtYxJ0%2FW2iPiCs9hgjdN9hzVnikT0u3m3I0dz4%2BgCD%2B2mXCyF9PoYhkdeC0Oz7K%2BCWO7MmuvVkzkItqsaVGFW0q1gxFNG8lIMx7qKnvaTpC5H7paYREVYEUNMkp0H3eIqrgsTFiuTWRw5oYZgoxzGGmPGMdgHURCa9XQJqk7puc3dKKWpR9WQ3lciepVo%2Bca0HeFct9QtLMdaJo%2FnfJHBCeFQSfdxOLY2SgVpj0WYAlRWukecnNiaWivQrb1a%2FQx1u5PpV6m%2FLR5oToXxQOGYdBZ3ZX%2BXRKhB0HbTjiex48xxvum2SbW6u61QA0u6M2l7SV9dDCGEeidrmR2YVbZDTGsx%2B%2F4SZXp3C9wHl64E9TP7%2FIqOOH6haQocP%2BnIBJpyd3l1KndHLhRcBGuvaiE6P4ePe1JRsPw%2FUZG5ckT6SUXar6jIClESflPQk2rUx0o5mLqoi4a8KOihMv5jdWRZKegp%2B9%2Bl0f%2BAcvprRe9gY8NfK%2BNxRsmrPLdIvKmlLSZNp4w%2F4wHHIXqu7qySZi0DRTsXKimATYLv60SO4BBvGL5G5Rx22%2Fb74nYSBW4qprv84FRuf60o%2F3SPjIDQY3zH0UiNXS5in7HFpozDaj2BLTKc6Rf%2FcWLPHdMK2fVWV3cG7xaEYj2ZxTXHdzmTvTStm19KOXfPkd8LOU5LIKE0H48f6b0S1VpwEmGrjYy16y5QTTKGcbm4j3qXSV6%2B0xOKwGu7HB%2FEEhc5OhZ4DdCNj%2BmKbEoO9kDEMMo6vqxP3RwE8uVqK9qQnztStyc56B%2FC5lZh4%2Bmyu22rW7mY%2FNHLUGezIlipx0rl6BBSOunq1Y6bbL5QzvCknGA7CdOrVBcUlU5cAxzOzhlmIQYdA4swIDyUJqp4ZE4THr3blx%2F0lE5rGaagJ7YYsHuXaMCqBZhUestTXkKBiaVU2pnE6U8KASnrcegPClkLfvSmn%2B9lOeLH9pUHb7su1DoGBU1BC0AbxkrVxp%2FWlgmOmOauwO4tqsghpHfoM%2Ff8T9pAXqWeMbwvueiuVIcZ73LPPNJjB7ZZcf4r9VTlLf47HRZRNd3dp8zRqDdtIGVUaaVTkfeY3j3vT6kfpKl%2FXH9p%2FlLNV%2F%2F08o%2F7JcXazXJkrncf3ZIvvRZVGk%2FK9dyHjzrpW%2B98190XTocQcz7nSWFtrnvvspgv72HFDSKnldFKbc91xklbQlRr39jdQj7qPtZ51Yrddb5rnU%2Fndc83dm2%2BXGLm73QGDP%2FdQprwkaJ8ltMgRi6dmwKL%2B%2BRKx9eOwUysPhXbRH62ubTV8ZYYYozBPuMLwJpba46VWMkEQwR12KMYWvkopkct1WqQnjCJPnbcGLSegyiSoLgPd4ubWSq7OCQXaIXdfW54tBtnyodtYKj7AeATRguN1HhMuj8WmefcskYMVc0kqFqrtE0eYRuRJ3unQhNOW4geMhqH4Uzd4DkG0kaxu89ktcmuG6LFBYsIlOCoz1qhL1UykPtOLChmU8OzZN023AZLvRkPd9S%2Bs4UOKwawu67AlHetpWibOxRKfW7teG0F4qJYlqdogWwQF73KSqk%2Bbs%2FITC63sy0PSZtrDNjbfesEPvNYTGQXePlx08dsybFFSaznulF15Q1WR5eIc3HKPeM7mm%2BhdGnayRlt4mhmHrZp8KK%2F3PBF%2Fvdoj2me0G66T9oz2K2P2CYMUXeF2ngOh5xB5P%2BtDDscYKheNYaJfp8geHaSXGdhNRUMLyqhM5V1r6Vt2Oxdpd8nHHpWq%2F8iNWeBAcGbelYyQ97U8xVaIveC6yRkkaauXaRWiOj6PR8ZFfWesuIlg9fucg0k%2B%2FCK%2Fz3b1w4w%2Fxki4DtEmAk878ugecKFvrvkzhOqfYZW9FzSF4UjB0Hf0pxN5NE4MnAIQ3oVFxlKSOKJ6YajrQsC2ilSAffaxRWHs0CB65YtWw4fGH0aTPPIehvEkInQDFwZx%2FZor8upgKQQez2nuohmWwHT3WW7CPdRIILGLafYPXceoli4n3LVo51QzLxNmQ8RSLd36OXRw7a%2Bw8mzGWcs2hAVraPTttQlcomijYPBfYeS5OMoLkvZYzOHL9Z6auO8IajJwT%2FlEx9DVNXIjeqtbaYIXbebRh54PiltYrt2%2BRt4vC%2BErHNOerSmAfAlXDodISpymySOn5%2F5BqNmDcfHjTaNMVRUZc6tVYhfBl6YqfslUOJTsvcllN1B2xGk64kD8IVRrJECxKvDZ6cnZRmcCtRnyZuYN6Xpb0ozmJWe%2BL%2BeBgz3KKq6%2FpigiFGTxQk31HZKt9qFGZdfYOjVyrDgBHHU5TRHtHLtt5pnmVBbn2THniY1qx6jmjuh7jmYBHUuGCtdw05sU3qRudDWAMPmEAVbSuQHpmkIf3xc95fE8XxO2%2Boqfed8HSsQcZEU5HrdXW45dAl5ORujUMcU6mLEtNuS0K7XJWtjOyNVsHgekUxxpaXFILAF37TLcvXkQT5LEDyT9YkXZ8GPr9wQ43dMJTc46cvenGTnGTZDY%2BVgIuSrE7rfXY7ndlImh%2BAdn60sgMI8dfONAOeushrp0bTZMOG5U8F6bq4UrTNPe4rPYaSrGZjEDJeH6gBqQEPsAFNJ%2BAXKaCy55WJdZtS8fygjRhJLrUJFH%2ByPiIhXNsLfuVZJT7ovMNO3X3X%2B0J%2FvpKAf76n%2BfIP1egn%2F%2Bo%2FA88Xx1%2F8U%2FB%2BJyfng", Base64.DEFAULT), StandardCharsets.UTF_8));
    }
}