package com.gocashfree.cashfreedev;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.util.Log;
import android.view.View;

import java.util.Calendar;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        findViewById(R.id.button).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                String nonce = Calendar.getInstance().getTimeInMillis() + "nonce";
                Log.d(MainActivity.class.getName()+"\t nonce", nonce);
                new GoogleSafetyNetAPI().generateSafetyNetToken(MainActivity.this, "AIzaSyAOIJhdoCME7oMIerSgIYb5p7FmnCf7_5c", nonce, new APISuccessListener() {
                    @Override
                    public void onSuccess(String response) {
                        Log.d(MainActivity.class.getName()+"\t safetynet response", response);
                    }
                }, new APIErrorListener() {
                    @Override
                    public void onError(String error) {
                        Log.e(MainActivity.class.getName()+"\t safetynet error", error);
                    }
                });
            }
        });
    }
}