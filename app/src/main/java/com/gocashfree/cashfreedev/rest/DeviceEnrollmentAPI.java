package com.gocashfree.cashfreedev.rest;

import android.util.Log;

import java.util.HashMap;

public class DeviceEnrollmentAPI extends BaseApi {

    private static final String TAG = DeviceEnrollmentAPI.class.getName();
    public static String publicKey = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJwdWJsaWNLZXlPYmplY3QiOnsia2V5U2l6ZSI6IjIwNDgiLCJwdWJsaWNLZXkiOiIw77-9XHUwMDAxXCIwXHJcdTAwMDZcdCrvv71I77-977-9XHJcdTAwMDFcdTAwMDFcdTAwMDFcdTAwMDVcdTAwMDBcdTAwMDPvv71cdTAwMDFcdTAwMEZcdTAwMDAw77-9XHUwMDAxXG5cdTAwMDLvv71cdTAwMDFcdTAwMDFcdTAwMDDvv71cdTAwMDQ6XHUwMDFD77-9ae-_ve-_vciv77-977-9Mu-_ve-_ve-_ve-_ve-_vVx1MDAwMu-_vXfvv73vv73vv73vv71cdEnvv73vv73vv71d77-9O--_vVx077-9Jjzvv71iNu-_ve-_vTbvv73vv73vv70mIFnvv73vv71hR--_vTvvv73vv71RPivvv71cdTAwMDbvv73vv73vv73vv71cdTAwMTTvv73vv71cdTAwMUNR77-977-9WXJcdTAwMEXvv71cdTAwMTDvv71cdTAwMUbvv71kPjXvv71S77-9f1Xvv71CbVHvv71t77-9cmnvv70mICbvv71cdTAwMELCue-_ve-_ve-_vW1cdTAwMUXvv717Q0Fm77-977-977-9xJF5Q--_ve-_vTtE77-977-977-977-9xLlQKO-_ve-_vSB1QVx1MDAwNXDvv70677-977-977-9XHUwMDBG77-9XHUwMDE477-9ae-_ve-_vVx1MDAxOGhL77-977-9V--_vVxiPDfCge-_vUgw2IEkL--_vdS7N2khR0fvv70r77-9Plx1MDAxMSxcdTAwMDXvv71TXFzvv73vv73vv73vv73vv73vv73vv73vv71eXHUwMDE4cO-_ve-_ve-_vUPvv71cdTAwMULvv73vv73vv73vv71cdTAwMDfvv73vv705XHUwMDE177-9KFx1MDAxNu-_vWVcdTAwMTgzYO-_vSBi3p7vv71kXGLvv73vv71677-977-914THp--_ve-_vVfvv71e77-9XHUwMDEzwqPvv73vv71cdTAwMDJcdTAwMDNcdTAwMDFcdTAwMDBcdTAwMDEiLCJrZXlUeXBlIjoiUlNBIn0sInNhZmV0eU5ldERhdGEiOiJleUpoYkdjaU9pSlNVekkxTmlJc0luZzFZeUk2V3lKTlNVbEdXVlJEUTBKRmJXZEJkMGxDUVdkSlVrRlFhRXRrVVhkclNVRk5SRU5SUVVGQlFVTTRRelp2ZDBSUldVcExiMXBKYUhaalRrRlJSVXhDVVVGM1VtcEZURTFCYTBkQk1WVkZRbWhOUTFaV1RYaEpha0ZuUW1kT1ZrSkJiMVJIVldSMllqSmtjMXBUUWxWamJsWjZaRU5DVkZwWVNqSmhWMDVzWTNsQ1RWUkZUWGhGZWtGU1FtZE9Wa0pCVFZSRGEyUlZWWGxDUkZGVFFYaFNSRkYzU0doalRrMXFSWGhOUkVVelRWUmpkMDVxUVROWGFHTk9UV3BKZDAxVVJURk5WR04zVG1wQk1sZHFRV1JOVW5OM1IxRlpSRlpSVVVSRmVFcG9aRWhTYkdNelVYVlpWelZyWTIwNWNGcEROV3BpTWpCM1oyZEZhVTFCTUVkRFUzRkhVMGxpTTBSUlJVSkJVVlZCUVRSSlFrUjNRWGRuWjBWTFFXOUpRa0ZSUTNablUyVkhNM0pUVmxjd1NWQnBXa0pHVm1Kb01rdGpZak5vVG5sM1IyVkpPVVptYVZneVVYWlJRbkJtVWtJdlQweGlVVUZ3WkdkRFdUWkpMMWRxTkV3MGFIVk5RelJNVkhBM09GWlhibWh0WkdKM1kxTnhiWEp6TmtwRE0za3dXblZtVm00eWR6aHNWME5ZT0ROc1l5dEZVbWRSVkhobWFHVXdUVk5JYWtobFdrOW1XR1JPUTNkcWVqWnJUWEprWkVWUFVsSjVUM1YzU1dkamNYY3JOR295Y1M5bVNrdEhia1V5TlhRNU5uZE9URGdyVURnMVYyOTRaWGhhWkVST1IxcHpNbWt6Tm1SdlprZFZUR1IxWVRaYVdGSTFZakZsT0RKa2QwZHJhMFJrZDNSRk1qWkNlRFJoVFRsNFZERXdLM0EwUzNGS05YWjBNV3B2WTFOMEsydFRXSEZSYUVvd1FsSmpTMDgyT1doR1VUUkRTVWRLWWs1RVlsUklNRU5HWWxNdmFuSnNOVGhHV25oVlRVVndhVU5IYkc5SmRtSnlaMjB4U2xGelJERTJVbXRJWmxRME5WTTVVRVJOYzNrNVdGSTRialZxUVdkTlFrRkJSMnBuWjBwNFRVbEpRMkpVUVU5Q1owNVdTRkU0UWtGbU9FVkNRVTFEUW1GQmQwVjNXVVJXVWpCc1FrRjNkME5uV1VsTGQxbENRbEZWU0VGM1JYZEVRVmxFVmxJd1ZFRlJTQzlDUVVsM1FVUkJaRUpuVGxaSVVUUkZSbWRSVlVKME0xbFVXa0ZZWjNwR1lYZHBWMkZYTjNobWFTdFlSRGhuWjNkSWQxbEVWbEl3YWtKQ1ozZEdiMEZWU21WSldVUnlTbGhyV2xGeE5XUlNaR2h3UTBRemJFOTZkVXBKZDJKUldVbExkMWxDUWxGVlNFRlJSVVZaVkVKbVRVTnZSME5EYzBkQlVWVkdRbnBCUW1ob05XOWtTRkozVDJrNGRtSXlUbnBqUXpWM1lUSnJkVm95T1haYWVUbHVaRWhOZUZwRVVuQmlibEYzVFZGWlNVdDNXVUpDVVZWSVRVRkxSMHBYYURCa1NFRTJUSGs1ZDJFeWEzVmFNamwyV25rNWVWcFlRblpNTWs1c1kyNVNla3d5WkRCamVrWnJUa00xYTFwWVNYZElVVmxFVmxJd1VrSkNXWGRHU1VsVFdWaFNNRnBZVGpCTWJVWjFXa2hLZG1GWFVYVlpNamwwVFVORlIwRXhWV1JKUVZGaFRVSm5kME5CV1VkYU5FVk5RVkZKUWsxQmQwZERhWE5IUVZGUlFqRnVhME5DVVUxM1VIZFpSRlpTTUdaQ1JHZDNUbXBCTUc5RVMyZE5TVmwxWVVoU01HTkViM1pNTWs1NVlraE5kV05IZEhCTWJXUjJZakpqZGxvelVucE5WMUV3WVZjMU1Fd3haM2xUYWtwSlkydzRNMVZIYkU1TWJVNTVZa1JEUTBGUlVVZERhWE5IUVZGUlFqRnVhME5DUVVsRloyWlZSV2RtU1VFNFFVSXhRVVpIYW5OUVdEbEJXRzFqVm0weU5FNHphVkJFUzFJMmVrSnpibmt2WldWcFJVdGhSR1kzVldsM1dHeEJRVUZDWmtrNWRYVnFTVUZCUVZGRVFVVlpkMUpCU1dkWWQzSnhiRUV2VjIxSVJGVnlTVnBTV0RJclMyNHJhbGRqUlZsc1FqbGlWQ3RzUms5SFQzUmFURXROUTBsR1V6UlhZVTE0UTA5R2FWQXhUbmhWTjNoTWNWQlFWR2x3UjJkbGFGZ3dTMEl3VEZnclRYaGtkRWwwUVVoalFVdFliU3M0U2pRMVQxTklkMVp1VDJaWk5sWXpOV0kxV0daYWVHZERkbW8xVkZZd2JWaERWbVI0TkZGQlFVRkdPR295TmpaTFVVRkJRa0ZOUVZORVFrZEJhVVZCTkRkUk5sZEpZbVZuUVVadUwwbGlVVU01T0VGb1IwZGxZMHhHVldvd2NqUkNNbmxyU2tGbE4ydHpkME5KVVVSaVEyUk5ORmR6UTJKVlVISnNTRGhJVjNNMVpHcHFRV2x1S3k5aldEWlBOSHBEVGxkTWJ6Snhha2hFUVU1Q1oydHhhR3RwUnpsM01FSkJVWE5HUVVGUFEwRlJSVUZNV0hsaE9VaFZWbTVyWlVSa1VGZ3lkMHR6UTJReWJEaE5jR3BUZVc1aVZXVktXR0k1VW0wNGRYUnNjelJqUnprdmRYRXpSelozY2xSR1drTmhkbGRKTW5FNVNteGxVbkExUTIxRGVDdHJjRWxQVlZoM1QwZFBRVVozU1ZGcl";


    public void enrollDevice(String jwe, APISuccessListener successListener, APIErrorListener errorListener) {
        String body = "{\"customerDetails\": {" +
                "  \"merchantCustId\": \"1635927040\"," +
                "  \"mobileNumber\": \"9094395340\"," +
                "  \"merchantCardAlias\": \"1635927013\"" +
                "    }," +
                "\"merchantDetails\": {" +
                "    \"merchantAppId\": \"com.gocashfree.cashfreedev\"" +
                "}," +
                "  \"staticKeyRefId\": \"VSC-STATIC-KEYS-21.02-00-SBX-MER-6\"," +
                "  \"encryptedAuthCodeReq\": \"" + jwe + "\"}";
//        System.out.println(body);
        geCFExecutor().executeCertPinnedPostRequest( "https://sandbox.consumerapi.digital.visa.com/resource-broker/vcolite/v1/authcode",  body, null, successListener, errorListener);
    }

    public void enrollDevice(String cardAlias, String jwe, APISuccessListener successListener, APIErrorListener errorListener) {
        String body = "{\"customerDetails\": {" +
                "  \"merchantCustId\": \"1635927040\"," +
                "  \"mobileNumber\": \"9094395340\"," +
                "  \"merchantCardAlias\": \""+cardAlias+"\"" +
                "    }," +
                "\"merchantDetails\": {" +
                "    \"merchantAppId\": \"com.gocashfree.cashfreedev\"" +
                "}," +
                "  \"staticKeyRefId\": \"VSC-STATIC-KEYS-21.02-00-SBX-MER-6\"," +
                "  \"encryptedAuthCodeReq\": \"" + jwe + "\"}";
//        System.out.println(body);
        geCFExecutor().executeCertPinnedPostRequest( "https://sandbox.consumerapi.digital.visa.com/resource-broker/vcolite/v1/authcode",  body, null, successListener, errorListener);
    }
}
