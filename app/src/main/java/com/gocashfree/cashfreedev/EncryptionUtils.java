/*
 *
 *   © Copyright 2018 - 2020 Visa. All Rights Reserved.
 *
 *   NOTICE: The software and accompanying information and documentation (together, the “Software”) remain the property of and are proprietary to Visa
 *   and its suppliers and affiliates. The Software remains protected by intellectual property rights and may be covered by U.S. and foreign patents or patent applications.
 *   The Software is licensed and not sold.
 *
 *  By accessing the Software you are agreeing to Visa's terms of use (developer.vis.com/terms) and privacy policy (developer.visa.com/privacy).
 *  In addition, all permissible uses of the Software must be in support of Visa products,
 *  programs and services provided through the Visa Developer Program (VDP) platform only (developer.visa.com).
 *  **THE SOFTWARE AND ANY ASSOCIATED INFORMATION OR DOCUMENTATION IS PROVIDED ON AN “AS IS,” “AS AVAILABLE,” “WITH ALL FAULTS” BASIS WITHOUT WARRANTY OR  CONDITION OF ANY KIND. YOUR USE IS AT YOUR OWN RISK.**
 *  All brand names are the property of their respective owners, used for identification purposes only,
 *  and do not imply product endorsement or affiliation with Visa. Any links to third party
 *  sites are for your information only and
 *  equally  do not constitute a Visa endorsement. Visa has no insight into and control over
 *  third party content and
 *  code and disclaims all liability for any such components, including continued availability
 *  and functionality.
 *  Benefits depend on implementation details and business factors and coding steps shown are exemplary only and
 *  do not reflect all necessary elements for the described capabilities. Capabilities and
 *  features are subject to Visa’s terms and conditions and
 *  may require development,implementation and resources by you based on your business
 *  and operational details.
 *  Please refer to the specific API documentation for details on the requirements, eligibility
 *  and geographic availability.
 *
 *  This Software includes programs, concepts and details under continuing development by
 *  Visa. Any Visa features,functionality, implementation, branding, and
 * schedules may be amended, updated or canceled at Visa’s discretion.
 *  The timing of widespread availability of programs and functionality is also subject to a number of factors outside Visa’s control,including but
 *  not limited to deployment of necessary infrastructure by issuers, acquirers, merchants
 *  and mobile device manufacturers.
 *
 *  This sample code is licensed only for use in a non-production environment for sandbox testing. See the license for all terms of use.
 */
package com.gocashfree.cashfreedev;


import static javax.xml.bind.DatatypeConverter.printBase64Binary;

import android.annotation.SuppressLint;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.gocashfree.cashfreedev.rest.DeviceEnrollmentAPI;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.SignedJWT;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.lang.JoseException;
import org.json.JSONException;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.Base64;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public final class EncryptionUtils {

    private static final Charset CHARSET_UTF_8 = Charset.forName("UTF-8");
    private static final String CONTENT_TYPE_JWE = "JWE";
    private static final String CONTENT_TYPE_JWS = "JWS";
    private static final String CONTENT_TYPE_XML = "application/xml";
    private static final String SHA_256 = "SHA-256";
    private static final String ERROR_MESSAGE_INVALID_SIGNATURE = "Invalid signature";
    private static final String HEADER_CTY = "cty";
    private static final String HEADER_IAT = "iat";
    private static final String HEADER_EXP = "exp";

    public static RSAPublicKey publicKey;
    public static String visaPublicKey;
    public static String visaPublicKey1="";
    public static RSAPrivateKey privateKey;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }



    public static String generateJWSFromDPrivateKey(String idToken, String nonce, String safetynetToken) throws JSONException, NoSuchAlgorithmException {
        String token;
        try {
            Algorithm algorithm = com.auth0.jwt.algorithms.Algorithm.RSA256(publicKey, privateKey);
            Map<String, Object> payloadMap = new HashMap<>();

            payloadMap.put("idToken", idToken);
            payloadMap.put("safetyNetData", safetynetToken);
            payloadMap.put("timestamp", nonce);
            token = JWT.create()
                    .withIssuer("auth0")
                    .withPayload(payloadMap)
                    .sign(algorithm);
            System.out.println("Signed ::"+token);
//            try {
//                generateJWE(token);
//            } catch (IOException e) {
//                e.printStackTrace();
//            } catch (JoseException e) {
//                e.printStackTrace();
//            } catch (InvalidKeySpecException e) {
//                e.printStackTrace();
//            }
//            JWT.create().withIssuer("auth0").withPayload(token).sign()
            return token;
        } catch (JWTCreationException exception){
            //Invalid Signing configuration / Couldn't convert Claims.
        }
        return "";
    }

    public static String generateJWSFromDPrivateKey(String idToken, String nonce, String safetynetToken, String privateKey) throws JSONException, NoSuchAlgorithmException {
        String token;
        try {
            Algorithm algorithm = com.auth0.jwt.algorithms.Algorithm.RSA256(publicKey, (RSAPrivateKey) getPrivateKey(privateKey));
            Map<String, Object> payloadMap = new HashMap<>();

            payloadMap.put("idToken", idToken);
            payloadMap.put("safetyNetData", safetynetToken);
            payloadMap.put("timestamp", nonce);
            token = JWT.create()
                    .withIssuer("auth0")
                    .withPayload(payloadMap)
                    .sign(algorithm);
            System.out.println("Signed ::"+token);
//            try {
//                generateJWE(token);
//            } catch (IOException e) {
//                e.printStackTrace();
//            } catch (JoseException e) {
//                e.printStackTrace();
//            } catch (InvalidKeySpecException e) {
//                e.printStackTrace();
//            }
//            JWT.create().withIssuer("auth0").withPayload(token).sign()
            return token;
        } catch (JWTCreationException exception){
            //Invalid Signing configuration / Couldn't convert Claims.
        }
        return "";
    }


    public static String generateJWS(String androidID, String nonce, String safetynetToken) throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        String token;
        KeyPair kp = kpg.generateKeyPair();
        publicKey = (RSAPublicKey) kp.getPublic();
        privateKey = (RSAPrivateKey) kp.getPrivate();
        System.out.println("publicKey :\t"+printBase64Binary(kp.getPublic().getEncoded()));
        System.out.println("privateKey :\t"+printBase64Binary(kp.getPrivate().getEncoded()));
        try {
            Algorithm algorithm = com.auth0.jwt.algorithms.Algorithm.RSA256(publicKey, privateKey);
            Map<String, Object> payloadMap = new HashMap<>();
            Map<String, String> publicKeyObject = new HashMap<>();
            publicKeyObject.put("keyType", "RSA");
            publicKeyObject.put("keySize", "2048");
            publicKeyObject.put("publicKey", printBase64Binary(kp.getPublic().getEncoded()));
            payloadMap.put("publicKeyObject",publicKeyObject);

            Map<String, String> deviceIdData = new HashMap<>();
            deviceIdData.put("deviceId", androidID);
            payloadMap.put("deviceIdData",deviceIdData);

            payloadMap.put("deviceNonce", nonce);
            payloadMap.put("safetyNetData", safetynetToken);

            token = JWT.create()
            .withIssuer("auth0")
            .withPayload(payloadMap)
            .sign(algorithm);
            System.out.println(token);
//            try {
//
//                generateJWE(token);
//            } catch (IOException e) {
//                e.printStackTrace();
//            } catch (JoseException e) {
//                e.printStackTrace();
//            } catch (InvalidKeySpecException e) {
//                e.printStackTrace();
//            }
//            JWT.create().withIssuer("auth0").withPayload(token).sign()
            return token;
        } catch (JWTCreationException exception){
            //Invalid Signing configuration / Couldn't convert Claims.
        }
        return "";
    }
    public static String generateJWSVBA(String androidID, String sessionID) throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        String token;
        KeyPair kp = kpg.generateKeyPair();
        publicKey = (RSAPublicKey) kp.getPublic();
        privateKey = (RSAPrivateKey) kp.getPrivate();
        System.out.println("publicKey :\t"+printBase64Binary(kp.getPublic().getEncoded()));
        System.out.println("privateKey :\t"+printBase64Binary(kp.getPrivate().getEncoded()));
        try {
            Algorithm algorithm = com.auth0.jwt.algorithms.Algorithm.RSA256(publicKey, privateKey);
            Map<String, Object> payloadMap = new HashMap<>();
            Map<String, String> publicKeyObject = new HashMap<>();
            publicKeyObject.put("keyType", "RSA");
            publicKeyObject.put("keySize", "2048");
            publicKeyObject.put("publicKey", printBase64Binary(kp.getPublic().getEncoded()));
            payloadMap.put("publicKeyObject",publicKeyObject);

            Map<String, String> deviceIdData = new HashMap<>();
            deviceIdData.put("deviceId", androidID);
            deviceIdData.put("deviceIntegrityClaim", sessionID);
            deviceIdData.put("deviceIntegrityClaimType","VBA_ANDROID");
            payloadMap.put("deviceIdData",deviceIdData);
            payloadMap.put("deviceIntegrityClaim", sessionID);
            payloadMap.put("deviceIntegrityClaimType","VBA_ANDROID");


            token = JWT.create()
            .withIssuer("auth0")
            .withPayload(payloadMap)
            .sign(algorithm);
            System.out.println(token);
//            try {
//
//                generateJWE(token);
//            } catch (IOException e) {
//                e.printStackTrace();
//            } catch (JoseException e) {
//                e.printStackTrace();
//            } catch (InvalidKeySpecException e) {
//                e.printStackTrace();
//            }
//            JWT.create().withIssuer("auth0").withPayload(token).sign()
            return token;
        } catch (JWTCreationException exception){
            //Invalid Signing configuration / Couldn't convert Claims.
        }
        return "";
    }

    public static String generateJWS(String value) throws NoSuchAlgorithmException, GenericSecurityException {
        JWSObject jwsObject = new JWSObject((new com.nimbusds.jose.JWSHeader.Builder(JWSAlgorithm.RS256))
                .type(JOSEObjectType.JOSE).contentType(CONTENT_TYPE_JWE).build(), new Payload(value));
        JWSSigner signer = new RSASSASigner(privateKey);
        try {
            jwsObject.sign(signer);
            System.out.println(jwsObject.serialize());
            return jwsObject.serialize();
        } catch (JOSEException e) {
            throw new GenericSecurityException(e.getMessage(), e);
        }
    }

    @SuppressLint("NewApi")
    public static PublicKey getSandboxPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        String publicK =  "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAol0I9onWvzdVseFJnl5ux9XAANJzqcfWYPGs0uu5XLrzZcE7lIjkP31gXKCtftnTWlOdPu4SBBjCXdLpVb96eA5zmJNUD3UDtvlpiC2diVDse0OHLXr8T2f71ojaLshnNLfG0xnG/vITIHwNQfjQv7r5wHCVcqAbHYnHF2Yh8hb5inn1WDPKXalsLqgWB0bm8TzhPPOe0hHvcCHxDdBRh+f65iksyNphXoMEEIqYCPjowXTuLi8mB0jYrWAH3tjHC/j4ooLaBqUb+jN/xHaTmhWP8aqO/eF9IUXJZqkfxy3BfiQnUOglFWDNT2c8W1aHOb089cQ/iu0Lz+xF/PWHMQIDAQAB" ;
         byte[] publicBytes = Base64.getDecoder().decode(publicK);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey pubKey = keyFactory.generatePublic(keySpec);
        return pubKey;

    }

    public static PublicKey getVisaPublicKey() throws IOException {
        String hostname = "sandbox.consumerapi.digital.visa.com";
        SSLSocketFactory factory = HttpsURLConnection.getDefaultSSLSocketFactory();
        SSLSocket socket = (SSLSocket) factory.createSocket(hostname, 443);
        socket.startHandshake();
        java.security.cert.Certificate[] certs = socket.getSession().getPeerCertificates();
        java.security.cert.Certificate cert = certs[0];
        PublicKey key = cert.getPublicKey();
        DeviceEnrollmentAPI.publicKey = printBase64Binary(key.getEncoded());
        return key;
    }

    public static void setVisaDevicePublicKey(String key) throws IOException {
        visaPublicKey = key;
    }

    public static String generateJWE(String signedJwt) throws IOException, JoseException, InvalidKeySpecException, NoSuchAlgorithmException {
        return generateJWE(signedJwt, getSandboxPublicKey());
    }
    public static String generateJWE(String value, String publicKey) throws IOException, JoseException, InvalidKeySpecException, NoSuchAlgorithmException {
        return generateJWE(value, getPublicKey(publicKey));
    }

    public static String generateJWE(String value, PublicKey publicKey) throws JoseException {
        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setContentTypeHeaderValue("JWT");
        jwe.setKey(publicKey);
        jwe.setPayload(value);
        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.RSA_OAEP_256);
        jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_256_GCM);
        String encryptedJwt = jwe.getCompactSerialization();
        System.out.println("Encrypted ::" + encryptedJwt);
        return encryptedJwt;
    }

    public static String generateJWE(String value, RSAPublicKey publicKey) throws IOException, JoseException, InvalidKeySpecException, NoSuchAlgorithmException {

        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setContentTypeHeaderValue("JWT");
        jwe.setKey((publicKey));
        jwe.setPayload(value);
        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.RSA_OAEP_256);
        jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_256_GCM);
        String encryptedJwt = jwe.getCompactSerialization();
        System.out.println("Encrypted ::" + encryptedJwt);
        return encryptedJwt;
    }

    public static String decryptJWE(String value, RSAPrivateKey privateKey) throws ParseException, JOSEException {
        RSADecrypter rsaDecrypter = new RSADecrypter(privateKey);
        EncryptedJWT encryptedJWT = EncryptedJWT.parse(value);
        encryptedJWT.decrypt(rsaDecrypter);
        System.out.println("Decrypted ::" + encryptedJWT.getPayload());
        return encryptedJWT.getPayload().toString();
    }

    public static String digestJWS(String value) throws ParseException, JOSEException {
        JWSVerifier jwsVerifier = new RSASSAVerifier((RSAPublicKey) getPublicKey(visaPublicKey));
        SignedJWT signedJWT = SignedJWT.parse(value);
        System.out.println("Verify Signature ::" + signedJWT.verify(jwsVerifier));
        System.out.println("Decrypted ::" + signedJWT.getPayload());
        return signedJWT.getPayload().toString();
    }
    @SuppressLint("NewApi")
    public static PublicKey getPublicKey(String key){
        try{
            byte[] byteKey = Base64.getDecoder().decode(key.getBytes());
            X509EncodedKeySpec X509publicKey = new X509EncodedKeySpec(byteKey);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(X509publicKey);
        }
        catch(Exception e){
            e.printStackTrace();
        }

        return null;
    }
    @SuppressLint("NewApi")
    public static PrivateKey getPrivateKey(String key){
        try{
            byte[] byteKey = Base64.getDecoder().decode(key.getBytes());
            X509EncodedKeySpec X509publicKey = new X509EncodedKeySpec(byteKey);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(X509publicKey);
        }
        catch(Exception e){
            e.printStackTrace();
        }

        return null;
    }
    @SuppressLint("NewApi")
    public static String getPrivateKeyString(PrivateKey key){
        try{
            return new String(key.getEncoded());
        }
        catch(Exception e){
            e.printStackTrace();
        }

        return null;
    }
    @SuppressLint("NewApi")
    public static String getPublicKeyString(PrivateKey key){
        try{
            return new String(key.getEncoded());
        }
        catch(Exception e){
            e.printStackTrace();
        }

        return null;
    }

    @SuppressLint("NewApi")
    public static String decrypt(String jwe){
        String decryptedResponse = "";
        try {
            RSADecrypter decrypter = new RSADecrypter(privateKey);
            JWEObject object = JWEObject.parse(jwe);
            object.decrypt(decrypter);
            ObjectMapper objectMapper = new ObjectMapper();
            String payload = object.getPayload().toString();
            System.out.println(new String(Base64.getDecoder().decode(payload.split("\\.")[1].getBytes())));
            decryptedResponse = new String(Base64.getDecoder().decode(payload.split("\\.")[1].getBytes()));
//            System.out.println(printBase64Binary(payload.split(".")[1].getBytes()));
//            decryptedResponse = object.getPayload().toString();
//            JWEObject object1 =  JWEObject.parse(decryptedResponse);
//            object1.decrypt(decrypter);
//            System.out.println(object1.getPayload().toString());
//            decryptedResponse = objectMapper.readValue(object.getPayload().toString(), String.class);
        } catch (ParseException | JOSEException e) {
            e.printStackTrace();
        }
//        System.out.println(decryptedResponse);
        return decryptedResponse;
    }
    public static PrivateKey getVSCDevicePrivateKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        ASN1Sequence primitive = (ASN1Sequence) ASN1Sequence.fromByteArray(new String(privateKey.getEncoded()).getBytes(CHARSET_UTF_8));
        Enumeration<?> e = primitive.getObjects();
        BigInteger v = ((ASN1Integer) e.nextElement()).getValue();
        int version = v.intValue();
        if (version != 0 && version != 1) {
            throw new IllegalArgumentException("wrong version for RSA private key");
        }
        BigInteger modulus = ((ASN1Integer) e.nextElement()).getValue();
        ((ASN1Integer) e.nextElement()).getValue();
        BigInteger privateExponent = ((ASN1Integer) e.nextElement()).getValue();
        ((ASN1Integer) e.nextElement()).getValue();
        ((ASN1Integer) e.nextElement()).getValue();
        ((ASN1Integer) e.nextElement()).getValue();
        ((ASN1Integer) e.nextElement()).getValue();
        ((ASN1Integer) e.nextElement()).getValue();
        RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(modulus, privateExponent);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return (PrivateKey) keyFactory.generatePrivate(privateKeySpec);
    }
}