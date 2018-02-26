package com.lorcanluo.keystore.versions;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.RequiresApi;
import android.util.Base64;

import com.lorcanluo.keystore.ISecure;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Calendar;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;

import static com.lorcanluo.keystore.constant.Constants.PREF_NAME_PRE;
import static com.lorcanluo.keystore.constant.Constants.SHARED_PREFERENCE_NAME;

/**
 * 低于M高于JELLY_BEAN_MR2的版本，使用这个类的方法
 * 1.第一次使用的时候，生成一对RSA key
 * 2.生成一个随机的AES key
 * 3.使用RSA的公钥，加密AES
 * 4.key保存到Preferences中
 * 5.当存储一个数据，从Preferences中拿到这个key，用RSA 私钥解密key， 用解密后的key，加密数据，保存这个加密后的数据到Preferences中。
 * 6.当获取一个数据，从Preferences读取这个加密后的数据，然后从Preferences中拿到这个key，用RSA 私钥解密key，解密数据。
 *
 * @author luocan
 * @version 1.0
 *          </p>
 *          Created on 2018/2/7.
 */
@RequiresApi(api = Build.VERSION_CODES.JELLY_BEAN_MR2)
public class SecureToolsBeforeM implements ISecure {
    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    private static final String AES_MODE_PRE_M = "AES/ECB/PKCS7Padding";
    private static final String RSA_MODE = "RSA/ECB/PKCS1Padding";

    private String keyAlias;
    private KeyStore keyStore;

    public SecureToolsBeforeM(String keyAlias) {
        this.keyAlias = keyAlias;
    }

    public void init(Context context) {
        try {
            generateRsaKeyPreM(context);
        } catch (Exception e) {
            e.printStackTrace();
        }
        generateAesKeyPreM(context);
    }

    public String encrypt(Context context, byte[] input) {
        Cipher c = null;
        String encryptedBase64Encoded = "";
        try {
            c = Cipher.getInstance(AES_MODE_PRE_M, "BC");

            c.init(Cipher.ENCRYPT_MODE, getSecretKeyPreM(context));
            byte[] encodedBytes = c.doFinal(input);
            encryptedBase64Encoded = Base64.encodeToString(encodedBytes, Base64.DEFAULT);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return encryptedBase64Encoded;
    }


    public byte[] decrypt(Context context, String encrypted) {
        Cipher c = null;
        byte[] decodedBytes = null;
        try {
            c = Cipher.getInstance(AES_MODE_PRE_M, "BC");

            c.init(Cipher.DECRYPT_MODE, getSecretKeyPreM(context));
            byte[] decode = Base64.decode(encrypted, Base64.DEFAULT);
            decodedBytes = c.doFinal(decode);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return decodedBytes;
    }


    private void generateRsaKeyPreM(Context context) throws Exception {
        keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
        keyStore.load(null);

        // Generate the RSA key pairs
        if (!keyStore.containsAlias(keyAlias)) {
            // Generate a key pair for encryption
            Calendar start = Calendar.getInstance();
            Calendar end = Calendar.getInstance();
            end.add(Calendar.YEAR, 30);
            KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(context)
                    .setAlias(keyAlias)
                    .setSubject(new X500Principal("CN=" + keyAlias))
                    .setSerialNumber(BigInteger.TEN)
                    .setStartDate(start.getTime())
                    .setEndDate(end.getTime())
                    .build();
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEY_STORE);
            kpg.initialize(spec);
            kpg.generateKeyPair();
        }

    }

    private byte[] rsaEncrypt(byte[] secret) throws Exception {
        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(keyAlias, null);
        // Encrypt the text
        Cipher inputCipher = Cipher.getInstance(RSA_MODE, "AndroidOpenSSL");
        inputCipher.init(Cipher.ENCRYPT_MODE, privateKeyEntry.getCertificate().getPublicKey());

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, inputCipher);
        cipherOutputStream.write(secret);
        cipherOutputStream.close();

        byte[] vals = outputStream.toByteArray();
        return vals;
    }

    private byte[] rsaDecrypt(byte[] encrypted) throws Exception {
        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(keyAlias, null);
        Cipher output = Cipher.getInstance(RSA_MODE, "AndroidOpenSSL");
        output.init(Cipher.DECRYPT_MODE, privateKeyEntry.getPrivateKey());
        CipherInputStream cipherInputStream = new CipherInputStream(
                new ByteArrayInputStream(encrypted), output);
        ArrayList<Byte> values = new ArrayList<>();
        int nextByte;
        while ((nextByte = cipherInputStream.read()) != -1) {
            values.add((byte) nextByte);
        }

        byte[] bytes = new byte[values.size()];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = values.get(i).byteValue();
        }
        return bytes;
    }


    private void generateAesKeyPreM(Context context) {
        SharedPreferences pref = context.getSharedPreferences(SHARED_PREFERENCE_NAME, Context.MODE_PRIVATE);
        String enryptedKeyB64 = pref.getString(PREF_NAME_PRE + keyAlias, null);
        if (enryptedKeyB64 == null) {
            byte[] key = new byte[16];
            SecureRandom secureRandom = new SecureRandom();
            secureRandom.nextBytes(key);
            byte[] encryptedKey = new byte[0];
            try {
                encryptedKey = rsaEncrypt(key);
            } catch (Exception e) {
                e.printStackTrace();
            }
            enryptedKeyB64 = Base64.encodeToString(encryptedKey, Base64.DEFAULT);
            SharedPreferences.Editor edit = pref.edit();
            edit.putString(PREF_NAME_PRE + keyAlias, enryptedKeyB64);
            edit.commit();
        }
    }


    private Key getSecretKeyPreM(Context context) throws Exception {
        SharedPreferences pref = context.getSharedPreferences(SHARED_PREFERENCE_NAME, Context.MODE_PRIVATE);
        String enryptedKeyB64 = pref.getString(PREF_NAME_PRE + keyAlias, null);
        // need to check null, omitted here
        byte[] encryptedKey = Base64.decode(enryptedKeyB64, Base64.DEFAULT);
        byte[] key = rsaDecrypt(encryptedKey);
        return new SecretKeySpec(key, "AES");
    }


}
