package com.lorcanluo.keystore.versions;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.RequiresApi;
import android.util.Base64;

import com.lorcanluo.keystore.ISecure;

import java.security.Key;
import java.security.KeyStore;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;

import static com.lorcanluo.keystore.constant.Constants.SHARED_PREFERENCE_NAME;

/**
 * 高于M的版本，使用这个类的方法
 * 1.第一次使用的时候，生成一个随机的key。
 * 2.当存储一个数据，从keystore中拿到这个key，加密数据，保存这个加密后的数据到Preferences中。
 * 3.当获取一个数据，从Preferences读取这个加密后的数据，然后从keystore中拿到这个key，解密数据。
 *
 * @author luocan
 * @version 1.0
 *          </p>
 *          Created on 2018/2/7.
 */
@RequiresApi(api = Build.VERSION_CODES.M)
public class SecureToolsAfterM implements ISecure {
    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    private static final String AES_MODE = "AES/CBC/PKCS7Padding";
    private String keyAlias;
    private KeyStore keyStore;
    private byte[] iv;

    public SecureToolsAfterM(String keyAlias) {
        this.keyAlias = keyAlias;
    }

    public void init(Context context) {
        try {
            generateKey();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public String encrypt(Context context, byte[] input) {
        Cipher c = null;
        String encryptedBase64Encoded = "";
        try {
            c = Cipher.getInstance(AES_MODE);

            Key secretKey = getSecretKey();
            c.init(Cipher.ENCRYPT_MODE, secretKey);
            iv = c.getIV();
            storeIVToSharePreference(context);
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
            c = Cipher.getInstance(AES_MODE);
            if (iv == null) {
                iv = getIVFromSharePreference(context);
            }
            final IvParameterSpec spec = new IvParameterSpec(iv);
            c.init(Cipher.DECRYPT_MODE, getSecretKey(), spec);

            byte[] decode = Base64.decode(encrypted, Base64.DEFAULT);
            decodedBytes = c.doFinal(decode);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return decodedBytes;
    }

    private void generateKey() throws Exception {
        keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
        keyStore.load(null);

        if (!keyStore.containsAlias(keyAlias)) {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE);
//            keyGenerator.init(
//                    new KeyGenParameterSpec.Builder(keyAlias,
//                            KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
//                            .setBlockModes(KeyProperties.BLOCK_MODE_CBC).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
//                            .setRandomizedEncryptionRequired(false)
//                            .build());

            keyGenerator.init(new KeyGenParameterSpec.Builder(keyAlias,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .build());
            keyGenerator.generateKey();
        }

    }

    private java.security.Key getSecretKey() throws Exception {
        return keyStore.getKey(keyAlias, null);
    }

    private void storeIVToSharePreference(Context context) {
        SharedPreferences pref = context.getSharedPreferences(SHARED_PREFERENCE_NAME, Context.MODE_PRIVATE);
        SharedPreferences.Editor edit = pref.edit();
        String encryptedBase64Encoded = Base64.encodeToString(iv, Base64.DEFAULT);
        edit.putString(keyAlias, new String(encryptedBase64Encoded));
        edit.commit();
    }

    private byte[] getIVFromSharePreference(Context context) {
        SharedPreferences pref = context.getSharedPreferences(SHARED_PREFERENCE_NAME, Context.MODE_PRIVATE);
        String string = pref.getString(keyAlias, "");
        return Base64.decode(string, Base64.DEFAULT);
    }

}
