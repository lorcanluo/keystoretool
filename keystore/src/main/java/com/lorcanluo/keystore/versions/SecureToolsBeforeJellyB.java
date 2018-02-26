package com.lorcanluo.keystore.versions;

import android.content.Context;
import android.text.TextUtils;
import android.util.Base64;

import com.lorcanluo.keystore.ISecure;
import com.lorcanluo.keystore.utils.CloseUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;

/**
 * 低于4.3的版本，使用这个类的方法
 * 加密通过3DES来完成
 * 1.第一次使用的时候，生成一个随机的key,并保存到文件中。
 * 2.当存储一个数据，从文件中拿到这个key，加密数据，保存这个加密后的数据到Preferences中。
 * 3.当获取一个数据，从Preferences读取这个加密后的数据，然后从文件中拿到这个key，解密数据。
 *
 * @author luocan
 * @version 1.0
 *          </p>
 *          Created on 2018/2/7.
 */
public class SecureToolsBeforeJellyB implements ISecure {
    public static final String TAG = SecureToolsBeforeJellyB.class.getName();
    private static final String DES_MODE = "DESede/ECB/PKCS5Padding";
    private String keyAlias;

    public SecureToolsBeforeJellyB(String keyAlias) {
        this.keyAlias = keyAlias;
    }

    @Override
    public void init(Context context) {

    }


    /**
     * 获取加密过的value,通过key和value得到加密过的value
     *
     * @param context
     * @param input
     * @return 加密过的value
     */
    public String encrypt(Context context, byte[] input) {
        try {
            String secretKeyPath = getSecretKeyPath(context, keyAlias);
            if (secretKeyPath != null) {
                SecretKey secretKey = readSecretKey(secretKeyPath);
                if (secretKey != null) {
                    // 已经存在secretKey
                } else {
                    // 不存在secretKey,生成一个
                    secretKey = generate3DESKey();
                    saveSecretKey(secretKey, secretKeyPath);
                }
                byte[] bytes = encryptWith3DES(input, secretKey);
                return Base64.encodeToString(bytes, Base64.DEFAULT);// 最终会返回一个base64过的字符串
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 获取解密后的value,通过key和decodedValue得到解密后的value
     *
     * @param context
     * @param decodedValue
     * @return 加密后的value
     */
    public byte[] decrypt(Context context, String decodedValue) {
        try {
            String secretKeyPath = getSecretKeyPath(context, keyAlias);
            if (secretKeyPath != null) {
                SecretKey secretKey = readSecretKey(secretKeyPath);
                if (secretKey != null) {
                    // 先做base64解码
                    byte[] bytes = Base64.decode(decodedValue.getBytes(), Base64.DEFAULT);
                    if (bytes != null) {
                        return decodeWith3DES(bytes, secretKey);
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }


    /**
     * 保存SecretKey
     *
     * @param key
     * @param filePath
     * @return
     */
    private boolean saveSecretKey(SecretKey key, String filePath) {
        FileOutputStream fileOutputStream = null;
        try {
            fileOutputStream = new FileOutputStream(filePath);
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(fileOutputStream);
            objectOutputStream.writeObject(key);
            objectOutputStream.flush();
            objectOutputStream.close();
            return true;
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            CloseUtils.closeIOQuietly(fileOutputStream);
        }
        return false;
    }

    /**
     * 读取SecretKey
     *
     * @param filePath
     * @return
     */
    private SecretKey readSecretKey(String filePath) {
        SecretKey key = null;
        FileInputStream fileInputStream = null;
        try {
            fileInputStream = new FileInputStream(filePath);
            ObjectInputStream objectInputStream = new ObjectInputStream(fileInputStream);
            key = (SecretKey) objectInputStream.readObject();
            objectInputStream.close();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            CloseUtils.closeIOQuietly(fileInputStream);
        }
        return key;
    }

    /**
     * 获取SecretKey路径
     *
     * @param fileName
     * @return
     */
    private String getSecretKeyPath(Context context, String fileName) {
        if (TextUtils.isEmpty(fileName)) {
            return null;
        }
        File file = new File(context.getFilesDir(), "secure");
        if (!file.exists() || !file.isDirectory()) {
            file.mkdirs();
        }

        File f = new File(file, fileName);
        if (!f.exists() || !f.isFile()) {
            try {
                f.createNewFile();
            } catch (IOException e) {
                e.printStackTrace();
                return null;
            }
        }
        return f.getPath();
    }

    /**
     * 数据加解密3DES所需要的Key
     *
     * @return
     */
    private SecretKey generate3DESKey() {
        try {
            // 生成key
            KeyGenerator keyGenerator = KeyGenerator.getInstance("DESede");
            keyGenerator.init(168);// can 168 or 112/new SecureRandom()
            SecretKey secretKey = keyGenerator.generateKey();
            byte[] bytesKey = secretKey.getEncoded();

            // 转化key
            DESedeKeySpec deSedeKeySpec = new DESedeKeySpec(bytesKey);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("DESede");
            SecretKey generateSecret = factory.generateSecret(deSedeKeySpec);

            return generateSecret;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 数据加密3DES
     *
     * @param strData
     * @param secretKey
     * @return
     */
    private byte[] encryptWith3DES(byte[] strData, SecretKey secretKey) {
        try {
            // 加密
            Cipher cipher = Cipher.getInstance(DES_MODE);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] result = cipher.doFinal(strData);
            return result;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 数据解密3DES
     *
     * @param bytes
     * @param secretKey
     * @return
     */
    private byte[] decodeWith3DES(byte[] bytes, SecretKey secretKey) {
        try {
            // 加密
            Cipher cipher = Cipher.getInstance(DES_MODE);
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] result = cipher.doFinal(bytes);
            return result;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

}
