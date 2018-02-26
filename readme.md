# KeyStore工具库

[ ![Download](https://api.bintray.com/packages/lorcanluo/maven/keystoretool/images/download.svg?version=1.0.0) ](https://bintray.com/lorcanluo/maven/keystoretool/1.0.0/link)
```
compile 'com.lorcanluo.keystoretool:keystore:1.0.0'

```


用于存储需要加密保存的数据，该版本做了兼容性处理。
1. 6.0 以上版本使用KeyStore 直接存储AES密匙
2. 4.3-6.0 版本通过 RSA间接加密AES密匙的方式
3. 4.3以下版本通过3DES的方式加密

使用方法

初始化：
```
        secretsTools = new SecureTools.Builder()
                .context(this)
                .keyAlias("pwd")
                .build();
        secretsTools.init();
        
```

加密：
```
  private void decrypt(String input) {
        byte[] decrypt = secretsTools.decrypt(input);
        String text = new String(decrypt);
        tvText.setText(text);
    }
```
    
解密：

```
  private void encrypt(String input) {
        try {
            String encrypt = secretsTools.encrypt(input.getBytes("UTF-8"));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }
```
