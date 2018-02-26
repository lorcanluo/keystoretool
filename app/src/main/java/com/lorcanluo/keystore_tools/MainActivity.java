package com.lorcanluo.keystore_tools;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import com.lorcanluo.keystore.SecureTools;
import com.lorcanluo.keystore_tools.tools.SPUtils;

import java.io.UnsupportedEncodingException;

public class MainActivity extends AppCompatActivity implements View.OnClickListener {
    private EditText editText;
    private TextView tvText;
    private Button btnEncrypt;
    private Button btnDecrypte;
    private SecureTools secretsTools;
    private boolean isSecured = false;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        editText = findViewById(R.id.edText);
        tvText = findViewById(R.id.tvText);
        btnEncrypt = findViewById(R.id.btnEncrypt);
        btnEncrypt.setOnClickListener(this);
        btnDecrypte = findViewById(R.id.btnDecrypte);
        btnDecrypte.setOnClickListener(this);

        String encryptData = SPUtils.getInstance(this).getString("encrypt_data");
        if (!TextUtils.isEmpty(encryptData)) {
            tvText.setText(encryptData);
            isSecured = true;
        }

        secretsTools = new SecureTools.Builder()
                .context(this)
                .keyAlias("pwd")
                .build();
        secretsTools.init();
    }

    @Override
    public void onClick(View view) {
        switch (view.getId()) {
            case R.id.btnEncrypt:
                isSecured = true;
                encrypt();
                break;
            case R.id.btnDecrypte:
                if (isSecured == true) {
                    decrypt();
                    isSecured = false;
                }
                break;
        }

    }

    private void decrypt() {
        String eStr = tvText.getText().toString();
        if (!TextUtils.isEmpty(eStr)) {
            long l = System.currentTimeMillis();
            byte[] decrypt = secretsTools.decrypt(eStr);
            Log.d("decrypt",(System.currentTimeMillis() - l) + "");
            String text = new String(decrypt);
            tvText.setText(text);
        }
    }

    private void encrypt() {
        String str = editText.getText().toString();
        if (!TextUtils.isEmpty(str)) {
            String encrypt = null;
            try {
                long l = System.currentTimeMillis();
                encrypt = secretsTools.encrypt(str.getBytes("UTF-8"));
                Log.d("encrypt",(System.currentTimeMillis() - l) + "");
                SPUtils.getInstance(this).put("encrypt_data", encrypt);
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }
            tvText.setText(encrypt);
        }
    }

}
