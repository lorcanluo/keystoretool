package com.lorcanluo.keystore;

import android.content.Context;
import android.os.Build;

import com.lorcanluo.keystore.versions.SecureToolsAfterM;
import com.lorcanluo.keystore.versions.SecureToolsBeforeJellyB;
import com.lorcanluo.keystore.versions.SecureToolsBeforeM;

/**
 * 利用keystore来保存数据的工具库
 *
 * @author luocan
 * @version 1.0
 *          </p>
 *          Created on 2018/2/7.
 */

public class SecureTools {
    private Context context;
    private String keyAlias;

    private ISecure secure;

    private SecureTools(Builder builder) {
        context = builder.context;
        keyAlias = builder.keyAlias;
    }

    public void init() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            secure = new SecureToolsAfterM(keyAlias);
            secure.init(context);
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
            secure = new SecureToolsBeforeM(keyAlias);
            secure.init(context);
        } else {
            secure = new SecureToolsBeforeJellyB(keyAlias);
        }
    }

    public String encrypt(byte[] input) {
        if (secure == null) {
            throw new IllegalStateException("please call init first");
        }
        return secure.encrypt(context, input);
    }

    public byte[] decrypt(String encrypted) {
        if (secure == null) {
            throw new IllegalStateException("please call init first");
        }
        return secure.decrypt(context, encrypted);
    }


    public static final class Builder {
        private Context context;
        private String keyAlias;

        public Builder() {
        }

        public Builder context(Context val) {
            context = val;
            return this;
        }


        /**
         * 要存储数据的一个别名，不同数据一定要不同
         *
         * @param val 要存储数据的一个别名
         * @return
         */
        public Builder keyAlias(String val) {
            keyAlias = val;
            return this;
        }

        public SecureTools build() {
            return new SecureTools(this);
        }
    }
}
