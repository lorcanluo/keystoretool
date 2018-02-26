package com.lorcanluo.keystore;

import android.content.Context;

/**
 * @author luocan
 * @version 1.0
 *          </p>
 *          Created on 2018/2/8.
 */

public interface ISecure {
    String encrypt(Context context, byte[] input) ;

    byte[] decrypt(Context context, String encrypted);

    void init(Context context);
}
