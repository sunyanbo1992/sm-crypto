package com.sm.sm3;

import com.sm.SMUtils;

import java.io.IOException;

/**
 * @author William Sun
 */
public abstract class SM3Digest {

    private SM3Digest() {
    }

    public static String getHexHash(String plainText) throws IOException {
        byte[] digest = SM3.hash(plainText.getBytes());
        return SMUtils.byteToHex(digest);
    }

    public static String getBase64Hash(String plainText) throws IOException {
        byte[] digest = SM3.hash(plainText.getBytes());
        return SMUtils.encodeBase64(digest);
    }
}
