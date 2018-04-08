package com.sm.sm2;

/**
 * @author William Sun
 */
public class SM2DecryptResult {

    private boolean c3Result;

    private byte[] plainText;

    public SM2DecryptResult(boolean decryptResult, byte[] plainText) {
        this.c3Result = decryptResult;
        this.plainText = plainText;
    }

    public boolean getC3Result() {
        return c3Result;
    }


    public byte[] getPlainText() {
        return plainText;
    }

}
