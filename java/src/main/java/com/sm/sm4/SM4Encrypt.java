package com.sm.sm4;

import com.sm.SMUtils;


public abstract class SM4Encrypt {

    private static final int ENCRYPT = 1;


    private SM4Encrypt() {
    }


    
    public static String encryptUseBase64(String plaintext, String key) {
        if (key == null || key.length() != 16) {
            throw new IllegalStateException("key length must be 16");
        }
        final byte[] encrypt = encryptSM4(plaintext, key.getBytes());
        return SMUtils.encodeBase64(encrypt);
    }

  
    public static String encryptUseHex(String plaintext, String key) {
        if (key == null || key.length() != 16) {
            throw new IllegalStateException("key length must be 16");
        }
        final byte[] encrypt = encryptSM4(plaintext, key.getBytes());
        return SMUtils.byteToHex(encrypt);
    }


 
    public static byte[] encryptSM4(String plaintext, byte[] key) {
        if (plaintext == null || plaintext.equals("")) {
            return null;
        }
        for (int i = plaintext.getBytes().length % 16; i < 16; i++) {
            plaintext += '\0';
        }

        return encryptSM4(plaintext.getBytes(), key);
    }

    public static byte[] encryptSM4(byte[] plaintext, byte[] key) {

        byte[] ciphertext = new byte[plaintext.length];
        int k = 0;
        int plainLen = plaintext.length;
        while (k + 16 <= plainLen) {
            byte[] cellPlain = new byte[16];
            for (int i = 0; i < 16; i++) {
                cellPlain[i] = plaintext[k + i];
            }
            byte[] cellCipher = encrypt16(cellPlain, key);
            for (int i = 0; i < cellCipher.length; i++) {
                ciphertext[k + i] = cellCipher[i];
            }

            k += 16;
        }

        return ciphertext;
    }

  
    private static byte[] encrypt16(byte[] plaintext, byte[] key) {
        byte[] cipher = new byte[16];
        SM4 sm4 = new SM4();
        sm4.sm4(plaintext, 16, key, cipher, ENCRYPT);

        return cipher;
    }

}
