package com.sm.sm4;

import com.sm.SMUtils;

/**
 * SM4加密接口
 *
 * @author William Sun
 */
public abstract class SM4Encrypt {

    private static final int ENCRYPT = 1;


    private SM4Encrypt() {
    }


    /**
     * SM4加密, 使用Base64 格式
     *
     * @param plaintext 字符串格式的明文, 需要加密的数据
     * @param key       加密 key, 长度 16
     * @return 加密结果, base64
     */
    public static String encryptUseBase64(String plaintext, String key) {
        if (key == null || key.length() != 16) {
            throw new IllegalStateException("key length must be 16");
        }
        final byte[] encrypt = encryptSM4(plaintext, key.getBytes());
        return SMUtils.encodeBase64(encrypt);
    }

    /**
     * SM4加密, 使用Hex 格式
     *
     * @param plaintext 字符串格式的明文, 需要加密的数据
     * @param key       加密 key, 长度 16
     * @return 加密结果, Hex编码
     */
    public static String encryptUseHex(String plaintext, String key) {
        if (key == null || key.length() != 16) {
            throw new IllegalStateException("key length must be 16");
        }
        final byte[] encrypt = encryptSM4(plaintext, key.getBytes());
        return SMUtils.byteToHex(encrypt);
    }


    /**
     * 加密，明文以字符串格式输入
     *
     * @param plaintext 字符串格式的明文
     * @param key       密钥
     * @return 密文
     */
    public static byte[] encryptSM4(String plaintext, byte[] key) {
        if (plaintext == null || plaintext.equals("")) {
            return null;
        }
        for (int i = plaintext.getBytes().length % 16; i < 16; i++) {
            plaintext += '\0';
        }

        return encryptSM4(plaintext.getBytes(), key);
    }

    /**
     * SM4加密
     *
     * @param plaintext 明文
     * @param key       密钥
     * @return 密文
     */
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

    /**
     * SM4加密16字节
     *
     * @param plaintext 明文
     * @param key       密钥
     * @return 密文
     */
    private static byte[] encrypt16(byte[] plaintext, byte[] key) {
        byte[] cipher = new byte[16];
        SM4 sm4 = new SM4();
        sm4.sm4(plaintext, 16, key, cipher, ENCRYPT);

        return cipher;
    }

//    /**
//     * SM4加密32字节
//     *
//     * @param plaintext 明文
//     * @param key       密钥
//     * @return 密文
//     */
//    private static byte[] encrypt32(byte[] plaintext, byte[] key) {
//        byte[] cipher = new byte[32];
//        SM4 sm4 = new SM4();
//        sm4.sm4(plaintext, 32, key, cipher, ENCRYPT);
//
//        return cipher;
//    }
}
