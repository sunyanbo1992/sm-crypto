/*
 * Copyright (c) 2016 BeiJing JZYT Technology Co. Ltd
 * www.idsmanager.com
 * All rights reserved.
 *
 * This software is the confidential and proprietary information of
 * BeiJing JZYT Technology Co. Ltd ("Confidential Information").
 * You shall not disclose such Confidential Information and shall use
 * it only in accordance with the terms of the license agreement you
 * entered into with BeiJing JZYT Technology Co. Ltd.
 */
package com.sm.sm4;

import com.sm.SMUtils;

/**
 * SM4解密接口
 *
 * @author William Sun
 */
public abstract class SM4Decrypt {

    private static final int DECRYPT = 0;


    private SM4Decrypt() {
    }

    /**
     * SM4解密对外接口
     *
     * @param cipherText String型Hex编码密文
     * @param keyText String型密钥
     * @return byte[]数组密文
     */
    public static byte[] decryptSM4(String cipherText, String keyText) {
        byte[] key = keyText.getBytes();
        return decryptSM4(cipherText,key,1);
    }

    /**
     * SM4解密对外接口
     *
     * @param cipherText String型Hex编码密文
     * @param key byte[]型密钥
     * @return byte[]数组密文
     */
    public static byte[] decryptSM4(String cipherText, byte[] key) {
        return decryptSM4(cipherText,key,1);
    }

    /**
     *SM4解密对外接口
     *
     * @param cipherText String型HEX编码的密文
     * @param key byte[]数组型密钥
     * @param times 解密次数
     * @return
     */
    public static byte[] decryptSM4(String cipherText, byte[] key, int times) {
        byte[] result = SMUtils.hexStringToBytes(cipherText);

        for (int i = 0 ;i < times; ++i ){
            result = decrypt(result,key);
        }
        //去掉加密时候填充的多余\0
        int pos = 0;
        for (int i = 0 ; i < result.length; ++i){
            if ( 0 == result[i]){
                pos = i;
                break;
            }
        }
        if (0 == pos){
            return result;
        }
        byte[] plainText = new byte[pos];
        for (int i = 0 ; i < plainText.length; ++i){
            plainText[i] = result[i];
        }
        return plainText;
    }

    /**
     * SM4解密（主方法，供内部调用）
     *
     * @param cipherText 密文
     * @param key        密钥
     * @return 明文
     */
    private static byte[] decrypt(byte[] cipherText, byte[] key) {
        byte[] plaintext = new byte[cipherText.length];

        int k = 0;
        int cipherLen = cipherText.length;
        while (k + 16 <= cipherLen) {
            byte[] cellCipher = new byte[16];
            for (int i = 0; i < 16; i++) {
                cellCipher[i] = cipherText[k + i];
            }
            byte[] cellPlain = decrypt16(cellCipher, key);
            for (int i = 0; i < cellPlain.length; i++) {
                plaintext[k + i] = cellPlain[i];
            }

            k += 16;
        }

        return plaintext;
    }

    /**
     * SM4解密成字符串类型
     *
     * @param cipherText 密文
     * @param key        密钥
     * @return 明文
     */
    public static String decryptSM4toString(String cipherText, String key) {
        byte[] plaintext = decryptSM4(cipherText, key);
        return new String(plaintext);
    }

    /**
     * SM4解密16字节的密文
     *
     * @param cipherText 密文
     * @param key        密钥
     * @return 明文
     */
    private static byte[] decrypt16(byte[] cipherText, byte[] key) {
        byte[] plain = new byte[16];
        SM4 sm4 = new SM4();
        sm4.sm4(cipherText, 16, key, plain, DECRYPT);

        return plain;
    }

    /**
     * SM4解密 , base64方式
     *
     * @param encrypt 加密的密文
     * @param key 密钥
     * @return 明文
     */
    public static String decryptUseBase64(String encrypt, String key) {
        final byte[] cipherText = SMUtils.decodeBase64(encrypt);
        String hexCipherText = SMUtils.byteToHex(cipherText);
        return decryptSM4toString(hexCipherText, key);
    }

//    /**
//     * SM4解密32字节的密文
//     *
//     * @param cipherText 密文
//     * @param key        密钥
//     * @return 明文
//     */
//    private static byte[] decrypt32(byte[] cipherText, byte[] key) {
//        byte[] plain = new byte[32];
//        SM4 sm4 = new SM4();
//        sm4.sm4(cipherText, 32, key, plain, DECRYPT);
//
//        return plain;
//    }

}

