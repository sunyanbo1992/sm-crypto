package com.sm.sm2;

import com.sm.SMUtils;
import org.bouncycastle.math.ec.ECPoint;

import java.io.IOException;

/**
 * SM2加密
 *
 * @author William Sun
 */
public abstract class SM2Encrypt {


    private SM2Encrypt() {
    }

    /**
     * 数据加密 HEX, 16进制
     * 默认测试参数
     *
     * @param publicKey 公钥,  HEX编码字符串
     * @param plainText 明文, 需要加密的数据
     * @return SM2加密后的密文(HEX编码)
     * @throws IOException
     */
    public static String encryptUseHex(String publicKey, String plainText) throws IOException {
        return encryptUseHex(publicKey, plainText, false);
    }


    /**
     * 数据加密 HEX, 16进制
     * 默认测试参数
     *
     * @param publicKey 公钥,  HEX编码字符串
     * @param plainText 明文, 需要加密的数据
     * @return SM2加密后的密文(HEX编码)
     * @throws IOException
     */
    public static String encryptUseHex(String publicKey, String plainText, boolean onlineEnv) throws IOException {
        return encrypt(SMUtils.hexStringToBytes(publicKey), plainText.getBytes(), onlineEnv);
    }


    /**
     * 数据加密, Base64 public key
     * 默认测试参数
     *
     * @param publicKeyBase64 公钥  Base64
     * @param plainText       明文, 字符串格式
     * @return SM2加密后的密文
     * @throws IOException
     */
    public static String encryptUseBase64(String publicKeyBase64, String plainText) throws IOException {
        return encryptUseBase64(publicKeyBase64, plainText, false);
    }


    /**
     * 数据加密, Base64 public key
     *
     * @param publicKeyBase64 公钥  Base64
     * @param plainText       明文, 需要加密的数据
     * @param onlineEnv       是否为正式参数, true正式, false测试
     * @return SM2加密后的密文 base64
     * @throws IOException
     */
    public static String encryptUseBase64(String publicKeyBase64, String plainText, boolean onlineEnv) throws IOException {
        final byte[] publicKey = SMUtils.decodeBase64(publicKeyBase64);
        final String encrypt = encrypt(publicKey, plainText.getBytes(), onlineEnv);
        return SMUtils.hexToBase64(encrypt);
    }


    /**
     * 数据加密 HEX, 16进制
     *
     * @param publicKey 公钥
     * @param plainText 明文, 需要加密的数据
     * @param onlineEnv 是否为正式参数, true正式, false测试
     * @return SM2加密后的密文（HEX编码字符串）
     * @throws IOException
     */
    public static String encrypt(byte[] publicKey, byte[] plainText, boolean onlineEnv) throws IOException {

        byte[] plaintTextCopy = new byte[plainText.length];
        System.arraycopy(plainText, 0, plaintTextCopy, 0, plainText.length);
        SM2Cipher SM2Cipher = new SM2Cipher();
        SM2 sm2 = new SM2(onlineEnv);
        ECPoint publicKeyPoint = sm2.eccCurve.decodePoint(publicKey);
        byte[] c1 = SM2Cipher.getC1(sm2);
        byte[] c2 = SM2Cipher.getC2(plainText, publicKeyPoint);

        while (c2.length == 0) {
            c1 = SM2Cipher.getC1(sm2);
            c2 = SM2Cipher.getC2(plainText, publicKeyPoint);
        }

        byte[] c3 = SM2Cipher.getC3(plaintTextCopy);

        return SMUtils.byteToHex(c1) + SMUtils.byteToHex(c2) + SMUtils.byteToHex(c3);
    }

}
