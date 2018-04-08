package com.sm.sm2;

import com.sm.SMUtils;
import org.bouncycastle.math.ec.ECPoint;

import java.io.IOException;
import java.math.BigInteger;

/**
 * SM2解密
 *
 * @author William Sun
 */
public abstract class SM2Decrypt {


    private SM2Decrypt() {
    }


    /**
     * 数据解密, Base64
     * 默认测试参数
     *
     * @param privateKeyBase64 私钥 base64
     * @param cipherText      密文(BASE64字符串)
     * @return 解密结果
     * @throws IOException
     */
    public static SM2DecryptResult decryptUseBase64(String privateKeyBase64, String cipherText) throws IOException {
        return decryptUseBase64(privateKeyBase64, cipherText, false);
    }

    /**
     * 数据解密, Base64
     *
     * @param privateKeyBase64 私钥 base64
     * @param cipherText       密文(BASE64字符串)
     * @param onlineEnv        是否为正式参数, true正式, false测试
     * @return 解密结果
     * @throws IOException
     */
    public static SM2DecryptResult decryptUseBase64(String privateKeyBase64, String cipherText, boolean onlineEnv) throws IOException {
        final byte[] privateKey = SMUtils.decodeBase64(privateKeyBase64);
        final byte[] decrypt = SMUtils.decodeBase64(cipherText);
        return decrypt(privateKey, SMUtils.byteToHex(decrypt), onlineEnv);
    }

    /**
     * 数据解密, HEX
     * 默认测试参数
     *
     * @param privateKey  私钥(String型HEX编码)
     * @param cipherText 密文(String型HEX编码)
     * @return 解密结果
     * @throws IOException
     */
    public static SM2DecryptResult decryptUseHex(String privateKey, String cipherText) throws IOException {
        return decryptUseHex(privateKey, cipherText, false);
    }

    /**
     * 数据解密, HEX
     * 默认测试参数
     *
     * @param privateKey  私钥(HEX编码)
     * @param cipherText 密文(HEX编码)
     * @return 解密结果
     * @throws IOException
     */
    public static SM2DecryptResult decryptUseHex(String privateKey, String cipherText, boolean onlineEnv) throws IOException {
        return decrypt(SMUtils.hexStringToBytes(privateKey), cipherText, onlineEnv);
    }


    /**
     * 数据解密, HEX
     *
     * @param privateKey  私钥
     * @param cipherTextHex 密文(HEX编码字符串)
     * @param onlineEnv   是否为正式参数, true正式, false测试
     * @return 解密结果
     * @throws IOException
     */
    public static SM2DecryptResult decrypt(byte[] privateKey, String cipherTextHex, boolean onlineEnv) throws IOException {

        final byte[] cipherText = SMUtils.hexToByte(cipherTextHex);
        String data = SMUtils.byteToHex(cipherText);
        byte[] c1Bytes = SMUtils.hexToByte(data.substring(0, 130));
        int c2Len = cipherText.length - 97;
        byte[] c2 = SMUtils.hexToByte(data.substring(130, 130 + 2 * c2Len));
        byte[] c3 = SMUtils.hexToByte(data.substring(130 + 2 * c2Len, 194 + 2 * c2Len));

        SM2 sm2 = new SM2(onlineEnv);
        BigInteger priKey = new BigInteger(1, privateKey);
        ECPoint c1 = sm2.eccCurve.decodePoint(c1Bytes);

        SM2Cipher SM2Cipher = new SM2Cipher();
        byte[] decryptedC2 = SM2Cipher.decryptC2(priKey, c1, c2);
        boolean result = SM2Cipher.verifyC3(decryptedC2, c3);

        return new SM2DecryptResult(result, decryptedC2);
    }


}
