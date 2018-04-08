package com.sm.sm2;

import com.sm.SMUtils;
import org.bouncycastle.math.ec.ECPoint;

import java.io.IOException;
import java.math.BigInteger;

/**
 * SM2
 *
 * 
 */
public abstract class SM2Decrypt {


    private SM2Decrypt() {
    }


    /**
     * Base64
     * 
     *
     * @param privateKeyBase64 base64
     * @param cipherText     
     * @return
     * @throws IOException
     */
    public static SM2DecryptResult decryptUseBase64(String privateKeyBase64, String cipherText) throws IOException {
        return decryptUseBase64(privateKeyBase64, cipherText, false);
    }

    /**
     * 数据解密, Base64
     *
     * @param privateKeyBase64 base64
     * @param cipherText       (BASE64字符串)
     * @param onlineEnv        
     * @return plaintext
     * @throws IOException
     */
    public static SM2DecryptResult decryptUseBase64(String privateKeyBase64, String cipherText, boolean onlineEnv) throws IOException {
        final byte[] privateKey = SMUtils.decodeBase64(privateKeyBase64);
        final byte[] decrypt = SMUtils.decodeBase64(cipherText);
        return decrypt(privateKey, SMUtils.byteToHex(decrypt), onlineEnv);
    }

    /*
     *
     * @param privateKey  String hex
     * @param cipherText String hex
     * @return
     * @throws IOException
     */
    public static SM2DecryptResult decryptUseHex(String privateKey, String cipherText) throws IOException {
        return decryptUseHex(privateKey, cipherText, false);
    }

    /**
     
     * @param privateKey HEX
     * @param cipherText HEX
     * @return 
     * @throws IOException
     */
    public static SM2DecryptResult decryptUseHex(String privateKey, String cipherText, boolean onlineEnv) throws IOException {
        return decrypt(SMUtils.hexStringToBytes(privateKey), cipherText, onlineEnv);
    }


    /**
     *
     *
     * @param privateKey 
     * @param cipherTextHex HEX
     * @param onlineEnv
     * @return
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
