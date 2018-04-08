package com.sm.sm2;

import com.sm.SMUtils;
import org.testng.annotations.Test;

import java.util.UUID;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

/**
 * 2017/2/10
 *
 * @author Shengzhao Li
 */
public class SM2FlowTest {


    @Test
    public void base64Test() throws Exception {

        final SM2KeyPair keyPair = SM2KeyPairGenerator.generateKeyPair(true);
        assertNotNull(keyPair);

        final String privateKey = keyPair.getBase64PrivateKey();
        final String publicKey = keyPair.getBase64PublicKey();
//        System.out.println("privateKey: " + privateKey);
//        System.out.println("publicKey: " + publicKey);

        String data = "Just Test " + UUID.randomUUID().toString();
        final String encrypt = SM2Encrypt.encryptUseBase64(publicKey, data, true);
        assertNotNull(encrypt);
//        System.out.println(data + " -> " + encrypt);

        final SM2DecryptResult decrypt = SM2Decrypt.decryptUseBase64(privateKey, encrypt, true);
        assertNotNull(decrypt);
        assertTrue(decrypt.getC3Result());

        final byte[] plainText = decrypt.getPlainText();
        assertEquals(data, new String(plainText));


        final String userId = "userId Test";
        final String sourceData = data;

        final SM2SignResult sm2SignResult = SM2Sign.signUseBase64(userId, privateKey, sourceData, true);
        assertNotNull(sm2SignResult);
        final String base64 = sm2SignResult.resultToBase64();
        assertNotNull(base64);


        SM2VerifyParams params = new SM2VerifyParams(userId, publicKey, sourceData, base64);
        final boolean verify = SM2Verify.verify(params, true);
        assertTrue(verify);

    }


    @Test(enabled = true)
    public void hexTest() throws Exception {

        final SM2KeyPair keyPair = SM2KeyPairGenerator.generateKeyPair();
        assertNotNull(keyPair);

        final String privateKey = keyPair.getHexPrivateKey();
        final String publicKey = keyPair.getHexPublicKey();
//        System.out.println("privateKey: " + privateKey);
//        System.out.println("publicKey: " + publicKey);

        String data = "Just Test " + UUID.randomUUID().toString();
        final String encrypt = SM2Encrypt.encryptUseHex(publicKey, data);
        assertNotNull(encrypt);
//        System.out.println(data + " -> " + encrypt);

        final SM2DecryptResult decrypt = SM2Decrypt.decryptUseHex(privateKey, encrypt);
        assertNotNull(decrypt);
        assertTrue(decrypt.getC3Result());

        final byte[] plainText = decrypt.getPlainText();
        assertEquals(data, new String(plainText));


        final byte[] userId = "userId Test".getBytes();
        final byte[] sourceData = data.getBytes();

        final SM2SignResult sm2SignResult = SM2Sign.sign(userId, SMUtils.hexStringToBytes(privateKey), sourceData);
        assertNotNull(sm2SignResult);
        final String base64 = sm2SignResult.resultToBase64();
        assertNotNull(base64);

        SM2VerifyParams params = new SM2VerifyParams(userId, SMUtils.hexStringToBytes(publicKey), sourceData, base64);
        final boolean verify = SM2Verify.verify(params);
        assertTrue(verify);

    }

}
