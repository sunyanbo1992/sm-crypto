package com.sm.sm4;

import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

/**
 * 2017/2/10
 *
 * @author Shengzhao Li
 */
public class SM4FlowTest {


    @Test
    public void hexTest() throws Exception {

        String keyText = "iue98623diDEs096";
        String data = "I am marico";

        final String cipherText = SM4Encrypt.encryptUseHex(data, keyText);
        assertNotNull(cipherText);


        final String decryptHex = SM4Decrypt.decryptSM4toString(cipherText, keyText);
        assertNotNull(decryptHex);
        assertEquals(decryptHex, data);

    }

    @Test
    public void base64Test() throws Exception {

        String keyText = "iue98623diDEs096";
        String data = "I am marico";


        final String encrypt = SM4Encrypt.encryptUseBase64(data, keyText);
        assertNotNull(encrypt);
        System.out.println(data + " -> " + encrypt);


        String decrypt = SM4Decrypt.decryptUseBase64(encrypt, keyText);
        assertNotNull(decrypt);
        assertEquals(decrypt, data);

    }


}
