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


    /**
     * SM4 流程测试 HEX
     * 加密,解密
     *
     * @throws Exception
     */
    @Test
    public void hexTest() throws Exception {

        String keyText = "iue98623diDEs096";
        String data = "I am marico";

        //加密 HEX方式
        final String cipherText = SM4Encrypt.encryptUseHex(data, keyText);
        assertNotNull(cipherText);


        //解密 HEX方式
        final String decryptHex = SM4Decrypt.decryptSM4toString(cipherText, keyText);
        assertNotNull(decryptHex);
        assertEquals(decryptHex, data);

    }

    /**
     * SM4 流程测试 Base64
     * 加密,解密
     *
     * @throws Exception
     */
    @Test
    public void base64Test() throws Exception {

        String keyText = "iue98623diDEs096";
        String data = "I am marico";


        //加密 base64方式
        final String encrypt = SM4Encrypt.encryptUseBase64(data, keyText);
        assertNotNull(encrypt);
        System.out.println(data + " -> " + encrypt);


        //解密 base64方式
        String decrypt = SM4Decrypt.decryptUseBase64(encrypt, keyText);
        assertNotNull(decrypt);
        assertEquals(decrypt, data);

    }


}
