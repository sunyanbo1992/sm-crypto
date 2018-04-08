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
package com.sm.sm2;

import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

/**
 * @author William Sun
 */
public class SM2EncryptTest {

    @Test
    public void encryptHexTest() throws Exception {

        //case1: Hex格式密钥；
        String message = "encryption standard";
        String privateKey = "1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0";
        String publicKey = "04435B39CCA8F3B508C1488AFC67BE491A0F7BA07E581A0E4849A5CF70628A7E0A75DDBA78F15FEECB4C7895E2C1CDF5FE01DEBB2CDBADF45399CCF77BBA076A42";
        String cipherText = SM2Encrypt.encryptUseHex(publicKey, message);
        SM2DecryptResult sm2DecryptResult = SM2Decrypt.decryptUseHex(privateKey, cipherText);
        String plainText = new String(sm2DecryptResult.getPlainText());
        boolean c3Result = sm2DecryptResult.getC3Result();
        assertTrue(c3Result);
        assertEquals(plainText, message);
        assertEquals(plainText, message);

    }

    @Test
    public void encryptBase64Test() throws Exception {

        //case2: Base64格式密钥；
        String message = "encryption standard";
        SM2KeyPair keyPair = SM2KeyPairGenerator.generateKeyPair();
        String privateKey = keyPair.getBase64PrivateKey();
        String publicKey = keyPair.getBase64PublicKey();
        String cipherText = SM2Encrypt.encryptUseBase64(publicKey, message);
        SM2DecryptResult sm2DecryptResult1 = SM2Decrypt.decryptUseBase64(privateKey, cipherText);
        String plainText = new String(sm2DecryptResult1.getPlainText());
        boolean c3Result = sm2DecryptResult1.getC3Result();
        assertTrue(c3Result);
        assertEquals(plainText, message);
        assertEquals(plainText, message);
    }
}


