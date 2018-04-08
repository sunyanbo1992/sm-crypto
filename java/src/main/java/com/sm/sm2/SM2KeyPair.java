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

import com.sm.SMUtils;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

/**
 * 存放密钥对
 *
 * @author William Sun
 */
public class SM2KeyPair {

    private AsymmetricCipherKeyPair keyPair;

    public SM2KeyPair() {
    }

    public SM2KeyPair(AsymmetricCipherKeyPair keyPair) {
        this.keyPair = keyPair;
    }

    public AsymmetricCipherKeyPair getKeyPair() {
        return keyPair;
    }

    //获取hex格式的密钥对
    //公钥
    public String getHexPublicKey() {
        ECPublicKeyParameters ecpub = (ECPublicKeyParameters) keyPair.getPublic();
        ECPoint publicKey = ecpub.getQ();
        return SMUtils.byteToHex(publicKey.getEncoded());
    }

    //获取hex格式的密钥对
    //私钥
    public String getHexPrivateKey() {
        ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters) keyPair.getPrivate();
        BigInteger privateKey = ecpriv.getD();
        return SMUtils.byteToHex(privateKey.toByteArray());
    }

    //获取base64格式的密钥对
    //公钥
    public String getBase64PublicKey() {
        ECPublicKeyParameters ecpub = (ECPublicKeyParameters) keyPair.getPublic();
        ECPoint publicKey = ecpub.getQ();
        return SMUtils.encodeBase64(publicKey.getEncoded());
    }

    //获取base64格式的密钥对
    //私钥
    public String getBase64PrivateKey() {
        ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters) keyPair.getPrivate();
        BigInteger privateKey = ecpriv.getD();
        return SMUtils.encodeBase64(privateKey.toByteArray());
    }

}
