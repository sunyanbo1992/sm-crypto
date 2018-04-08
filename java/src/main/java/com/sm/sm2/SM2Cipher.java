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
import com.sm.sm3.SM3;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;

import java.io.IOException;
import java.math.BigInteger;

/**
 * SM2加密器，求解c1,c2,c3值的具体实现，包括KDF函数，调用SM3摘要算法等；
 *
 * @author William Sun
 */
public class SM2Cipher {

    //存放（x2,y2）
    private ECPoint p2;
    //随机数k
    private BigInteger k;
    //密钥派生函数生成的结果
    private byte[] t;

    public SM2Cipher() {
    }

    /**
     * 获取C1值
     *
     * @param sm2 SM2对象
     * @return C1值
     */
    public byte[] getC1(SM2 sm2) {

        AsymmetricCipherKeyPair key = sm2.eccKeyPairGenerator.generateKeyPair();
        ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters) key.getPrivate();
        ECPublicKeyParameters ecpub = (ECPublicKeyParameters) key.getPublic();
        this.k = ecpriv.getD();
        ECPoint c1 = ecpub.getQ();

        return c1.getEncoded();
    }

    /**
     * 获取C2值
     *
     * @param plainText 明文（byte[]形式）
     * @param publicKey 公钥对象
     * @return C2值
     * @throws IOException
     */
    public byte[] getC2(byte[] plainText, ECPoint publicKey) throws IOException {

        this.p2 = publicKey.multiply(k);
        byte[] x2 = SMUtils.byteConvert32Bytes(p2.normalize().getXCoord().toBigInteger());
        byte[] y2 = SMUtils.byteConvert32Bytes(p2.normalize().getYCoord().toBigInteger());
        byte[] temp = new byte[64];
        System.arraycopy(x2, 0, temp, 0, x2.length);
        System.arraycopy(y2, 0, temp, x2.length, y2.length);
        this.t = KDF(temp, plainText.length);

        int count = 0;
        for (int i = 0; i < this.t.length; ++i) {
            if (this.t[i] == 0) {
                count++;
            }
        }
        if (count == this.t.length) {
            return new byte[0];
        }

        int index = 0;
        for (int i = 0; i < plainText.length; i++) {
            plainText[i] ^= t[index++];
        }
        return plainText;
    }

    /**
     * 获取C3值
     *
     * @param plainText 明文（byte[]形式）
     * @return C3值
     * @throws IOException
     */
    public byte[] getC3(byte[] plainText) throws IOException {

        byte[] x2 = SMUtils.byteConvert32Bytes(p2.normalize().getXCoord().toBigInteger());
        byte[] y2 = SMUtils.byteConvert32Bytes(p2.normalize().getYCoord().toBigInteger());
        byte[] temp = new byte[32 + 32 + plainText.length];
        System.arraycopy(x2, 0, temp, 0, x2.length);
        System.arraycopy(plainText, 0, temp, x2.length, plainText.length);
        System.arraycopy(y2, 0, temp, x2.length + plainText.length, y2.length);

        return SM3.hash(temp);

    }

    /**
     * 解密C2
     *
     * @param privateKey 私钥
     * @param c1         点C1（C1值还原得来）
     * @param c2         C2值
     * @return 明文
     * @throws IOException
     */
    public byte[] decryptC2(BigInteger privateKey, ECPoint c1, byte[] c2) throws IOException {
        this.p2 = c1.multiply(privateKey);
        byte[] x2 = SMUtils.byteConvert32Bytes(p2.normalize().getXCoord().toBigInteger());
        byte[] y2 = SMUtils.byteConvert32Bytes(p2.normalize().getYCoord().toBigInteger());
        byte[] temp = new byte[64];
        System.arraycopy(x2, 0, temp, 0, x2.length);
        System.arraycopy(y2, 0, temp, x2.length, y2.length);
        this.t = KDF(temp, c2.length);
        int index = 0;
        for (int i = 0; i < c2.length; i++) {
            c2[i] ^= t[index++];
        }

        return c2;
    }

    /**
     * 验证生成的C3与原始C3是否一致
     *
     * @param plainText  由C2解密出的明文
     * @param originalC3 原始的C3
     * @return 验证结果
     * @throws IOException
     */
    public boolean verifyC3(byte[] plainText, byte[] originalC3) throws IOException {

        byte[] x2 = SMUtils.byteConvert32Bytes(p2.normalize().getXCoord().toBigInteger());
        byte[] y2 = SMUtils.byteConvert32Bytes(p2.normalize().getYCoord().toBigInteger());
        byte[] temp = new byte[32 + plainText.length + 32];
        System.arraycopy(x2, 0, temp, 0, x2.length);
        System.arraycopy(plainText, 0, temp, x2.length, plainText.length);
        System.arraycopy(y2, 0, temp, x2.length + plainText.length, y2.length);
        byte[] generateC3 = SM3.hash(temp);

        return SMUtils.byteToHex(originalC3).equals(SMUtils.byteToHex(generateC3));
    }

    /**
     * 密钥派生函数
     * <p>
     * 函数名 KDF 是白皮书上定义的
     *
     * @param Z    (x2||y2)
     * @param kLen 明文长度
     * @return t值
     * @throws IOException
     */
    private byte[] KDF(byte[] Z, int kLen) throws IOException {

        int ct = 1;
        byte[] ctByte;
        byte[] buffer = new byte[kLen];
        byte[] ctZ = new byte[Z.length + 4];
        byte[] digest;
        int digestLength = 32;
        int n = (kLen + 31) / 32;
        System.arraycopy(Z, 0, ctZ, 0, Z.length);

        for (int i = 0; i < n; i++) {
            ctByte = SMUtils.intToByteArray(ct);
            System.arraycopy(ctByte, 0, ctZ, Z.length, ctByte.length);
            digest = SM3.hash(ctZ);

            if (i == n - 1) {

                if (kLen % 32 != 0) {
                    digestLength = kLen % 32;
                }
            }
            System.arraycopy(digest, 0, buffer, 32 * i, digestLength);
            ct++;
        }
        byte[] result = new byte[kLen];
        System.arraycopy(buffer, 0, result, 0, kLen);

        return result;
    }

}