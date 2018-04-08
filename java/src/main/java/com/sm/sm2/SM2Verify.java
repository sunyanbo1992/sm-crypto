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
import org.bouncycastle.math.ec.ECPoint;

import java.io.IOException;
import java.math.BigInteger;

/**
 * SM2签名验签
 *
 * @author William Sun
 */
public class SM2Verify {


    /**
     * 签名验签接口，初始化各种参数
     * 使用测试参数
     *
     * @param sm2VerifyParams 验签需要的数据
     * @return 验签结果
     * @throws IOException
     */
    public static boolean verify(SM2VerifyParams sm2VerifyParams) throws IOException {
        return verify(sm2VerifyParams, false);
    }

    /**
     * 签名验签接口，初始化各种参数
     *
     * @param sm2VerifyParams 验签需要的数据
     * @param onlineEnv       SM2是否为正式参数
     * @return 验签结果
     * @throws IOException
     */
    public static boolean verify(SM2VerifyParams sm2VerifyParams, boolean onlineEnv) throws IOException {

        byte[] userId = sm2VerifyParams.getUserId();
        byte[] publicKey = sm2VerifyParams.getPublicKey();
        byte[] sourceData = sm2VerifyParams.getSourceData();
        SM2SignResult sm2SignResult = sm2VerifyParams.getSm2SignResult();
        SM2 sm2 = new SM2(onlineEnv);
        ECPoint pubKey = sm2.eccCurve.decodePoint(publicKey);
        byte[] z = SMUtils.sm2GetZ(userId, pubKey, sm2);
        byte[] M = new byte[z.length + sourceData.length];
        System.arraycopy(z, 0, M, 0, z.length);
        System.arraycopy(sourceData, 0, M, z.length, sourceData.length);
        byte[] e = SM3.hash(M);
        return doVerify(e, pubKey, sm2SignResult, sm2);
    }

    /**
     * 签名验证具体实现
     *
     * @param md            密码杂凑函数作用于消息M ′的输出值。
     * @param publicKey     公钥
     * @param sm2SignResult 签名结果
     * @param sm2           SM2对象
     * @return 签名结果
     */
    private static boolean doVerify(byte md[], ECPoint publicKey, SM2SignResult sm2SignResult, SM2 sm2) {

        BigInteger e = new BigInteger(1, md);
        BigInteger r = sm2SignResult.getR();
        BigInteger s = sm2SignResult.getS();
        BigInteger t = r.add(s).mod(sm2.getEcc_n());
        if (t.equals(BigInteger.ZERO)) {
            return false;
        } else {
            ECPoint x1y1 = sm2.getEcc_point_g().multiply(s);
            x1y1 = x1y1.add(publicKey.multiply(t));
            BigInteger R = e.add(x1y1.normalize().getXCoord().toBigInteger()).mod(sm2.getEcc_n());
            return r.equals(R);

        }
    }
}
