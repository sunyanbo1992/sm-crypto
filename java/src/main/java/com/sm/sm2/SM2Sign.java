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
 * SM2签名
 *
 * @author William Sun
 */
public abstract class SM2Sign {


    /**
     * 国密规范测试 随机数k
     */
    private static final String FIXED_RANDOM = "6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F";


    private SM2Sign() {
    }



    /**
     * SM2签名, HEX
     * 使用默认测试参数
     *
     * @param userId     用户的可辨别标识
     * @param privateKey HEX编码String型的私钥
     * @param sourceData 待签名数据
     * @return 签名结果
     * @throws IOException
     */
    public static SM2SignResult signUseHex(String userId, String privateKey, String sourceData) throws IOException {
        return sign(userId.getBytes(), SMUtils.hexStringToBytes(privateKey), sourceData.getBytes(), false);
    }

    /**
     * SM2签名, HEX
     * 使用默认测试参数
     *
     * @param userId     用户的可辨别标识
     * @param privateKey HEX编码String型的私钥
     * @param sourceData 待签名数据
     * @return 签名结果
     * @throws IOException
     */
    public static SM2SignResult signUseHex(String userId, String privateKey, String sourceData, boolean onlineEnv) throws IOException {
        return sign(userId.getBytes(), SMUtils.hexStringToBytes(privateKey), sourceData.getBytes(), onlineEnv);
    }

    /**
     * SM2签名, Base64
     * 使用默认测试参数
     *
     * @param userId     用户的可辨别标识
     * @param privateKey Base64编码String型的私钥
     * @param sourceData 待签名数据
     * @return 签名结果
     * @throws IOException
     */
    public static SM2SignResult signUseBase64(String userId, String privateKey, String sourceData) throws IOException {
        return sign(userId.getBytes(), SMUtils.decodeBase64(privateKey), sourceData.getBytes(), false);
    }


    /**
     * SM2签名, Base64
     * 使用默认测试参数
     *
     * @param userId     用户的可辨别标识
     * @param privateKey Base64编码String型的私钥
     * @param sourceData 待签名数据
     * @return 签名结果
     * @throws IOException
     */
    public static SM2SignResult signUseBase64(String userId, String privateKey, String sourceData, boolean onlineEnv) throws IOException {
        return sign(userId.getBytes(), SMUtils.decodeBase64(privateKey), sourceData.getBytes(), onlineEnv);
    }

    /**
     * SM2签名, HEX
     * 使用默认测试参数
     *
     * @param userId     用户的可辨别标识
     * @param privateKey 私钥
     * @param sourceData 待签名数据
     * @return 签名结果
     * @throws IOException
     */
    public static SM2SignResult sign(byte[] userId, byte[] privateKey, byte[] sourceData) throws IOException {
        return sign(userId, privateKey, sourceData, false);
    }

    /**
     * SM2签名, HEX
     *
     * @param userId     用户的可辨别标识
     * @param privateKey 私钥
     * @param sourceData 待签名数据
     * @param onlineEnv  是否为正式参数, true正式, false测试
     * @return 签名结果
     * @throws IOException
     */
    public static SM2SignResult sign(byte[] userId, byte[] privateKey, byte[] sourceData, boolean onlineEnv) throws IOException {

        SM2 sm2 = new SM2(onlineEnv);
        BigInteger priKey = new BigInteger(privateKey);
        ECPoint publicKey = sm2.eccPointG.multiply(priKey);

        byte[] z = SMUtils.sm2GetZ(userId, publicKey, sm2);
        byte[] M = new byte[z.length + sourceData.length];
        System.arraycopy(z, 0, M, 0, z.length);
        System.arraycopy(sourceData, 0, M, z.length, sourceData.length);
        byte[] e = SM3.hash(M);
        return doSign(e, priKey, sm2);
    }

    /**
     * SM2签名, Base64方式
     *
     * @param userId           用户的可辨别标识
     * @param privateKeyBase64 私钥 base64格式
     * @param sourceData       待签名数据
     * @param onlineEnv        是否为正式参数, true正式, false测试
     * @return 签名结果
     * @throws IOException
     */
    public static SM2SignResult signUseBase64(byte[] userId, String privateKeyBase64, byte[] sourceData, boolean onlineEnv) throws IOException {
        final byte[] privateKey = SMUtils.decodeBase64(privateKeyBase64);
        return sign(userId, privateKey, sourceData, onlineEnv);
    }


    /**
     * 进行签名操作
     *
     * @param eByte      密码杂凑函数作用于消息M的输出值。
     * @param privateKey 私钥
     * @param sm2        SM2对象
     * @return SM2SignResult
     */
    private static SM2SignResult doSign(byte[] eByte, BigInteger privateKey, SM2 sm2) {
        BigInteger e = new BigInteger(1, eByte);
        BigInteger k;
        ECPoint point;
        BigInteger r;
        BigInteger s;
        do {
            do {

                // 正式环境
//                SM2 sm2ForK = new SM2(false);
//				AsymmetricCipherKeyPair keypair = sm2ForK.eccKeyPairGenerator.generateKeyPair();
//				ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters) keypair.getPrivate();
//				ECPublicKeyParameters ecpub = (ECPublicKeyParameters) keypair.getPublic();
//				k = ecpriv.getD();
//				point = ecpub.getQ();
                //测试环境
                k = new BigInteger(FIXED_RANDOM, 16);
                point = sm2.getEcc_point_g().multiply(k);

                r = e.add(point.normalize().getXCoord().toBigInteger());
                r = r.mod(sm2.getEcc_n());

            } while (r.equals(BigInteger.ZERO) || r.add(k).equals(sm2.getEcc_n()));

            BigInteger da_1 = privateKey.add(BigInteger.ONE);
            da_1 = da_1.modInverse(sm2.getEcc_n());
            s = r.multiply(privateKey);
            s = k.subtract(s).mod(sm2.getEcc_n());
            s = da_1.multiply(s).mod(sm2.getEcc_n());
        } while (s.equals(BigInteger.ZERO));

        return new SM2SignResult(r, s);
    }
}
