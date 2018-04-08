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

import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECFieldElement.Fp;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * SM2算法的一些基本参数，以及调用ECC类库所需的参数
 *
 * @author William Sun
 */
public class SM2 {

    // 白皮书测试参数
    private final static String[] ECC_TEST_PARAM = {
            "8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3",
            "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498",
            "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A",
            "8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7",
            "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D",
            "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2"
    };

    //SM2国家推荐正式参数
    private final static String[] ECC_ONLINE_PARAM = {
            "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",
            "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",
            "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",
            "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
            "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
            "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"
    };

    //从上述参数中提取的值，命名与白皮书命名一致
    private BigInteger eccP;
    private BigInteger eccA;
    private BigInteger eccB;
    private BigInteger eccN;
    private BigInteger eccGx;
    private BigInteger eccGy;
    private ECDomainParameters eccBcSpec;
    private ECFieldElement eccGxFieldElement;
    private ECFieldElement eccGyFieldElement;
    //以下值分别为：基点g,椭圆曲线，密钥对生成器
    public ECCurve eccCurve;
    public ECPoint eccPointG;
    public ECKeyPairGenerator eccKeyPairGenerator;


    /**
     * 默认使用测试参数 构造器
     */
    public SM2() {
        this(false);
    }


    /**
     * 是否使用 正式参数(onlineEnv) 构造SM2对象
     *
     * @param onlineEnv True 使用正式参数, false 使用测试参数
     */
    public SM2(boolean onlineEnv) {
        if (onlineEnv) {
            this.eccP = new BigInteger(ECC_ONLINE_PARAM[0], 16);
            this.eccA = new BigInteger(ECC_ONLINE_PARAM[1], 16);
            this.eccB = new BigInteger(ECC_ONLINE_PARAM[2], 16);
            this.eccN = new BigInteger(ECC_ONLINE_PARAM[3], 16);
            this.eccGx = new BigInteger(ECC_ONLINE_PARAM[4], 16);
            this.eccGy = new BigInteger(ECC_ONLINE_PARAM[5], 16);
        } else {
            this.eccP = new BigInteger(ECC_TEST_PARAM[0], 16);
            this.eccA = new BigInteger(ECC_TEST_PARAM[1], 16);
            this.eccB = new BigInteger(ECC_TEST_PARAM[2], 16);
            this.eccN = new BigInteger(ECC_TEST_PARAM[3], 16);
            this.eccGx = new BigInteger(ECC_TEST_PARAM[4], 16);
            this.eccGy = new BigInteger(ECC_TEST_PARAM[5], 16);
        }

        initialSM2Params();
    }

    private void initialSM2Params() {
        this.eccGxFieldElement = new Fp(this.eccP, this.eccGx);
        this.eccGyFieldElement = new Fp(this.eccP, this.eccGy);

        this.eccCurve = new ECCurve.Fp(this.eccP, this.eccA, this.eccB);
        this.eccPointG = new ECPoint.Fp(this.eccCurve, this.eccGxFieldElement, this.eccGyFieldElement);
        this.eccBcSpec = new ECDomainParameters(this.eccCurve, this.eccPointG, this.eccN);

        ECKeyGenerationParameters ecc_ecgenparam = new ECKeyGenerationParameters(this.eccBcSpec, new SecureRandom());

        this.eccKeyPairGenerator = new ECKeyPairGenerator();
        this.eccKeyPairGenerator.init(ecc_ecgenparam);
    }


    public BigInteger getEcc_p() {
        return eccP;
    }

    public BigInteger getEcc_a() {
        return eccA;
    }

    public BigInteger getEcc_b() {
        return eccB;
    }

    public BigInteger getEcc_n() {
        return eccN;
    }

    public BigInteger getEcc_gx() {
        return eccGx;
    }

    public BigInteger getEcc_gy() {
        return eccGy;
    }

    public ECCurve getEcc_curve() {
        return eccCurve;
    }

    public ECPoint getEcc_point_g() {
        return eccPointG;
    }

    public ECDomainParameters getEcc_bc_spec() {
        return eccBcSpec;
    }

    public ECKeyPairGenerator getEcc_key_pair_generator() {
        return eccKeyPairGenerator;
    }

    public ECFieldElement getEcc_gx_fieldelement() {
        return eccGxFieldElement;
    }

    public ECFieldElement getEcc_gy_fieldelement() {
        return eccGyFieldElement;
    }

}


