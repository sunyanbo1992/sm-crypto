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

/**
 * SM2密钥对生成器
 * @author William Sun
 */
public class SM2KeyPairGenerator {

    public SM2KeyPairGenerator() {
    }

    //默认参数为测试环境
    public static SM2KeyPair generateKeyPair() {
        return generateKeyPair(false);
    }

    public static SM2KeyPair generateKeyPair(boolean onlineEnv) {

        SM2 sm2 = new SM2(onlineEnv);
        return new SM2KeyPair(sm2.eccKeyPairGenerator.generateKeyPair());

    }

}
