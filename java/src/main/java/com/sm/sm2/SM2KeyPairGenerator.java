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
