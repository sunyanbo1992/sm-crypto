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

import java.io.Serializable;
import java.math.BigInteger;

/**
 * 签名结果对象
 *
 * @author William Sun
 */
public class SM2SignResult implements Serializable {

    private static final long serialVersionUID = 5358593419511495312L;

    //冒号, 用于分隔
    private static final String COLON = ":";


    /**
     * 将 Base64 的数据{@link #resultToBase64()}转化为 SM2SignResult 对象
     *
     * @param base64Data Base64
     * @return SM2SignResult
     */
    public static SM2SignResult parse(String base64Data) {
        String decode = new String(SMUtils.decodeBase64(base64Data));
        if (!decode.contains(COLON)) {
            throw new IllegalStateException(decode + " must include char " + COLON);
        }
        final String[] strArray = decode.split(COLON, 2);
        final BigInteger r1 = new BigInteger(strArray[0]);
        final BigInteger s1 = new BigInteger(strArray[1]);
        return new SM2SignResult(r1, s1);
    }


    //白皮书数据，签名结果的两个值：r和s;
    private BigInteger r;

    private BigInteger s;

    /**
     * Only constructor
     *
     * @param r R
     * @param s S
     */
    public SM2SignResult(BigInteger r, BigInteger s) {
        this.r = r;
        this.s = s;
    }

    public BigInteger getR() {
        return r;
    }

    public void setR(BigInteger r) {
        this.r = r;
    }

    public BigInteger getS() {
        return s;
    }

    public void setS(BigInteger s) {
        this.s = s;
    }

    public String getHexStringR() {
        return this.r.toString(16).toUpperCase();
    }

    public String getHexStringS() {
        return this.s.toString(16).toUpperCase();
    }


    /*
    *  转化为 Base64 格式输出: r:s
    * */
    public String resultToBase64() {
        String text = r.toString() + COLON + s.toString();

        return SMUtils.encodeBase64(text.getBytes());
    }

    @Override
    public String toString() {
        return "SM2SignResult{" +
                "r=" + r +
                ", s=" + s +
                '}';
    }

}
