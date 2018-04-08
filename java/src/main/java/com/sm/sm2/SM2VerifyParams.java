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

import java.util.Arrays;

/**
 * SM2签名验签参数封装
 *
 * @author William Sun
 */
public class SM2VerifyParams {

    private byte[] userId;
    private byte[] publicKey;
    private byte[] sourceData;
    private SM2SignResult sm2SignResult;

    public SM2VerifyParams() {
    }

    /*
    * 不对外开放的 构造器
    * publicKey为String类型Base64编码的字符串
    * */
    SM2VerifyParams(String userId, String publicKey, String sourceData, SM2SignResult sm2SignResult) {
        this.userId = userId.getBytes();
        this.publicKey = SMUtils.decodeBase64(publicKey);
        this.sourceData = sourceData.getBytes();
        this.sm2SignResult = sm2SignResult;
    }

    /*
    * 不对外开放的 构造器
    * */
    SM2VerifyParams(byte[] userId, byte[] publicKey, byte[] sourceData, SM2SignResult sm2SignResult) {
        this.userId = userId;
        this.publicKey = publicKey;
        this.sourceData = sourceData;
        this.sm2SignResult = sm2SignResult;
    }

    public SM2VerifyParams(String userId, String publicKey, String sourceData, String base64SM2SignResult) {
        this(userId, publicKey, sourceData, SM2SignResult.parse(base64SM2SignResult));
    }

    public SM2VerifyParams(byte[] userId, byte[] publicKey, byte[] sourceData, String base64SM2SignResult) {
        this(userId, publicKey, sourceData, SM2SignResult.parse(base64SM2SignResult));
    }


    public SM2VerifyParams(byte[] userId, String publicKeyBase64, byte[] sourceData, SM2SignResult sm2SignResult) {
        this(userId, SMUtils.decodeBase64(publicKeyBase64), sourceData, sm2SignResult);
    }

    public SM2VerifyParams(byte[] userId, String publicKeyBase64, byte[] sourceData, String base64SM2SignResult) {
        this(userId, SMUtils.decodeBase64(publicKeyBase64), sourceData, SM2SignResult.parse(base64SM2SignResult));
    }

    public byte[] getUserId() {
        return userId;
    }

    public void setUserId(byte[] userId) {
        this.userId = userId;
    }

    public byte[] getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(byte[] publicKey) {
        this.publicKey = publicKey;
    }

    public byte[] getSourceData() {
        return sourceData;
    }

    public void setSourceData(byte[] sourceData) {
        this.sourceData = sourceData;
    }

    public SM2SignResult getSm2SignResult() {
        return sm2SignResult;
    }

    public void setSm2SignResult(SM2SignResult sm2SignResult) {
        this.sm2SignResult = sm2SignResult;
    }


    @Override
    public String toString() {
        return "SM2VerifyParams{" +
                "userId=" + Arrays.toString(userId) +
                ", publicKey=" + Arrays.toString(publicKey) +
                ", sourceData=" + Arrays.toString(sourceData) +
                ", sm2SignResult=" + sm2SignResult +
                '}';
    }
}
