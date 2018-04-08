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
package com.sm.sm3;

import com.sm.SMUtils;

import java.io.IOException;

/**
 * @author William Sun
 */
public abstract class SM3Digest {

    private SM3Digest() {
    }

    public static String getHexHash(String plainText) throws IOException {
        byte[] digest = SM3.hash(plainText.getBytes());
        return SMUtils.byteToHex(digest);
    }

    public static String getBase64Hash(String plainText) throws IOException {
        byte[] digest = SM3.hash(plainText.getBytes());
        return SMUtils.encodeBase64(digest);
    }
}
