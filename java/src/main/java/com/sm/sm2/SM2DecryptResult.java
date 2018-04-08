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
 * @author William Sun
 */
public class SM2DecryptResult {

    private boolean c3Result;

    private byte[] plainText;

    public SM2DecryptResult(boolean decryptResult, byte[] plainText) {
        this.c3Result = decryptResult;
        this.plainText = plainText;
    }

    public boolean getC3Result() {
        return c3Result;
    }


    public byte[] getPlainText() {
        return plainText;
    }

}
